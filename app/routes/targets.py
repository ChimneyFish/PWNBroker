import threading
from datetime import datetime, timezone
from flask import Blueprint, render_template, redirect, url_for, flash, request, current_app
from flask_login import login_required, current_user
from ..models import Target, DomainRecord, ThreatConfig
from ..extensions import db
from ..validators import is_valid_host, is_valid_github_repo, is_valid_local_path
from .decorators import admin_required
from ..scanner.ssh_verify import apply_ssh_form, Creds, test_login, SSH_FIELDS

targets_bp = Blueprint("targets", __name__, url_prefix="/targets")


@targets_bp.route("/")
@login_required
def index():
    targets = Target.query.order_by(Target.created_at.desc()).all()
    return render_template("targets/index.html", targets=targets)


@targets_bp.route("/new", methods=["GET", "POST"])
@login_required
@admin_required
def new():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        host = request.form.get("host", "").strip()
        description = request.form.get("description", "").strip()
        target_type = request.form.get("target_type", "host")
        if not name or not host:
            flash("Name and host are required.", "danger")
            return render_template("targets/new.html")

        if target_type == "github_repo":
            valid, err = is_valid_github_repo(host), f"'{host}' isn't a valid GitHub repository (expected owner/repo)."
        elif target_type == "local_path":
            valid, err = is_valid_local_path(host), f"'{host}' isn't a valid absolute path (must start with /)."
        elif target_type == "ad_domain":
            valid, err = is_valid_host(host), f"'{host}' isn't a valid domain name."
        else:
            valid, err = is_valid_host(host), f"'{host}' isn't a valid IP address, CIDR range, or hostname."
        if not valid:
            flash(err, "danger")
            return render_template("targets/new.html")

        if target_type == "ad_domain":
            ad_dc_host = request.form.get("ad_dc_host", "").strip()
            if not ad_dc_host or not is_valid_host(ad_dc_host):
                flash(f"'{ad_dc_host}' isn't a valid domain controller hostname or IP.", "danger")
                return render_template("targets/new.html")

        t = Target(
            name=name, host=host, description=description,
            created_by=current_user.id,
            target_type=target_type,
        )
        ssh_err = apply_ssh_form(t, request.form)
        if ssh_err:
            flash(ssh_err, "danger")
            return render_template("targets/new.html")
        t.ad_dc_host = request.form.get("ad_dc_host", "").strip() or None
        t.ad_username = request.form.get("ad_username", "").strip() or None
        t.ad_auth_type = request.form.get("ad_auth_type", "password")
        t.ad_password = request.form.get("ad_password", "").strip() or None
        t.ad_nt_hash = request.form.get("ad_nt_hash", "").strip() or None
        db.session.add(t)
        db.session.commit()

        if t.target_type == "domain":
            app = current_app._get_current_object()
            threading.Thread(target=_run_domain_enum, args=(t.id, app), daemon=True).start()
            flash(f"Target '{name}' created. DNS enumeration started in the background.", "success")
        elif t.target_type == "ad_domain":
            flash(f"Target '{name}' created. Launch a BloodHound scan from the AD Attack Paths "
                  "section to start collection.", "success")
        else:
            flash(f"Target '{name}' created.", "success")

        return redirect(url_for("targets.index"))
    return render_template("targets/new.html")


@targets_bp.route("/<int:target_id>")
@login_required
def detail(target_id):
    t = Target.query.get_or_404(target_id)
    records = (DomainRecord.query
               .filter_by(target_id=target_id)
               .order_by(DomainRecord.record_type, DomainRecord.name)
               .all())
    by_type = {}
    for r in records:
        by_type.setdefault(r.record_type, []).append(r)
    return render_template("targets/detail.html", target=t, by_type=by_type,
                           record_count=len(records))


@targets_bp.route("/<int:target_id>/credentials", methods=["GET", "POST"])
@login_required
@admin_required
def credentials(target_id):
    """Attach, change or remove the SSH login saved on a target (used for
    credentialed CVE checks, deep EOL checks and remote dependency scans)."""
    t = Target.query.get_or_404(target_id)
    if request.method == "POST":
        from ..audit import log_action
        if request.form.get("remove"):
            for f in SSH_FIELDS:
                setattr(t, f, None)
            t.ssh_port, t.ssh_auth_type = 22, "password"
            db.session.commit()
            log_action("target.ssh_credentials_removed", entity_type="target",
                       entity_id=t.id, entity_name=t.name)
            flash(f"SSH credentials removed from '{t.name}'.", "success")
            return redirect(url_for("targets.index"))
        err = apply_ssh_form(t, request.form, keep_secrets=True)
        if err:
            db.session.rollback()
            flash(err, "danger")
            return render_template("targets/credentials.html", target=t)
        db.session.commit()
        log_action("target.ssh_credentials_saved", entity_type="target", entity_id=t.id,
                   entity_name=t.name, detail=f"user={t.ssh_username or '-'} auth={t.ssh_auth_type}")
        flash(f"SSH credentials saved on '{t.name}'." if t.ssh_username
              else f"'{t.name}' has no SSH credentials.", "success")
        return redirect(url_for("targets.index"))
    return render_template("targets/credentials.html", target=t)


def _host_for_test(default_host):
    """The host a "Test login" button should connect to: the form's
    test_host if given, else the target host when it's a single host."""
    from ..validators import is_valid_host
    host = (request.form.get("test_host") or "").strip() or default_host or ""
    if not host or "/" in host or not is_valid_host(host):
        return None
    return host


def ssh_test_response(form_obj, default_host):
    """Shared JSON handler for the Test login buttons."""
    from flask import jsonify
    from types import SimpleNamespace
    host = _host_for_test(default_host)
    if not host:
        return jsonify(ok=False, error="Enter a single host or IP to test against "
                                       "(a subnet or group can't be tested as a whole).")
    ns = SimpleNamespace(**{f: getattr(form_obj, f, None) for f in SSH_FIELDS})
    err = apply_ssh_form(ns, request.form, keep_secrets=True)
    if err:
        return jsonify(ok=False, error=err)
    if not ns.ssh_username:
        return jsonify(ok=False, error="Enter an SSH username.")
    creds = Creds(host=host, ssh_username=ns.ssh_username, ssh_port=ns.ssh_port,
                  ssh_auth_type=ns.ssh_auth_type, ssh_password=ns.ssh_password,
                  ssh_private_key=ns.ssh_private_key, ssh_key_passphrase=ns.ssh_key_passphrase)
    result = test_login(creds)
    result["host"] = host
    return jsonify(result)


@targets_bp.route("/<int:target_id>/credentials/test", methods=["POST"])
@login_required
@admin_required
def credentials_test(target_id):
    t = Target.query.get_or_404(target_id)
    return ssh_test_response(t, t.host)


@targets_bp.route("/<int:target_id>/re-enum", methods=["POST"])
@login_required
@admin_required
def re_enum(target_id):
    t = Target.query.get_or_404(target_id)
    if t.target_type != "domain":
        flash("Re-enumeration is only available for domain targets.", "warning")
        return redirect(url_for("targets.detail", target_id=target_id))
    app = current_app._get_current_object()
    threading.Thread(target=_run_domain_enum, args=(t.id, app), daemon=True).start()
    flash("DNS enumeration started — refresh in a few seconds.", "info")
    return redirect(url_for("targets.detail", target_id=target_id))


@targets_bp.route("/<int:target_id>/delete", methods=["POST"])
@login_required
@admin_required
def delete(target_id):
    t = Target.query.get_or_404(target_id)
    db.session.delete(t)
    db.session.commit()
    flash("Target deleted.", "success")
    return redirect(url_for("targets.index"))


# ── Domain enumeration ────────────────────────────────────────────────────────

def _run_domain_enum(target_id, app):
    with app.app_context():
        target = db.session.get(Target, target_id)
        if not target or target.target_type != "domain":
            return
        cfg = ThreatConfig.query.first()
        dnsdumpster_key = cfg.dnsdumpster_api_key if cfg else None

        from ..threat.subdomain import enumerate_dns_records
        try:
            records = enumerate_dns_records(target.host, dnsdumpster_key)
        except Exception as e:
            app.logger.error(f"Domain enum failed for {target.host}: {e}")
            return

        _apply_domain_records(target, records)
        db.session.commit()


def _apply_domain_records(target, records):
    """Diff incoming DNS records against stored ones, mark new/changed/removed."""
    now = datetime.now(timezone.utc)
    existing = {
        (r.name, r.record_type): r
        for r in DomainRecord.query.filter_by(target_id=target.id).all()
    }
    seen_keys = set()

    for rec in records:
        key = (rec["name"], rec["record_type"])
        seen_keys.add(key)
        new_val = rec.get("value", "")

        if key in existing:
            dr = existing[key]
            if new_val and dr.value != new_val:
                dr.previous_value = dr.value
                dr.value = new_val
                dr.status = "changed"
            elif dr.status == "removed":
                dr.status = "new"
            else:
                dr.status = "active"
            dr.last_seen = now
        else:
            dr = DomainRecord(
                target_id=target.id,
                record_type=rec["record_type"],
                name=rec["name"],
                value=new_val,
                source=rec.get("source", ""),
                status="new",
                first_seen=now,
                last_seen=now,
            )
            db.session.add(dr)

    for key, dr in existing.items():
        if key not in seen_keys and dr.status != "removed":
            dr.status = "removed"

    target.last_enum_at = now
