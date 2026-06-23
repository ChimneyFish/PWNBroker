import threading
from datetime import datetime, timezone
from flask import Blueprint, render_template, redirect, url_for, flash, request, current_app
from flask_login import login_required, current_user
from ..models import Target, DomainRecord, ThreatConfig
from ..extensions import db
from .decorators import admin_required

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
        if not name or not host:
            flash("Name and host are required.", "danger")
            return render_template("targets/new.html")

        t = Target(
            name=name, host=host, description=description,
            created_by=current_user.id,
            target_type=request.form.get("target_type", "host"),
        )
        t.ssh_port = int(request.form.get("ssh_port") or 22)
        t.ssh_username = request.form.get("ssh_username", "").strip() or None
        t.ssh_auth_type = request.form.get("ssh_auth_type", "password")
        t.ssh_password = request.form.get("ssh_password", "").strip() or None
        t.ssh_private_key = request.form.get("ssh_private_key", "").strip() or None
        t.ssh_key_passphrase = request.form.get("ssh_key_passphrase", "").strip() or None
        db.session.add(t)
        db.session.commit()

        if t.target_type == "domain":
            app = current_app._get_current_object()
            threading.Thread(target=_run_domain_enum, args=(t.id, app), daemon=True).start()
            flash(f"Target '{name}' created. DNS enumeration started in the background.", "success")
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
