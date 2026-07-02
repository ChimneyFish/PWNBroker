import threading
from flask import Blueprint, render_template, redirect, url_for, flash, request, jsonify
from flask_login import login_required, current_user
from ..models import Scan, Target, ScanResult, AtlassianConfig
from ..extensions import db
from .decorators import admin_required

dependency_bp = Blueprint("dependency", __name__, url_prefix="/dependency")


@dependency_bp.route("/")
@login_required
def index():
    scans = Scan.query.filter_by(scan_type="osv").order_by(Scan.created_at.desc()).all()
    targets = Target.query.order_by(Target.name).all()
    return render_template("dependency/index.html", scans=scans, targets=targets)


@dependency_bp.route("/new", methods=["GET", "POST"])
@login_required
@admin_required
def new():
    targets = Target.query.order_by(Target.name).all()
    if request.method == "POST":
        name            = request.form.get("name", "").strip()
        target_id       = request.form.get("target_id", type=int)
        scan_path       = request.form.get("scan_path", "").strip()
        auto_remediate  = bool(request.form.get("auto_remediate"))

        if not name or not target_id:
            flash("Name and target are required.", "danger")
            return render_template("dependency/new.html", targets=targets)

        target = Target.query.get_or_404(target_id)

        if target.target_type == "github_repo":
            # GitHub repo scans use the API — no SSH needed, scan_path is optional subpath
            pass
        else:
            if not scan_path:
                flash("Remote path is required for SSH-based scans.", "danger")
                return render_template("dependency/new.html", targets=targets)
            if not target.ssh_username:
                flash("Selected target has no SSH credentials configured. Edit the target first.", "warning")
                return render_template("dependency/new.html", targets=targets)

        scan = Scan(
            name=name,
            target_id=target_id,
            scan_type="osv",
            scan_path=scan_path,
            auto_remediate=auto_remediate,
            created_by=current_user.id,
            status="pending",
        )
        db.session.add(scan)
        db.session.commit()

        from ..scanner.engine import run_scan
        from flask import current_app
        app = current_app._get_current_object()
        t = threading.Thread(target=run_scan, args=(scan.id, app), daemon=True)
        t.start()

        flash(f"Dependency scan '{name}' started.", "success")
        return redirect(url_for("dependency.view", scan_id=scan.id))

    return render_template("dependency/new.html", targets=targets)


@dependency_bp.route("/<int:scan_id>")
@login_required
def view(scan_id):
    scan = Scan.query.filter_by(id=scan_id, scan_type="osv").first_or_404()
    results = scan.results.order_by(ScanResult.severity).all()
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    results.sort(key=lambda r: (0 if r.result_type == "vulnerability" else 1,
                                severity_order.get(r.severity, 5)))
    atlassian_cfg = AtlassianConfig.query.first()
    jira_enabled = bool(atlassian_cfg and atlassian_cfg.enabled and atlassian_cfg.jira_enabled)
    existing_tickets = {t.result_id: t for t in scan.jira_tickets.all()}
    return render_template("dependency/view.html", scan=scan, results=results,
                           jira_enabled=jira_enabled, existing_tickets=existing_tickets)


@dependency_bp.route("/<int:scan_id>/delete", methods=["POST"])
@login_required
@admin_required
def delete(scan_id):
    scan = Scan.query.filter_by(id=scan_id, scan_type="osv").first_or_404()
    db.session.delete(scan)
    db.session.commit()
    flash("Dependency scan deleted.", "success")
    return redirect(url_for("dependency.index"))


@dependency_bp.route("/<int:scan_id>/remediate/<int:result_id>", methods=["POST"])
@login_required
@admin_required
def remediate(scan_id, result_id):
    result = ScanResult.query.filter_by(id=result_id, scan_id=scan_id).first_or_404()
    result.is_remediated = not result.is_remediated
    db.session.commit()
    return jsonify({"remediated": result.is_remediated})


@dependency_bp.route("/ssh-test/<int:target_id>", methods=["POST"])
@login_required
@admin_required
def ssh_test(target_id):
    target = Target.query.get_or_404(target_id)
    from ..scanner.osv_scanner import test_ssh_connection
    result = test_ssh_connection(target)
    return jsonify(result)
