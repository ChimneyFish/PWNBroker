import threading
from flask import Blueprint, render_template, redirect, url_for, flash, request, current_app
from flask_login import login_required, current_user
from ..models import Scan, Target, ThreatConfig, ScanResult
from ..extensions import db
from .decorators import admin_required

secrets_bp = Blueprint("secrets", __name__, url_prefix="/secrets")


@secrets_bp.route("/")
@login_required
def index():
    scans = Scan.query.filter_by(scan_type="reaper").order_by(Scan.created_at.desc()).all()
    targets = Target.query.filter_by(target_type="github_repo").order_by(Target.name).all()
    return render_template("secrets/index.html", scans=scans, targets=targets)


@secrets_bp.route("/new", methods=["GET", "POST"])
@login_required
@admin_required
def new():
    targets = Target.query.filter_by(target_type="github_repo").order_by(Target.name).all()
    tc = ThreatConfig.query.first()
    has_token = bool(tc and tc.github_advisory_token)

    if request.method == "POST":
        name      = request.form.get("name", "").strip()
        target_id = request.form.get("target_id", type=int)

        if not name or not target_id:
            flash("Name and target are required.", "danger")
            return render_template("secrets/new.html", targets=targets, has_token=has_token)

        target = Target.query.get_or_404(target_id)
        if target.target_type != "github_repo":
            flash("REAPER only scans GitHub repository targets.", "danger")
            return render_template("secrets/new.html", targets=targets, has_token=has_token)

        scan = Scan(
            name=name,
            target_id=target_id,
            scan_type="reaper",
            created_by=current_user.id,
            status="pending",
        )
        db.session.add(scan)
        db.session.commit()

        from ..audit import log_action
        log_action("scan.create", entity_type="scan", entity_id=scan.id, entity_name=name,
                   detail=f"Type: reaper | Target: {target.name}")

        from ..scanner.engine import run_scan
        app = current_app._get_current_object()
        threading.Thread(target=run_scan, args=(scan.id, app), daemon=True).start()

        flash(f"Secret scan '{name}' started.", "success")
        return redirect(url_for("secrets.view", scan_id=scan.id))

    return render_template("secrets/new.html", targets=targets, has_token=has_token)


@secrets_bp.route("/<int:scan_id>")
@login_required
def view(scan_id):
    scan = Scan.query.filter_by(id=scan_id, scan_type="reaper").first_or_404()
    results = scan.results.order_by(ScanResult.severity).all()
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    results.sort(key=lambda r: (0 if r.result_type == "vulnerability" else 1,
                                severity_order.get(r.severity, 5)))
    return render_template("secrets/view.html", scan=scan, results=results)


@secrets_bp.route("/<int:scan_id>/delete", methods=["POST"])
@login_required
@admin_required
def delete(scan_id):
    scan = Scan.query.filter_by(id=scan_id, scan_type="reaper").first_or_404()
    db.session.delete(scan)
    db.session.commit()
    from ..audit import log_action
    log_action("scan.delete", entity_type="scan", entity_id=scan_id, entity_name=scan.name)
    flash("Secret scan deleted.", "success")
    return redirect(url_for("secrets.index"))
