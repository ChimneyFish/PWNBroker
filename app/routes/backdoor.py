import threading
from flask import Blueprint, render_template, redirect, url_for, flash, request, current_app
from flask_login import login_required, current_user
from ..models import Scan, Target, ScanResult
from ..extensions import db
from .decorators import admin_required

backdoor_bp = Blueprint("backdoor", __name__, url_prefix="/backdoor")


@backdoor_bp.route("/")
@login_required
def index():
    scans = Scan.query.filter_by(scan_type="backdoor").order_by(Scan.created_at.desc()).all()
    targets = Target.query.filter_by(target_type="local_path").order_by(Target.name).all()
    return render_template("backdoor/index.html", scans=scans, targets=targets)


@backdoor_bp.route("/new", methods=["GET", "POST"])
@login_required
@admin_required
def new():
    targets = Target.query.filter_by(target_type="local_path").order_by(Target.name).all()

    if request.method == "POST":
        name      = request.form.get("name", "").strip()
        target_id = request.form.get("target_id", type=int)

        if not name or not target_id:
            flash("Name and target are required.", "danger")
            return render_template("backdoor/new.html", targets=targets)

        target = Target.query.get_or_404(target_id)
        if target.target_type != "local_path":
            flash("Backdoor Detector only scans Local Path targets.", "danger")
            return render_template("backdoor/new.html", targets=targets)

        scan = Scan(
            name=name,
            target_id=target_id,
            scan_type="backdoor",
            created_by=current_user.id,
            status="pending",
        )
        db.session.add(scan)
        db.session.commit()

        from ..audit import log_action
        log_action("scan.create", entity_type="scan", entity_id=scan.id, entity_name=name,
                   detail=f"Type: backdoor | Target: {target.name}")

        from ..scanner.engine import run_scan
        app = current_app._get_current_object()
        threading.Thread(target=run_scan, args=(scan.id, app), daemon=True).start()

        flash(f"Backdoor scan '{name}' started.", "success")
        return redirect(url_for("backdoor.view", scan_id=scan.id))

    return render_template("backdoor/new.html", targets=targets)


@backdoor_bp.route("/<int:scan_id>")
@login_required
def view(scan_id):
    scan = Scan.query.filter_by(id=scan_id, scan_type="backdoor").first_or_404()
    results = scan.results.order_by(ScanResult.severity).all()
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    results.sort(key=lambda r: (0 if r.result_type == "vulnerability" else 1,
                                severity_order.get(r.severity, 5)))
    return render_template("backdoor/view.html", scan=scan, results=results)


@backdoor_bp.route("/<int:scan_id>/delete", methods=["POST"])
@login_required
@admin_required
def delete(scan_id):
    scan = Scan.query.filter_by(id=scan_id, scan_type="backdoor").first_or_404()
    db.session.delete(scan)
    db.session.commit()
    from ..audit import log_action
    log_action("scan.delete", entity_type="scan", entity_id=scan_id, entity_name=scan.name)
    flash("Backdoor scan deleted.", "success")
    return redirect(url_for("backdoor.index"))
