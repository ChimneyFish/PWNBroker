import threading
from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_required, current_user
from ..models import Scan, Target, ScanResult
from ..extensions import db
from .decorators import admin_required

eol_bp = Blueprint("eol", __name__, url_prefix="/eol")


@eol_bp.route("/")
@login_required
def index():
    scans   = Scan.query.filter_by(scan_type="eol").order_by(Scan.created_at.desc()).all()
    targets = Target.query.filter(
        Target.target_type != "github_repo"
    ).order_by(Target.name).all()
    return render_template("eol/index.html", scans=scans, targets=targets)


@eol_bp.route("/new", methods=["GET", "POST"])
@login_required
@admin_required
def new():
    targets = Target.query.filter(
        Target.target_type != "github_repo"
    ).order_by(Target.name).all()

    if request.method == "POST":
        name      = request.form.get("name", "").strip()
        target_id = request.form.get("target_id", type=int)

        if not name or not target_id:
            flash("Name and target are required.", "danger")
            return render_template("eol/new.html", targets=targets)

        target = Target.query.get_or_404(target_id)
        if not target.ssh_username:
            flash("EOL scanning requires SSH credentials configured on the target.", "warning")
            return render_template("eol/new.html", targets=targets)

        scan = Scan(
            name=name,
            target_id=target_id,
            scan_type="eol",
            scan_path="",
            created_by=current_user.id,
            status="pending",
        )
        db.session.add(scan)
        db.session.commit()

        from ..scanner.engine import run_scan
        from flask import current_app
        app = current_app._get_current_object()
        threading.Thread(target=run_scan, args=(scan.id, app), daemon=True).start()

        flash(f"EOL scan '{name}' started.", "success")
        return redirect(url_for("eol.view", scan_id=scan.id))

    return render_template("eol/new.html", targets=targets)


@eol_bp.route("/<int:scan_id>")
@login_required
def view(scan_id):
    scan    = Scan.query.filter_by(id=scan_id, scan_type="eol").first_or_404()
    results = scan.results.order_by(ScanResult.created_at).all()
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    results.sort(key=lambda r: (
        0 if r.result_type == "vulnerability" else 1,
        sev_order.get(r.severity, 5),
    ))
    return render_template("eol/view.html", scan=scan, results=results)


@eol_bp.route("/<int:scan_id>/delete", methods=["POST"])
@login_required
@admin_required
def delete(scan_id):
    scan = Scan.query.filter_by(id=scan_id, scan_type="eol").first_or_404()
    db.session.delete(scan)
    db.session.commit()
    flash("EOL scan deleted.", "success")
    return redirect(url_for("eol.index"))
