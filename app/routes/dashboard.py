from flask import Blueprint, render_template
from flask_login import login_required
from ..models import Scan, ScanResult, Target
from ..extensions import db
import sqlalchemy as sa

dashboard_bp = Blueprint("dashboard", __name__)


@dashboard_bp.route("/")
@login_required
def index():
    total_scans = Scan.query.count()
    running_scans = Scan.query.filter_by(status="running").count()
    total_targets = Target.query.count()

    vuln_counts = db.session.execute(
        sa.select(ScanResult.severity, sa.func.count(ScanResult.id))
        .where(ScanResult.result_type == "vulnerability")
        .group_by(ScanResult.severity)
    ).all()
    severity_map = {row[0]: row[1] for row in vuln_counts}

    recent_scans = Scan.query.order_by(Scan.created_at.desc()).limit(8).all()

    recent_vulns = (
        ScanResult.query
        .filter_by(result_type="vulnerability")
        .order_by(ScanResult.created_at.desc())
        .limit(10)
        .all()
    )

    return render_template(
        "dashboard/index.html",
        total_scans=total_scans,
        running_scans=running_scans,
        total_targets=total_targets,
        severity_map=severity_map,
        recent_scans=recent_scans,
        recent_vulns=recent_vulns,
    )
