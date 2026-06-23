import os
from datetime import datetime, timezone
from flask import Blueprint, render_template, redirect, url_for, flash, request, send_file, Response, jsonify
from flask_login import login_required, current_user
from ..models import Scan, Target, ScheduledReport, GeneratedReport, CloudConfig, AtlassianConfig
from ..extensions import db
from ..email_utils.report_builder import (
    build_pdf_report, build_html_report,
    save_report_to_disk, load_report_from_disk, delete_report_from_disk,
)
from ..email_utils.cloud_push import push_report_to_cloud
from ..scheduler.jobs import _next_run_from_cron
from .decorators import admin_required
import io

reports_bp = Blueprint("reports", __name__, url_prefix="/reports")


@reports_bp.route("/")
@login_required
def index():
    latest_scan = Scan.query.filter_by(status="done").order_by(Scan.completed_at.desc()).first()
    scans = Scan.query.filter_by(status="done").order_by(Scan.completed_at.desc()).all()
    saved = GeneratedReport.query.order_by(GeneratedReport.generated_at.desc()).all()
    scheduled = ScheduledReport.query.order_by(ScheduledReport.created_at.desc()).all()
    cloud_cfg = CloudConfig.query.first()
    atlassian_cfg = AtlassianConfig.query.first()
    return render_template(
        "reports/index.html",
        latest_scan=latest_scan,
        scans=scans,
        saved=saved,
        scheduled=scheduled,
        cloud_enabled=bool(cloud_cfg and cloud_cfg.enabled and cloud_cfg.endpoint_url),
        confluence_enabled=bool(atlassian_cfg and atlassian_cfg.enabled and atlassian_cfg.confluence_enabled),
    )


@reports_bp.route("/generate/<int:scan_id>", methods=["POST"])
@login_required
def generate(scan_id):
    scan = Scan.query.get_or_404(scan_id)
    file_format = request.form.get("file_format", "pdf")
    delivery = request.form.get("delivery", "local")  # local | cloud | both

    # Build the report bytes
    if file_format == "pdf":
        report_bytes = build_pdf_report([scan])
        mime = "application/pdf"
        ext = "pdf"
    else:
        report_bytes = build_html_report([scan]).encode("utf-8")
        mime = "text/html"
        ext = "html"

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    filename = f"scan_{scan.id}_{timestamp}.{ext}"
    cloud_status = "not_sent"
    cloud_response = None

    # Always save locally
    save_report_to_disk(report_bytes, filename)
    file_size = len(report_bytes)

    # Cloud push
    if delivery in ("cloud", "both"):
        result = push_report_to_cloud(
            scan,
            report_bytes=report_bytes if delivery == "both" else None,
            file_format=file_format,
        )
        cloud_status = "ok" if result["ok"] else "error"
        cloud_response = result["message"]
        if result["ok"]:
            flash(f"Report pushed to cloud API (HTTP {result['status_code']}).", "success")
        else:
            flash(f"Cloud push failed: {result['message']}", "danger")

    # Record in DB
    gr = GeneratedReport(
        scan_id=scan.id,
        filename=filename,
        file_format=file_format,
        file_size=file_size,
        delivery=delivery,
        cloud_status=cloud_status,
        cloud_response=cloud_response,
        generated_by=current_user.id,
    )
    db.session.add(gr)
    db.session.commit()

    if delivery == "local":
        flash(f"Report saved locally — {filename}.", "success")
    elif delivery == "both":
        flash(f"Report saved locally and pushed to cloud.", "success") if cloud_status == "ok" else None

    return redirect(url_for("reports.index"))


@reports_bp.route("/saved/<int:report_id>/download")
@login_required
def download_saved(report_id):
    gr = GeneratedReport.query.get_or_404(report_id)
    try:
        data = load_report_from_disk(gr.filename)
    except FileNotFoundError:
        flash("Report file not found on disk.", "danger")
        return redirect(url_for("reports.index"))

    mime = "application/pdf" if gr.file_format == "pdf" else "text/html"
    return send_file(
        io.BytesIO(data),
        mimetype=mime,
        download_name=gr.filename,
        as_attachment=True,
    )


@reports_bp.route("/saved/<int:report_id>/delete", methods=["POST"])
@login_required
@admin_required
def delete_saved(report_id):
    gr = GeneratedReport.query.get_or_404(report_id)
    delete_report_from_disk(gr.filename)
    db.session.delete(gr)
    db.session.commit()
    flash("Report deleted.", "success")
    return redirect(url_for("reports.index"))


@reports_bp.route("/saved/<int:report_id>/push", methods=["POST"])
@login_required
@admin_required
def push_saved(report_id):
    gr = GeneratedReport.query.get_or_404(report_id)
    try:
        data = load_report_from_disk(gr.filename)
    except FileNotFoundError:
        flash("Report file not found on disk.", "danger")
        return redirect(url_for("reports.index"))

    result = push_report_to_cloud(gr.scan, report_bytes=data, file_format=gr.file_format)
    gr.cloud_status = "ok" if result["ok"] else "error"
    gr.cloud_response = result["message"]
    gr.delivery = "both"
    db.session.commit()

    if result["ok"]:
        flash(f"Report pushed to cloud (HTTP {result['status_code']}).", "success")
    else:
        flash(f"Cloud push failed: {result['message']}", "danger")
    return redirect(url_for("reports.index"))


# Legacy on-the-fly download (kept for scan view page PDF/HTML buttons)
@reports_bp.route("/download/<int:scan_id>/<fmt>")
@login_required
def download(scan_id, fmt):
    scan = Scan.query.get_or_404(scan_id)
    if fmt == "pdf":
        data = build_pdf_report([scan])
        return send_file(io.BytesIO(data), mimetype="application/pdf",
                         download_name=f"scan_{scan_id}_report.pdf", as_attachment=True)
    else:
        html = build_html_report([scan])
        return Response(html, mimetype="text/html",
                        headers={"Content-Disposition": f"attachment;filename=scan_{scan_id}_report.html"})


@reports_bp.route("/schedule/new", methods=["GET", "POST"])
@login_required
@admin_required
def schedule_new():
    targets = Target.query.order_by(Target.name).all()
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        target_id = request.form.get("target_id", type=int) or None
        recipients = request.form.get("recipients", "").strip()
        cron = request.form.get("cron_expression", "").strip()
        fmt = request.form.get("report_format", "pdf")

        if not name or not recipients or not cron:
            flash("Name, recipients, and schedule are required.", "danger")
            return render_template("reports/schedule_new.html", targets=targets)

        next_send = _next_run_from_cron(cron)
        sched = ScheduledReport(name=name, target_id=target_id, recipients=recipients,
                                cron_expression=cron, report_format=fmt,
                                created_by=current_user.id, next_send=next_send)
        db.session.add(sched)
        db.session.commit()
        flash(f"Scheduled report '{name}' created.", "success")
        return redirect(url_for("reports.index"))

    return render_template("reports/schedule_new.html", targets=targets)


@reports_bp.route("/schedule/<int:sched_id>/delete", methods=["POST"])
@login_required
@admin_required
def schedule_delete(sched_id):
    sched = ScheduledReport.query.get_or_404(sched_id)
    db.session.delete(sched)
    db.session.commit()
    flash("Scheduled report deleted.", "success")
    return redirect(url_for("reports.index"))
