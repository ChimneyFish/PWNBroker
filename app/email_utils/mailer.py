import io
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication
from datetime import datetime, timezone
from ..models import ScanResult, Scan, EmailConfig
from .report_builder import build_pdf_report, build_html_report


def _get_smtp_config(app):
    with app.app_context():
        cfg = EmailConfig.query.first()
        if cfg and cfg.smtp_server:
            return cfg
    return None


def send_scheduled_report(app, scheduled_report):
    with app.app_context():
        cfg = _get_smtp_config(app)
        if not cfg:
            app.logger.warning("No email config — skipping report email.")
            return

        target_id = scheduled_report.target_id
        query = Scan.query.filter_by(status="done")
        if target_id:
            query = query.filter_by(target_id=target_id)
        scans = query.order_by(Scan.completed_at.desc()).limit(10).all()

        if not scans:
            return

        recipients = [r.strip() for r in scheduled_report.recipients.split(",") if r.strip()]
        subject = f"Vulnerability Report: {scheduled_report.name} — {datetime.now(timezone.utc).strftime('%Y-%m-%d')}"

        if scheduled_report.report_format == "pdf":
            attachment = build_pdf_report(scans)
            filename = f"report_{datetime.now(timezone.utc).strftime('%Y%m%d')}.pdf"
            mime_type = "application/pdf"
        else:
            attachment = build_html_report(scans).encode("utf-8")
            filename = f"report_{datetime.now(timezone.utc).strftime('%Y%m%d')}.html"
            mime_type = "text/html"

        _send_email(cfg, recipients, subject, attachment, filename, mime_type)


def _send_email(cfg, recipients, subject, attachment_bytes, filename, mime_type):
    msg = MIMEMultipart()
    msg["From"] = cfg.sender
    msg["To"] = ", ".join(recipients)
    msg["Subject"] = subject

    body = MIMEText("Please find the attached vulnerability report.", "plain")
    msg.attach(body)

    part = MIMEApplication(attachment_bytes, Name=filename)
    part["Content-Disposition"] = f'attachment; filename="{filename}"'
    msg.attach(part)

    with smtplib.SMTP(cfg.smtp_server, cfg.smtp_port, timeout=30) as server:
        if cfg.use_tls:
            server.starttls()
        if cfg.username:
            server.login(cfg.username, cfg.password)
        server.sendmail(cfg.sender, recipients, msg.as_string())
