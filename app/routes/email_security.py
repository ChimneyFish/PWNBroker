import json
import secrets
from datetime import datetime, timezone

from flask import Blueprint, render_template, redirect, url_for, flash, request, jsonify, session
from flask_login import login_required, current_user

from ..models import O365Config, MonitoredMailbox, EmailScanResult
from ..extensions import db
from .decorators import admin_required

email_security_bp = Blueprint("email_security", __name__, url_prefix="/email-security")


def _get_cfg():
    cfg = O365Config.query.first()
    if not cfg:
        cfg = O365Config()
        db.session.add(cfg)
        db.session.commit()
    return cfg


@email_security_bp.route("/oauth/authorize")
@login_required
@admin_required
def oauth_authorize():
    """Kicks off Microsoft's hosted admin-consent flow — the one-click
    "Authorize in Microsoft" button. Requires the Azure AD app (tenant_id +
    client_id) to already exist; see the quick-setup script in Settings for
    the one-time app-registration step this can't skip."""
    cfg = _get_cfg()
    if not (cfg.tenant_id and cfg.client_id):
        flash("Enter Tenant ID and Client ID in Settings first (or run the quick-setup script), then Authorize.", "warning")
        return redirect(url_for("settings.index") + "#o365")

    state = secrets.token_urlsafe(24)
    session["o365_oauth_state"] = state
    redirect_uri = url_for("email_security.oauth_callback", _external=True)
    consent_url = (
        f"https://login.microsoftonline.com/{cfg.tenant_id}/adminconsent"
        f"?client_id={cfg.client_id}&redirect_uri={redirect_uri}&state={state}"
    )
    return redirect(consent_url)


@email_security_bp.route("/oauth/callback")
@login_required
def oauth_callback():
    """Microsoft redirects the admin's browser back here after they accept
    (or decline) the consent prompt. There's no client secret exchange here —
    admin-consent only grants the permissions already declared on the app; the
    client secret PWNBroker uses for the actual Graph calls is still entered
    separately in Settings."""
    error = request.args.get("error")
    if error:
        flash(f"Microsoft consent failed: {request.args.get('error_description', error)}", "danger")
        return redirect(url_for("settings.index") + "#o365")

    expected_state = session.pop("o365_oauth_state", None)
    state = request.args.get("state")
    if not state or not expected_state or state != expected_state:
        flash("Consent request could not be verified (state mismatch) — please try Authorize again.", "danger")
        return redirect(url_for("settings.index") + "#o365")

    if request.args.get("admin_consent") != "True":
        flash("Consent was not granted.", "warning")
        return redirect(url_for("settings.index") + "#o365")

    cfg = _get_cfg()
    cfg.status = "ok"
    cfg.last_error = None
    db.session.commit()
    flash("Microsoft 365 admin consent granted. Make sure your client secret is saved and "
          "Email Security is enabled below.", "success")
    return redirect(url_for("settings.index") + "#o365")


@email_security_bp.route("/")
@login_required
def index():
    cfg = _get_cfg()
    total_mailboxes = MonitoredMailbox.query.filter_by(enabled=True).count()
    total_scanned   = EmailScanResult.query.count()
    phishing_count  = EmailScanResult.query.filter_by(is_phishing_risk=True).count()
    dlp_count       = EmailScanResult.query.filter_by(is_dlp_risk=True).count()
    shadow_it_count = EmailScanResult.query.filter_by(is_shadow_it=True).count()
    pending_count   = EmailScanResult.query.filter_by(status="new").count()
    recent = (EmailScanResult.query
              .order_by(EmailScanResult.created_at.desc())
              .limit(10).all())

    return render_template("email_security/index.html", cfg=cfg,
                           total_mailboxes=total_mailboxes, total_scanned=total_scanned,
                           phishing_count=phishing_count, dlp_count=dlp_count,
                           shadow_it_count=shadow_it_count, pending_count=pending_count,
                           recent=recent)


@email_security_bp.route("/poll", methods=["POST"])
@login_required
@admin_required
def poll_now():
    cfg = _get_cfg()
    if not cfg.enabled:
        flash("O365 email security isn't enabled yet — configure it in Settings first.", "warning")
        return redirect(url_for("email_security.index"))

    from ..email_security.scanner import poll_mail
    flagged = poll_mail()
    if flagged < 0:
        flash("Poll failed — check the O365 credentials in Settings.", "danger")
    else:
        flash(f"Poll complete — {flagged} message(s) flagged.", "success")
    return redirect(url_for("email_security.index"))


@email_security_bp.route("/mailboxes")
@login_required
def mailboxes():
    boxes = MonitoredMailbox.query.order_by(MonitoredMailbox.upn).all()
    return render_template("email_security/mailboxes.html", boxes=boxes, cfg=_get_cfg())


@email_security_bp.route("/mailboxes/sync", methods=["POST"])
@login_required
@admin_required
def mailboxes_sync():
    cfg = _get_cfg()
    if not cfg.enabled:
        flash("O365 email security isn't enabled yet — configure it in Settings first.", "warning")
        return redirect(url_for("email_security.mailboxes"))

    from ..email_security.scanner import sync_mailboxes
    count = sync_mailboxes()
    if count < 0:
        flash("Mailbox sync failed — check the O365 credentials in Settings.", "danger")
    else:
        flash(f"Synced {count} mailbox(es) from the tenant.", "success")
    return redirect(url_for("email_security.mailboxes"))


@email_security_bp.route("/mailboxes/<int:mailbox_id>/toggle", methods=["POST"])
@login_required
@admin_required
def mailbox_toggle(mailbox_id):
    mb = MonitoredMailbox.query.get_or_404(mailbox_id)
    mb.enabled = not mb.enabled
    db.session.commit()
    return jsonify({"ok": True, "enabled": mb.enabled})


@email_security_bp.route("/alerts")
@login_required
def alerts():
    flag_filter   = request.args.get("flag", "")
    status_filter = request.args.get("status", "new")

    q = EmailScanResult.query
    if flag_filter == "phishing":
        q = q.filter_by(is_phishing_risk=True)
    elif flag_filter == "dlp":
        q = q.filter_by(is_dlp_risk=True)
    elif flag_filter == "shadow_it":
        q = q.filter_by(is_shadow_it=True)
    if status_filter != "all":
        q = q.filter_by(status=status_filter)

    results = q.order_by(EmailScanResult.created_at.desc()).limit(200).all()
    return render_template("email_security/alerts.html", results=results,
                           flag_filter=flag_filter, status_filter=status_filter)


@email_security_bp.route("/alerts/<int:result_id>")
@login_required
def alert_detail(result_id):
    result = EmailScanResult.query.get_or_404(result_id)
    return render_template("email_security/alert_detail.html", r=result)


@email_security_bp.route("/alerts/<int:result_id>/review", methods=["POST"])
@login_required
@admin_required
def alert_review(result_id):
    result = EmailScanResult.query.get_or_404(result_id)
    new_status = request.form.get("status", "").strip()
    notes = request.form.get("notes", "").strip()

    if new_status not in ("reviewed", "dismissed", "escalated"):
        flash("Invalid status.", "danger")
        return redirect(url_for("email_security.alert_detail", result_id=result.id))

    result.status = new_status
    if notes:
        result.notes = notes
    result.reviewed_by = current_user.id
    result.reviewed_at = datetime.now(timezone.utc)
    db.session.commit()

    from ..audit import log_action
    log_action("email_security.review", entity_type="email_scan_result", entity_id=result.id,
               entity_name=result.subject or result.sender, detail=f"status -> {new_status}")

    flash("Email alert updated.", "success")
    return redirect(url_for("email_security.alerts"))
