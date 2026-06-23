"""
Lightweight audit-logging helper.
Call log_action() from any route after a state-changing operation.
Never raises — logging failures are swallowed so they never break a request.
"""
import logging

log = logging.getLogger(__name__)

# Human-readable labels for actions shown in the UI
ACTION_LABELS = {
    "auth.login":            "Login",
    "auth.login_failed":     "Login Failed",
    "auth.logout":           "Logout",
    "scan.create":           "Scan Created",
    "scan.start":            "Scan Started",
    "scan.complete":         "Scan Completed",
    "scan.delete":           "Scan Deleted",
    "target.create":         "Target Created",
    "target.update":         "Target Updated",
    "target.delete":         "Target Deleted",
    "vuln.status_change":    "Vuln Status Changed",
    "vuln.assign":           "Vuln Assigned",
    "vuln.auto_close":       "Vulns Auto-Closed",
    "asset.tag_add":         "Tag Added to Asset",
    "asset.tag_remove":      "Tag Removed from Asset",
    "asset.notes_update":    "Asset Notes Updated",
    "asset.hostname_update": "Asset Hostname Updated",
    "user.create":           "User Created",
    "user.delete":           "User Deleted",
    "user.role_change":      "User Role Changed",
    "user.password_change":  "Password Changed",
    "settings.threat_save":  "Threat Intel Settings Saved",
    "settings.general_save": "General Settings Saved",
    "risk.create":           "Risk Created",
    "risk.update":           "Risk Updated",
    "risk.delete":           "Risk Deleted",
    "policy.create":         "Policy Created",
    "policy.update":         "Policy Updated",
    "policy.delete":         "Policy Deleted",
    "compliance.assess":     "Control Assessed",
    "evidence.upload":       "Evidence Uploaded",
    "evidence.delete":       "Evidence Deleted",
    "enrichment.trigger":    "CVE Enrichment Triggered",
    "assess.trigger":        "Auto-Assessment Triggered",
    "report.generate":       "Report Generated",
}

ACTION_ICONS = {
    "auth.login":            "bi-box-arrow-in-right text-success",
    "auth.login_failed":     "bi-exclamation-triangle text-danger",
    "auth.logout":           "bi-box-arrow-left text-muted",
    "scan.create":           "bi-plus-circle text-primary",
    "scan.start":            "bi-play-circle text-primary",
    "scan.complete":         "bi-check-circle text-success",
    "scan.delete":           "bi-trash text-danger",
    "target.create":         "bi-plus-circle text-primary",
    "target.update":         "bi-pencil text-info",
    "target.delete":         "bi-trash text-danger",
    "vuln.status_change":    "bi-arrow-repeat text-warning",
    "vuln.assign":           "bi-person-check text-info",
    "vuln.auto_close":       "bi-check2-circle text-success",
    "asset.tag_add":         "bi-tag text-info",
    "asset.tag_remove":      "bi-tag text-muted",
    "asset.notes_update":    "bi-pencil text-muted",
    "asset.hostname_update": "bi-pencil text-muted",
    "user.create":           "bi-person-plus text-success",
    "user.delete":           "bi-person-x text-danger",
    "user.role_change":      "bi-shield text-warning",
    "user.password_change":  "bi-key text-warning",
    "settings.threat_save":  "bi-shield-exclamation text-info",
    "settings.general_save": "bi-gear text-muted",
    "risk.create":           "bi-plus-circle text-danger",
    "risk.update":           "bi-pencil text-warning",
    "risk.delete":           "bi-trash text-danger",
    "policy.create":         "bi-file-plus text-primary",
    "policy.update":         "bi-file-text text-info",
    "policy.delete":         "bi-file-x text-danger",
    "compliance.assess":     "bi-clipboard-check text-success",
    "evidence.upload":       "bi-paperclip text-info",
    "evidence.delete":       "bi-paperclip text-danger",
    "enrichment.trigger":    "bi-cloud-download text-info",
    "assess.trigger":        "bi-robot text-info",
    "report.generate":       "bi-file-earmark-text text-primary",
}


def log_action(action, entity_type=None, entity_id=None, entity_name=None, detail=None):
    """
    Write an audit log entry. Safe to call from any Flask request context.
    entity_type: 'scan' | 'target' | 'vuln_ticket' | 'asset' | 'user' | 'risk' | 'policy' | 'control' | ...
    """
    try:
        from .models import AuditLog
        from .extensions import db
        from flask import request as _req
        from flask_login import current_user

        try:
            user_id = current_user.id if current_user and current_user.is_authenticated else None
        except Exception:
            user_id = None

        try:
            ip = _req.remote_addr
        except Exception:
            ip = None

        entry = AuditLog(
            user_id     = user_id,
            ip_address  = ip,
            action      = action,
            entity_type = entity_type,
            entity_id   = entity_id,
            entity_name = entity_name,
            detail      = detail,
        )
        db.session.add(entry)
        db.session.commit()
    except Exception as exc:
        log.warning("audit log write failed: %s", exc)
        try:
            from .extensions import db
            db.session.rollback()
        except Exception:
            pass
