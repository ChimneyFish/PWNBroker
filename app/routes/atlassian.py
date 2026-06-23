from flask import Blueprint, redirect, url_for, flash, request, jsonify
from flask_login import login_required, current_user
from ..models import Scan, AtlassianConfig, ConfluencePage, JiraTicket
from ..extensions import db
from .decorators import admin_required
from datetime import datetime, timezone

atlassian_bp = Blueprint("atlassian", __name__, url_prefix="/atlassian")


def _get_cfg():
    return AtlassianConfig.query.first()


@atlassian_bp.route("/confluence/publish/<int:scan_id>", methods=["POST"])
@login_required
@admin_required
def confluence_publish(scan_id):
    scan = Scan.query.get_or_404(scan_id)
    cfg = _get_cfg()

    if not cfg or not cfg.enabled or not cfg.confluence_enabled:
        flash("Confluence integration is not enabled.", "warning")
        return redirect(request.referrer or url_for("reports.index"))

    from ..integrations.confluence import publish_to_confluence
    result = publish_to_confluence(scan, cfg)

    if result["ok"]:
        existing = ConfluencePage.query.filter_by(scan_id=scan.id).first()
        if existing:
            existing.page_id = result["page_id"]
            existing.page_url = result["page_url"]
            existing.published_by = current_user.id
            existing.published_at = datetime.now(timezone.utc)
        else:
            page = ConfluencePage(
                scan_id=scan.id,
                page_id=result["page_id"],
                page_url=result["page_url"],
                published_by=current_user.id,
            )
            db.session.add(page)
        db.session.commit()
        flash(f"Published to Confluence: {result['page_url']}", "success")
    else:
        flash(f"Confluence publish failed: {result['message']}", "danger")

    return redirect(request.referrer or url_for("reports.index"))


@atlassian_bp.route("/jira/create/<int:scan_id>", methods=["POST"])
@login_required
@admin_required
def jira_create(scan_id):
    scan = Scan.query.get_or_404(scan_id)
    cfg = _get_cfg()

    if not cfg or not cfg.enabled or not cfg.jira_enabled:
        flash("Jira integration is not enabled.", "warning")
        return redirect(request.referrer or url_for("scans.view", scan_id=scan_id))

    from ..integrations.jira_client import create_tickets_for_scan
    result = create_tickets_for_scan(scan, cfg)

    parts = [f"{result['created']} ticket(s) created"]
    if result["skipped"]:
        parts.append(f"{result['skipped']} already ticketed")
    if result["errors"]:
        parts.append(f"{len(result['errors'])} error(s)")

    msg = ", ".join(parts) + "."
    level = "success" if result["created"] > 0 else ("warning" if not result["errors"] else "danger")
    flash(msg, level)

    if result["errors"]:
        for e in result["errors"][:3]:
            flash(e, "danger")

    return redirect(request.referrer or url_for("scans.view", scan_id=scan_id))
