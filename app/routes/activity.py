from datetime import datetime, timezone, timedelta
from flask import Blueprint, render_template, request, jsonify
from flask_login import login_required, current_user
from ..models import AuditLog, User
from ..extensions import db
from ..audit import ACTION_LABELS, ACTION_ICONS
from .decorators import admin_required

activity_bp = Blueprint("activity", __name__, url_prefix="/activity")


@activity_bp.route("/")
@login_required
@admin_required
def index():
    action_f   = request.args.get("action", "")
    user_f     = request.args.get("user_id", "", type=str)
    days_f     = request.args.get("days", "7", type=str)

    q = AuditLog.query.order_by(AuditLog.timestamp.desc())

    if action_f:
        q = q.filter(AuditLog.action == action_f)
    if user_f.isdigit():
        q = q.filter(AuditLog.user_id == int(user_f))
    if days_f.isdigit() and int(days_f) > 0:
        cutoff = datetime.now(timezone.utc) - timedelta(days=int(days_f))
        q = q.filter(AuditLog.timestamp >= cutoff)

    entries = q.limit(500).all()
    users   = User.query.order_by(User.username).all()

    # Distinct actions that have actually been logged (for filter dropdown)
    used_actions = (
        db.session.query(AuditLog.action)
        .distinct()
        .order_by(AuditLog.action)
        .all()
    )
    used_actions = [r[0] for r in used_actions]

    return render_template(
        "activity/index.html",
        entries=entries,
        users=users,
        action_filter=action_f,
        user_filter=user_f,
        days_filter=days_f,
        used_actions=used_actions,
        action_labels=ACTION_LABELS,
        action_icons=ACTION_ICONS,
    )


@activity_bp.route("/clear", methods=["POST"])
@login_required
@admin_required
def clear():
    days = request.form.get("days", "90", type=int)
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    deleted = AuditLog.query.filter(AuditLog.timestamp < cutoff).delete()
    db.session.commit()
    from ..audit import log_action
    log_action("settings.general_save", detail=f"Cleared {deleted} audit log entries older than {days} days")
    return jsonify(ok=True, deleted=deleted)
