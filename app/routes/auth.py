from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_user, logout_user, login_required, current_user
from ..models import User
from ..extensions import db

auth_bp = Blueprint("auth", __name__)


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard.index"))
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        user = User.query.filter_by(username=username, active=True).first()
        if user and user.check_password(password):
            login_user(user, remember=request.form.get("remember") == "on")
            from ..audit import log_action
            log_action("auth.login", entity_type="user", entity_id=user.id, entity_name=user.username)
            return redirect(request.args.get("next") or url_for("dashboard.index"))
        from ..audit import log_action
        log_action("auth.login_failed", entity_name=username, detail=f"Failed login attempt for '{username}'")
        flash("Invalid username or password.", "danger")
    return render_template("auth/login.html")


@auth_bp.route("/logout")
@login_required
def logout():
    from ..audit import log_action
    log_action("auth.logout", entity_type="user", entity_id=current_user.id, entity_name=current_user.username)
    logout_user()
    return redirect(url_for("auth.login"))
