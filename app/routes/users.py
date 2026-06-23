from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_required, current_user
from ..models import User
from ..extensions import db
from ..audit import log_action
from .decorators import admin_required

users_bp = Blueprint("users", __name__, url_prefix="/users")


@users_bp.route("/")
@login_required
@admin_required
def index():
    users = User.query.order_by(User.created_at.desc()).all()
    return render_template("users/index.html", users=users)


@users_bp.route("/new", methods=["GET", "POST"])
@login_required
@admin_required
def new():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")
        role = request.form.get("role", "user")
        if not username or not email or not password:
            flash("All fields required.", "danger")
            return render_template("users/new.html")
        if User.query.filter((User.username == username) | (User.email == email)).first():
            flash("Username or email already exists.", "danger")
            return render_template("users/new.html")
        u = User(username=username, email=email, role=role)
        u.set_password(password)
        db.session.add(u)
        db.session.commit()
        log_action("user.create", entity_type="user", entity_id=u.id,
                   entity_name=username, detail=f"Role: {role}")
        flash(f"User '{username}' created.", "success")
        return redirect(url_for("users.index"))
    return render_template("users/new.html")


@users_bp.route("/<int:user_id>/toggle", methods=["POST"])
@login_required
@admin_required
def toggle(user_id):
    u = User.query.get_or_404(user_id)
    if u.id == current_user.id:
        flash("Cannot deactivate your own account.", "warning")
        return redirect(url_for("users.index"))
    u.active = not u.active
    db.session.commit()
    flash(f"User {'activated' if u.active else 'deactivated'}.", "success")
    return redirect(url_for("users.index"))


@users_bp.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    if request.method == "POST":
        email = request.form.get("email", "").strip()
        current_pw = request.form.get("current_password", "")
        new_pw = request.form.get("new_password", "")
        if email:
            current_user.email = email
        if current_pw and new_pw:
            if not current_user.check_password(current_pw):
                flash("Current password is incorrect.", "danger")
                return render_template("users/profile.html")
            current_user.set_password(new_pw)
            log_action("user.password_change", entity_type="user",
                       entity_id=current_user.id, entity_name=current_user.username)
        db.session.commit()
        flash("Profile updated.", "success")
        return redirect(url_for("users.profile"))
    return render_template("users/profile.html")
