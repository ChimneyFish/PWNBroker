from flask import Blueprint, render_template, redirect, url_for, flash, request, session
from flask_login import login_required, current_user
from ..models import User
from ..extensions import db
from ..audit import log_action
from .decorators import admin_required

users_bp = Blueprint("users", __name__, url_prefix="/users")


def _mfa_qr_data_uri(secret, email):
    import io
    import base64
    import pyotp
    import qrcode
    uri = pyotp.totp.TOTP(secret).provisioning_uri(name=email, issuer_name="PwnBroker")
    img = qrcode.make(uri)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return f"data:image/png;base64,{base64.b64encode(buf.getvalue()).decode()}"


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
            current_user.must_change_password = False
            log_action("user.password_change", entity_type="user",
                       entity_id=current_user.id, entity_name=current_user.username)
        db.session.commit()
        flash("Profile updated.", "success")
        return redirect(url_for("users.profile"))
    return render_template("users/profile.html")


# ── MFA (TOTP) ──────────────────────────────────────────────────────────────

@users_bp.route("/mfa/setup", methods=["GET", "POST"])
@login_required
def mfa_setup():
    import pyotp

    if current_user.mfa_enabled:
        flash("Two-factor authentication is already enabled.", "info")
        return redirect(url_for("users.profile"))

    if request.method == "POST":
        secret = session.get("mfa_setup_secret")
        code   = request.form.get("code", "").strip()
        if not secret:
            flash("Setup session expired — start again.", "danger")
            return redirect(url_for("users.mfa_setup"))

        if not pyotp.TOTP(secret).verify(code, valid_window=1):
            flash("Invalid code — check your authenticator app and try again.", "danger")
            return render_template("users/mfa_setup.html",
                                   qr_data_uri=_mfa_qr_data_uri(secret, current_user.email),
                                   secret=secret)

        current_user.mfa_secret  = secret
        current_user.mfa_enabled = True
        backup_codes = current_user.generate_backup_codes()
        db.session.commit()
        session.pop("mfa_setup_secret", None)
        log_action("user.mfa_enabled", entity_type="user",
                   entity_id=current_user.id, entity_name=current_user.username)
        return render_template("users/mfa_backup_codes.html", backup_codes=backup_codes)

    secret = pyotp.random_base32()
    session["mfa_setup_secret"] = secret
    return render_template("users/mfa_setup.html",
                           qr_data_uri=_mfa_qr_data_uri(secret, current_user.email),
                           secret=secret)


@users_bp.route("/mfa/disable", methods=["POST"])
@login_required
def mfa_disable():
    password = request.form.get("password", "")
    code     = request.form.get("code", "").strip()

    if not current_user.check_password(password):
        flash("Current password is incorrect.", "danger")
        return redirect(url_for("users.profile"))
    if not (current_user.verify_totp(code) or current_user.verify_backup_code(code)):
        flash("Invalid authentication code.", "danger")
        return redirect(url_for("users.profile"))

    current_user.clear_mfa()
    db.session.commit()
    log_action("user.mfa_disabled", entity_type="user",
               entity_id=current_user.id, entity_name=current_user.username)
    flash("Two-factor authentication disabled.", "success")
    return redirect(url_for("users.profile"))


@users_bp.route("/<int:user_id>/mfa/reset", methods=["POST"])
@login_required
@admin_required
def mfa_reset(user_id):
    u = User.query.get_or_404(user_id)
    u.clear_mfa()
    db.session.commit()
    log_action("user.mfa_reset", entity_type="user", entity_id=u.id, entity_name=u.username,
               detail=f"Reset by {current_user.username}")
    flash(f"MFA reset for {u.username} — they'll need to re-enroll.", "success")
    return redirect(url_for("users.index"))


@users_bp.route("/<int:user_id>/mfa/require", methods=["POST"])
@login_required
@admin_required
def mfa_require_toggle(user_id):
    u = User.query.get_or_404(user_id)
    u.mfa_required = not u.mfa_required
    db.session.commit()
    flash(f"MFA {'now required' if u.mfa_required else 'no longer required'} for {u.username}.", "success")
    return redirect(url_for("users.index"))
