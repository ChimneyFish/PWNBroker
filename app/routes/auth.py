import re
import secrets
from urllib.parse import urlparse, urljoin
from flask import Blueprint, render_template, redirect, url_for, flash, request, session
from flask_login import login_user, logout_user, login_required, current_user
from ..models import User, SSOConfig
from ..extensions import db, limiter, oauth
from ..audit import log_action

auth_bp = Blueprint("auth", __name__)

_SSO_PROVIDERS = ("google", "microsoft")


def _safe_next(url):
    """Return url only if it points to the same host (prevents open redirect)."""
    if not url:
        return None
    host_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, url))
    if test_url.scheme in ("http", "https") and test_url.netloc == host_url.netloc:
        return url
    return None


def _unique_username_from_email(email):
    base = re.sub(r"[^a-zA-Z0-9_.-]", "", email.split("@")[0]).lower() or "user"
    username = base
    n = 1
    while User.query.filter_by(username=username).first():
        n += 1
        username = f"{base}{n}"
    return username


@auth_bp.route("/login", methods=["GET", "POST"])
@limiter.limit("8 per minute", methods=["POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard.index"))
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        user = User.query.filter_by(username=username, active=True).first()
        if user and user.check_password(password):
            if user.mfa_enabled:
                # Don't log in yet — hold the pending identity in the signed
                # session cookie until the second factor is verified.
                session["mfa_pending_user_id"]  = user.id
                session["mfa_pending_remember"] = request.form.get("remember") == "on"
                session["mfa_pending_next"]     = _safe_next(request.args.get("next"))
                return redirect(url_for("auth.login_mfa"))
            login_user(user, remember=request.form.get("remember") == "on")
            log_action("auth.login", entity_type="user", entity_id=user.id, entity_name=user.username)
            return redirect(_safe_next(request.args.get("next")) or url_for("dashboard.index"))
        log_action("auth.login_failed", entity_name=username, detail=f"Failed login attempt for '{username}'")
        flash("Invalid username or password.", "danger")
    return render_template("auth/login.html", sso_cfg=SSOConfig.query.first())


@auth_bp.route("/login/mfa", methods=["GET", "POST"])
@limiter.limit("10 per minute", methods=["POST"])
def login_mfa():
    pending_id = session.get("mfa_pending_user_id")
    if not pending_id:
        return redirect(url_for("auth.login"))

    user = db.session.get(User, pending_id)
    if not user or not user.active or not user.mfa_enabled:
        session.pop("mfa_pending_user_id", None)
        session.pop("mfa_pending_remember", None)
        session.pop("mfa_pending_next", None)
        return redirect(url_for("auth.login"))

    if request.method == "POST":
        code = request.form.get("code", "").strip()
        if user.verify_totp(code) or user.verify_backup_code(code):
            db.session.commit()  # persist backup-code consumption, if that's what matched
            remember = session.pop("mfa_pending_remember", False)
            next_url = session.pop("mfa_pending_next", None)
            session.pop("mfa_pending_user_id", None)
            login_user(user, remember=remember)
            log_action("auth.login", entity_type="user", entity_id=user.id, entity_name=user.username,
                       detail="MFA verified")
            return redirect(next_url or url_for("dashboard.index"))
        log_action("auth.login_failed", entity_type="user", entity_id=user.id, entity_name=user.username,
                   detail="Invalid MFA code")
        flash("Invalid authentication code.", "danger")
    return render_template("auth/login_mfa.html")


@auth_bp.route("/login/sso/<provider>")
def sso_login(provider):
    cfg = SSOConfig.query.first()
    if (provider not in _SSO_PROVIDERS or not cfg
            or not getattr(cfg, f"{provider}_enabled", False)):
        flash("That sign-in method isn't enabled.", "danger")
        return redirect(url_for("auth.login"))

    client = oauth.create_client(provider)
    if not client:
        flash("SSO isn't configured correctly — contact an administrator.", "danger")
        return redirect(url_for("auth.login"))

    redirect_uri = url_for("auth.sso_callback", provider=provider, _external=True)
    return client.authorize_redirect(redirect_uri)


@auth_bp.route("/login/sso/<provider>/callback")
def sso_callback(provider):
    cfg = SSOConfig.query.first()
    client = oauth.create_client(provider) if provider in _SSO_PROVIDERS else None
    if not client or not cfg:
        flash("SSO isn't configured correctly — contact an administrator.", "danger")
        return redirect(url_for("auth.login"))

    try:
        token = client.authorize_access_token()
    except Exception:
        flash("Sign-in was cancelled or failed.", "danger")
        return redirect(url_for("auth.login"))

    userinfo = token.get("userinfo") or client.userinfo(token=token)
    email = (userinfo.get("email") or "").strip().lower()
    # Some providers omit this claim entirely for accounts where it doesn't
    # apply — only reject when it's explicitly present and False.
    email_verified = userinfo.get("email_verified", True)

    if not email or not email_verified:
        flash("Could not verify your email address with the identity provider.", "danger")
        return redirect(url_for("auth.login"))

    if not cfg.domain_allowed(email):
        flash("Your account's email domain isn't authorized for SSO access.", "danger")
        return redirect(url_for("auth.login"))

    user = User.query.filter_by(email=email).first()
    if not user:
        if not cfg.auto_provision:
            flash("No account exists for this email — contact an administrator.", "danger")
            return redirect(url_for("auth.login"))
        user = User(username=_unique_username_from_email(email), email=email, role="user")
        # Random, never-shown password — this account only ever authenticates via SSO.
        user.set_password(secrets.token_urlsafe(32))
        db.session.add(user)
        db.session.commit()
        log_action("user.create", entity_type="user", entity_id=user.id, entity_name=user.username,
                   detail=f"Auto-provisioned via {provider} SSO")

    if not user.active:
        flash("This account is disabled.", "danger")
        return redirect(url_for("auth.login"))

    # SSO is treated as already having proven identity — no local MFA step.
    login_user(user)
    log_action("auth.login", entity_type="user", entity_id=user.id, entity_name=user.username,
               detail=f"SSO via {provider}")
    return redirect(url_for("dashboard.index"))


@auth_bp.route("/logout")
@login_required
def logout():
    log_action("auth.logout", entity_type="user", entity_id=current_user.id, entity_name=current_user.username)
    logout_user()
    return redirect(url_for("auth.login"))
