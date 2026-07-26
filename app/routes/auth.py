import re
import secrets
from urllib.parse import urlparse, urljoin
from flask import Blueprint, render_template, redirect, url_for, flash, request, session, Response, current_app
from flask_login import login_user, logout_user, login_required, current_user
from onelogin.saml2.auth import OneLogin_Saml2_Auth
from onelogin.saml2.settings import OneLogin_Saml2_Settings
from ..models import User, SSOConfig
from ..extensions import db, limiter, oauth, csrf
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


def _finish_sso_login(email, mechanism_label):
    """Shared identity-resolution tail for every SSO mechanism (OIDC
    providers and SAML): domain-gate, find-or-auto-provision, then log in.
    Kept in one place so the "empty allowlist never auto-provisions" safety
    invariant only has to be correct once. Callers are responsible for their
    own protocol-specific identity verification (OIDC's email_verified claim,
    SAML's signed-assertion validation) before calling this."""
    cfg = SSOConfig.query.first()
    email = (email or "").strip().lower()
    if not email or not cfg or not cfg.domain_allowed(email):
        flash("Your account's email domain isn't authorized for SSO access.", "danger")
        return redirect(url_for("auth.login"))

    user = User.query.filter_by(email=email).first()
    if not user:
        if not cfg.auto_provision:
            flash("No account exists for this email — contact an administrator.", "danger")
            return redirect(url_for("auth.login"))
        # Random, never-shown password — this account only ever authenticates via SSO.
        user = User(username=_unique_username_from_email(email), email=email, role="user")
        user.set_password(secrets.token_urlsafe(32))
        db.session.add(user)
        db.session.commit()
        log_action("user.create", entity_type="user", entity_id=user.id, entity_name=user.username,
                   detail=f"Auto-provisioned via {mechanism_label} SSO")

    if not user.active:
        flash("This account is disabled.", "danger")
        return redirect(url_for("auth.login"))

    # SSO is treated as already having proven identity — no local MFA step.
    login_user(user)
    log_action("auth.login", entity_type="user", entity_id=user.id, entity_name=user.username,
               detail=f"SSO via {mechanism_label}")
    return redirect(url_for("dashboard.index"))


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

    return _finish_sso_login(email, provider)


# ── SAML 2.0 (e.g. Microsoft Entra Enterprise App "SAML-based sign-on") ──────
# A separate protocol from the OIDC providers above — no client secret, trust
# comes from the IdP's signed XML assertions plus its certificate, both
# populated by uploading the IdP's Federation Metadata in Settings.

_SAML_EMAIL_CLAIMS = (
    "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
    "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name",  # UPN — last resort
)


def _prepare_flask_request(req):
    """Build the request dict python3-saml expects. This deployment runs
    gunicorn directly (no reverse proxy in front — see docs/deployment.md's
    Process model section), so request.scheme/host are already correct."""
    return {
        "https": "on" if req.scheme == "https" else "off",
        "http_host": req.host,
        "script_name": req.path,
        "get_data": req.args.copy(),
        "post_data": req.form.copy(),
    }


def _saml_settings(cfg):
    """Build the python3-saml settings dict from the DB-stored IdP config.
    strict/wantAssertionsSigned are hardcoded True — these are what make the
    library actually validate signatures, timestamps, and audience
    restriction (the defense against XML signature-wrapping attacks). They
    must never become admin-configurable."""
    sp_entity_id = cfg.saml_sp_entity_id or url_for("auth.saml_metadata", _external=True)
    return {
        "strict": True,
        "debug": False,
        "sp": {
            "entityId": sp_entity_id,
            "assertionConsumerService": {
                "url": url_for("auth.saml_acs", _external=True),
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
            },
            "NameIDFormat": "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
        },
        "idp": {
            "entityId": cfg.saml_idp_entity_id or "",
            "singleSignOnService": {
                "url": cfg.saml_idp_sso_url or "",
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
            },
            "x509cert": cfg.saml_idp_x509_cert or "",
        },
        "security": {
            "authnRequestsSigned": False,
            "wantMessagesSigned": False,
            "wantAssertionsSigned": True,
            "wantNameId": True,
            "requestedAuthnContext": False,
            "signatureAlgorithm": "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
            "digestAlgorithm": "http://www.w3.org/2001/04/xmlenc#sha256",
        },
    }


def _saml_email_from_response(auth):
    """Prefer the explicit emailaddress claim — NameID and UPN are both
    syntactically email-shaped (user@domain) whether or not they're actually
    the user's real email, so they're an ambiguous fallback, not a first
    choice. Entra emits the emailaddress claim by default; NameID and the UPN
    claim are only consulted if it's missing."""
    attrs = auth.get_attributes() or {}
    values = attrs.get(_SAML_EMAIL_CLAIMS[0])
    if values and "@" in values[0]:
        return values[0].strip().lower()
    nameid = (auth.get_nameid() or "").strip()
    if "@" in nameid:
        return nameid.lower()
    values = attrs.get(_SAML_EMAIL_CLAIMS[1])
    if values and "@" in values[0]:
        return values[0].strip().lower()
    return ""


@auth_bp.route("/login/sso/saml")
def saml_login():
    cfg = SSOConfig.query.first()
    if not cfg or not cfg.saml_enabled or not cfg.saml_idp_sso_url or not cfg.saml_idp_x509_cert:
        flash("That sign-in method isn't enabled.", "danger")
        return redirect(url_for("auth.login"))

    try:
        auth = OneLogin_Saml2_Auth(_prepare_flask_request(request), _saml_settings(cfg))
        redirect_url = auth.login()
        session["SAML_AuthNRequestID"] = auth.get_last_request_id()
    except Exception:
        current_app.logger.exception("Failed to build SAML AuthnRequest")
        flash("SSO isn't configured correctly — contact an administrator.", "danger")
        return redirect(url_for("auth.login"))
    return redirect(redirect_url)


@auth_bp.route("/login/sso/saml/acs", methods=["POST"])
@csrf.exempt  # cross-origin POST from the IdP — no session-carried CSRF token to check,
              # same reasoning as the agent API routes in threat.py
def saml_acs():
    cfg = SSOConfig.query.first()
    if not cfg or not cfg.saml_enabled:
        flash("That sign-in method isn't enabled.", "danger")
        return redirect(url_for("auth.login"))

    try:
        auth = OneLogin_Saml2_Auth(_prepare_flask_request(request), _saml_settings(cfg))
        request_id = session.pop("SAML_AuthNRequestID", None)
        auth.process_response(request_id=request_id)
        errors = auth.get_errors()
        authenticated = not errors and auth.is_authenticated()
    except Exception:
        current_app.logger.exception("SAML response processing failed")
        errors, authenticated = ["exception during processing"], False

    if not authenticated:
        current_app.logger.warning("SAML login rejected: %s", "; ".join(errors) or "not authenticated")
        flash("Sign-in failed — the identity provider rejected the request.", "danger")
        return redirect(url_for("auth.login"))

    email = _saml_email_from_response(auth)
    if not email:
        flash("Could not determine your email address from the identity provider's response — "
              "an administrator needs to add an email claim to the SAML app configuration.", "danger")
        return redirect(url_for("auth.login"))

    return _finish_sso_login(email, "SAML")


@auth_bp.route("/login/sso/saml/metadata")
def saml_metadata():
    """This SP's own metadata — what an admin can point Entra at directly,
    and the source of truth for the ACS URL / Entity ID shown in Settings."""
    cfg = SSOConfig.query.first() or SSOConfig()
    settings = OneLogin_Saml2_Settings(_saml_settings(cfg), sp_validation_only=True)
    metadata = settings.get_sp_metadata()
    errors = settings.validate_metadata(metadata)
    if errors:
        current_app.logger.error("Invalid SP metadata: %s", "; ".join(errors))
        return Response("Invalid SP metadata configuration", status=500)
    return Response(metadata, mimetype="text/xml")


@auth_bp.route("/logout")
@login_required
def logout():
    log_action("auth.logout", entity_type="user", entity_id=current_user.id, entity_name=current_user.username)
    logout_user()
    return redirect(url_for("auth.login"))
