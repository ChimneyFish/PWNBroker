import os
import re
import ssl
import subprocess
from datetime import datetime, timezone
from zoneinfo import ZoneInfo, available_timezones
from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_required, current_user
from ..models import EmailConfig, User, CloudConfig, AtlassianConfig, ThreatConfig, TimeConfig
from ..extensions import db
from .decorators import admin_required


# ── NTP / time helpers ────────────────────────────────────────────────────────

TIMESYNCD_CONF = "/etc/systemd/timesyncd.conf"
_NTP_RE = re.compile(r'^[a-zA-Z0-9.\-]+$')


def _ntp_status():
    """Read NTP sync state from timedatectl. Returns dict (all keys may be None on failure)."""
    try:
        r = subprocess.run(["timedatectl", "show", "--no-pager"],
                           capture_output=True, text=True, timeout=5)
        info = {}
        for line in r.stdout.splitlines():
            if "=" in line:
                k, v = line.split("=", 1)
                info[k.strip()] = v.strip()
        return {
            "ntp_active":   info.get("NTP", "no") == "yes",
            "ntp_synced":   info.get("NTPSynchronized", "no") == "yes",
            "sys_timezone": info.get("Timezone"),
        }
    except Exception:
        return {"ntp_active": None, "ntp_synced": None, "sys_timezone": None}


def _read_ntp_server():
    """Return the current NTP= value from timesyncd.conf, or ''."""
    try:
        with open(TIMESYNCD_CONF) as f:
            for line in f:
                s = line.strip()
                if s.startswith("NTP=") and not s.startswith("#"):
                    return s.split("=", 1)[1].strip()
    except Exception:
        pass
    return ""


def _write_ntp_server(server):
    """Write NTP server to timesyncd.conf and restart the service. Returns (ok, errmsg)."""
    if not _NTP_RE.fullmatch(server):
        return False, "Invalid NTP server address (use hostname or IP only)"
    try:
        with open(TIMESYNCD_CONF) as f:
            content = f.read()
        if re.search(r"^#?NTP=", content, re.MULTILINE):
            content = re.sub(r"^#?NTP=.*$", f"NTP={server}", content, flags=re.MULTILINE)
        else:
            # Ensure the [Time] section exists
            if "[Time]" not in content:
                content += "\n[Time]\n"
            content += f"NTP={server}\n"
        with open(TIMESYNCD_CONF, "w") as f:
            f.write(content)
        subprocess.run(["systemctl", "restart", "systemd-timesyncd"],
                       timeout=10, check=True, capture_output=True)
        subprocess.run(["timedatectl", "set-ntp", "true"],
                       timeout=10, check=True, capture_output=True)
        return True, None
    except PermissionError:
        return False, "Permission denied — restart as root or run: sudo systemctl restart systemd-timesyncd"
    except subprocess.CalledProcessError as e:
        return False, f"Command failed: {e.stderr.decode(errors='ignore').strip() or e}"
    except Exception as e:
        return False, str(e)


def _tz_list():
    """Return sorted list of (region, name) tuples for the timezone selector."""
    common = [
        "UTC",
        "America/New_York", "America/Chicago", "America/Denver", "America/Los_Angeles",
        "America/Anchorage", "America/Honolulu", "America/Phoenix",
        "Europe/London", "Europe/Paris", "Europe/Berlin", "Europe/Moscow",
        "Asia/Dubai", "Asia/Kolkata", "Asia/Bangkok", "Asia/Singapore",
        "Asia/Tokyo", "Asia/Shanghai", "Asia/Seoul",
        "Australia/Sydney", "Australia/Perth",
        "Pacific/Auckland",
    ]
    all_tz = sorted(available_timezones())
    # Remove duplicates while preserving common-first order
    seen = set()
    ordered = []
    for tz in common:
        if tz in all_tz and tz not in seen:
            ordered.append(("Common", tz))
            seen.add(tz)
    for tz in all_tz:
        if tz not in seen:
            region = tz.split("/")[0] if "/" in tz else "Other"
            ordered.append((region, tz))
            seen.add(tz)
    return ordered

SSL_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "data", "ssl")
CERT_PATH = os.path.join(SSL_DIR, "cert.pem")
KEY_PATH  = os.path.join(SSL_DIR, "key.pem")


def _read_cert_info():
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with open(CERT_PATH, "rb") as f:
            pem = f.read()
        cert = ssl.PEM_cert_to_DER_cert(pem.decode())
        # Use cryptography lib if available
        from cryptography import x509
        from cryptography.hazmat.backends import default_backend
        c = x509.load_der_x509_certificate(cert, default_backend())
        subject = c.subject.rfc4514_string()
        issuer  = c.issuer.rfc4514_string()
        not_before = c.not_valid_before_utc.strftime("%Y-%m-%d")
        not_after  = c.not_valid_after_utc.strftime("%Y-%m-%d")
        days_left  = (c.not_valid_after_utc - datetime.now(timezone.utc)).days
        self_signed = subject == issuer
        return dict(subject=subject, issuer=issuer, not_before=not_before,
                    not_after=not_after, days_left=days_left, self_signed=self_signed)
    except Exception:
        return None

settings_bp = Blueprint("settings", __name__, url_prefix="/settings")


@settings_bp.route("/", methods=["GET", "POST"])
@login_required
@admin_required
def index():
    cfg          = EmailConfig.query.first()    or EmailConfig()
    cloud_cfg    = CloudConfig.query.first()    or CloudConfig()
    atlassian_cfg= AtlassianConfig.query.first()or AtlassianConfig()
    threat_cfg   = ThreatConfig.query.first()   or ThreatConfig()
    time_cfg     = TimeConfig.query.first()     or TimeConfig()
    users        = User.query.order_by(User.created_at.desc()).all()

    if request.method == "POST":
        form = request.form.get("form")

        if form == "time":
            new_tz = request.form.get("timezone", "UTC").strip()
            try:
                ZoneInfo(new_tz)
            except Exception:
                flash("Invalid timezone name.", "danger")
                return redirect(url_for("settings.index") + "#time")

            time_cfg.timezone = new_tz

            ntp_server = request.form.get("ntp_server", "").strip()
            ntp_warn = None
            if ntp_server:
                time_cfg.ntp_server = ntp_server
                current = _read_ntp_server()
                if ntp_server != current:
                    ok, err = _write_ntp_server(ntp_server)
                    if not ok:
                        ntp_warn = err

            time_cfg.updated_at = datetime.now(timezone.utc)
            db.session.add(time_cfg)
            db.session.commit()

            if ntp_warn:
                flash(f"Timezone saved. NTP server could not be applied: {ntp_warn}", "warning")
            else:
                flash("Time & NTP settings saved.", "success")
            return redirect(url_for("settings.index") + "#time")

        if form == "threat":
            from ..models import IOCRecord
            otx_key = request.form.get("otx_api_key", "").strip()
            vt_key  = request.form.get("virustotal_api_key", "").strip()
            ab_key  = request.form.get("abuseipdb_api_key", "").strip()
            gn_key  = request.form.get("greynoise_api_key", "").strip()
            dd_key  = request.form.get("dnsdumpster_api_key", "").strip()
            nvd_key = request.form.get("nvd_api_key", "").strip()
            now = datetime.now(timezone.utc)

            if otx_key:
                threat_cfg.otx_api_key = otx_key
            if vt_key:
                threat_cfg.virustotal_api_key = vt_key
            if ab_key:
                threat_cfg.abuseipdb_api_key = ab_key
            if gn_key:
                threat_cfg.greynoise_api_key = gn_key
            if dd_key:
                threat_cfg.dnsdumpster_api_key = dd_key
            if nvd_key:
                threat_cfg.nvd_api_key = nvd_key
            from ..audit import log_action
            log_action("settings.threat_save", detail="Threat Intel API keys updated")
            threat_cfg.updated_at = now
            db.session.add(threat_cfg)
            db.session.flush()  # make updated keys visible for the check below

            # Expire stale cached IOC records that are missing data for any now-configured
            # service, so the next lookup re-queries instead of returning "No Key" results.
            active_otx = bool(threat_cfg.otx_api_key)
            active_vt  = bool(threat_cfg.virustotal_api_key)
            active_ab  = bool(threat_cfg.abuseipdb_api_key)
            past = datetime(2000, 1, 1, tzinfo=timezone.utc)
            for rec in IOCRecord.query.all():
                if (active_otx and rec.otx_result is None) or \
                   (active_vt  and rec.vt_result  is None) or \
                   (active_ab  and rec.abuseipdb_result is None and rec.ioc_type == "ip"):
                    rec.expires_at = past

            db.session.commit()
            flash("Threat Intelligence API keys saved.", "success")
            return redirect(url_for("settings.index") + "#threat")

        if form == "atlassian":
            atlassian_cfg.enabled = request.form.get("atlassian_enabled") == "on"
            atlassian_cfg.base_url = request.form.get("base_url", "").strip().rstrip("/")
            atlassian_cfg.email = request.form.get("atl_email", "").strip()
            token = request.form.get("api_token", "")
            if token:
                atlassian_cfg.api_token = token
            # Confluence
            atlassian_cfg.confluence_enabled = request.form.get("confluence_enabled") == "on"
            atlassian_cfg.confluence_space_key = request.form.get("confluence_space_key", "").strip().upper()
            atlassian_cfg.confluence_parent_page_id = request.form.get("confluence_parent_page_id", "").strip() or None
            # Jira
            atlassian_cfg.jira_enabled = request.form.get("jira_enabled") == "on"
            atlassian_cfg.jira_project_key = request.form.get("jira_project_key", "").strip().upper()
            atlassian_cfg.jira_issue_type = request.form.get("jira_issue_type", "Bug").strip()
            atlassian_cfg.jira_severity_threshold = request.form.get("jira_severity_threshold", "medium")
            atlassian_cfg.updated_at = datetime.now(timezone.utc)
            db.session.add(atlassian_cfg)
            db.session.commit()
            flash("Atlassian settings saved.", "success")
            return redirect(url_for("settings.index") + "#atlassian")

        if form == "email":
            cfg.smtp_server = request.form.get("smtp_server", "").strip()
            cfg.smtp_port = int(request.form.get("smtp_port", 587))
            cfg.use_tls = request.form.get("use_tls") == "on"
            cfg.username = request.form.get("username", "").strip()
            cfg.sender = request.form.get("sender", "").strip()
            password = request.form.get("password", "")
            if password:
                cfg.password = password
            cfg.updated_at = datetime.now(timezone.utc)
            db.session.add(cfg)
            db.session.commit()
            flash("Email settings saved.", "success")
            return redirect(url_for("settings.index"))

        if form == "cloud":
            cloud_cfg.enabled = request.form.get("cloud_enabled") == "on"
            cloud_cfg.endpoint_url = request.form.get("endpoint_url", "").strip()
            cloud_cfg.auth_type = request.form.get("auth_type", "bearer")
            cloud_cfg.auth_header = request.form.get("auth_header", "X-API-Key").strip()
            token = request.form.get("auth_token", "")
            if token:
                cloud_cfg.auth_token = token
            cloud_cfg.send_file = request.form.get("send_file") == "on"
            cloud_cfg.file_format = request.form.get("file_format", "pdf")
            cloud_cfg.updated_at = datetime.now(timezone.utc)
            db.session.add(cloud_cfg)
            db.session.commit()
            flash("Cloud API settings saved.", "success")
            return redirect(url_for("settings.index") + "#cloud")

    return render_template(
        "settings/index.html",
        cfg=cfg, cloud_cfg=cloud_cfg, atlassian_cfg=atlassian_cfg,
        threat_cfg=threat_cfg, time_cfg=time_cfg, users=users,
        cert_info=_read_cert_info(),
        ntp_status=_ntp_status(),
        ntp_server_current=_read_ntp_server(),
        tz_list=_tz_list(),
    )


@settings_bp.route("/test-email", methods=["POST"])
@login_required
@admin_required
def test_email():
    cfg = EmailConfig.query.first()
    if not cfg or not cfg.smtp_server:
        flash("Configure email settings first.", "warning")
        return redirect(url_for("settings.index"))

    recipient = request.form.get("test_recipient", "").strip()
    if not recipient:
        flash("Enter a recipient email.", "warning")
        return redirect(url_for("settings.index"))

    try:
        import smtplib
        from email.mime.text import MIMEText
        msg = MIMEText("This is a test email from your PwnBroker.")
        msg["Subject"] = "PwnBroker — Test Email"
        msg["From"] = cfg.sender
        msg["To"] = recipient
        with smtplib.SMTP(cfg.smtp_server, cfg.smtp_port) as server:
            if cfg.use_tls:
                server.starttls()
            if cfg.username:
                server.login(cfg.username, cfg.password)
            server.sendmail(cfg.sender, [recipient], msg.as_string())
        flash(f"Test email sent to {recipient}.", "success")
    except Exception as e:
        flash(f"Email failed: {e}", "danger")

    return redirect(url_for("settings.index"))


@settings_bp.route("/test-keys", methods=["POST"])
@login_required
@admin_required
def test_keys():
    """Test each threat intel API key and return {service: {status, detail}}.

    Accepts an optional JSON body containing key values typed into the form but
    not yet saved.  Values from the body take precedence over the DB so users
    can test a key before committing it.
    """
    import requests as _req

    cfg = ThreatConfig.query.first() or ThreatConfig()

    # Key values submitted from the form (optional — empty string = not provided)
    body = request.get_json(silent=True) or {}

    def _key(field: str) -> str | None:
        """Return the form-submitted value if non-empty, else fall back to DB."""
        v = body.get(field, "").strip()
        return v if v else getattr(cfg, field, None)

    results = {}

    def _get(url, headers=None, params=None, timeout=8):
        try:
            r = _req.get(url, headers=headers or {}, params=params or {},
                         timeout=timeout, allow_redirects=True)
            return r.status_code, r
        except Exception as e:
            return None, str(e)

    # ── OTX ──────────────────────────────────────────────────────────────────
    otx_key = _key("otx_api_key")
    if otx_key:
        code, resp = _get("https://otx.alienvault.com/api/v1/user/me",
                          headers={"X-OTX-API-KEY": otx_key})
        if code == 200:
            results["otx"] = {"status": "ok", "detail": "Valid"}
        elif code in (401, 403):
            results["otx"] = {"status": "error", "detail": "Invalid key"}
        elif code is None:
            results["otx"] = {"status": "error", "detail": f"Network error: {resp}"}
        else:
            results["otx"] = {"status": "error", "detail": f"HTTP {code}"}
    else:
        results["otx"] = {"status": "not_set", "detail": "Not configured"}

    # ── VirusTotal ───────────────────────────────────────────────────────────
    vt_key = _key("virustotal_api_key")
    if vt_key:
        code, resp = _get("https://www.virustotal.com/api/v3/domains/virustotal.com",
                          headers={"x-apikey": vt_key})
        if code == 200:
            results["virustotal"] = {"status": "ok", "detail": "Valid"}
        elif code in (401, 403):
            results["virustotal"] = {"status": "error", "detail": "Invalid key"}
        elif code == 429:
            results["virustotal"] = {"status": "ok", "detail": "Rate limited (key accepted)"}
        elif code is None:
            results["virustotal"] = {"status": "error", "detail": f"Network error: {resp}"}
        else:
            results["virustotal"] = {"status": "error", "detail": f"HTTP {code}"}
    else:
        results["virustotal"] = {"status": "not_set", "detail": "Not configured — save key first"}

    # ── AbuseIPDB ─────────────────────────────────────────────────────────────
    ab_key = _key("abuseipdb_api_key")
    if ab_key:
        code, resp = _get("https://api.abuseipdb.com/api/v2/check",
                          headers={"Key": ab_key, "Accept": "application/json"},
                          params={"ipAddress": "8.8.8.8", "maxAgeInDays": "90"})
        if code == 200:
            results["abuseipdb"] = {"status": "ok", "detail": "Valid"}
        elif code in (401, 422):
            results["abuseipdb"] = {"status": "error", "detail": "Invalid key"}
        elif code is None:
            results["abuseipdb"] = {"status": "error", "detail": f"Network error: {resp}"}
        else:
            results["abuseipdb"] = {"status": "error", "detail": f"HTTP {code}"}
    else:
        results["abuseipdb"] = {"status": "not_set", "detail": "Not configured"}

    # ── GreyNoise ─────────────────────────────────────────────────────────────
    gn_key = _key("greynoise_api_key")
    if gn_key:
        code, resp = _get("https://api.greynoise.io/ping",
                          headers={"key": gn_key})
        if code == 200:
            results["greynoise"] = {"status": "ok", "detail": "Valid"}
        elif code in (401, 403):
            results["greynoise"] = {"status": "error", "detail": "Invalid key"}
        elif code is None:
            results["greynoise"] = {"status": "error", "detail": f"Network error: {resp}"}
        else:
            results["greynoise"] = {"status": "error", "detail": f"HTTP {code}"}
    else:
        results["greynoise"] = {"status": "not_set", "detail": "Not configured"}

    # ── DNSDumpster ──────────────────────────────────────────────────────────
    dd_key = _key("dnsdumpster_api_key")
    if dd_key:
        code, resp = _get("https://api.dnsdumpster.com/domain/example.com",
                          headers={"X-API-Key": dd_key})
        if code in (200, 400, 404, 429):
            results["dnsdumpster"] = {"status": "ok", "detail": "Valid"}
        elif code in (401, 403):
            results["dnsdumpster"] = {"status": "error", "detail": "Invalid key"}
        elif code is None:
            results["dnsdumpster"] = {"status": "error", "detail": f"Network error: {resp}"}
        else:
            results["dnsdumpster"] = {"status": "error", "detail": f"HTTP {code}"}
    else:
        results["dnsdumpster"] = {"status": "not_set", "detail": "Not configured"}

    # ── NVD ───────────────────────────────────────────────────────────────────
    nvd_key = _key("nvd_api_key")
    if nvd_key:
        code, resp = _get("https://services.nvd.nist.gov/rest/json/cves/2.0",
                          headers={"apiKey": nvd_key},
                          params={"resultsPerPage": 1})
        if code == 200:
            results["nvd"] = {"status": "ok", "detail": "Valid"}
        elif code in (401, 403):
            results["nvd"] = {"status": "error", "detail": "Invalid key"}
        elif code == 429:
            results["nvd"] = {"status": "ok", "detail": "Rate limited (key accepted)"}
        elif code is None:
            results["nvd"] = {"status": "error", "detail": f"Network error: {resp}"}
        else:
            results["nvd"] = {"status": "error", "detail": f"HTTP {code}"}
    else:
        results["nvd"] = {"status": "not_set", "detail": "Not configured"}

    return results


@settings_bp.route("/users/add", methods=["POST"])
@login_required
@admin_required
def user_add():
    username = request.form.get("username", "").strip()
    email = request.form.get("email", "").strip()
    password = request.form.get("password", "")
    role = request.form.get("role", "user")

    if not username or not email or not password:
        flash("All fields are required to add a user.", "danger")
        return redirect(url_for("settings.index"))

    if role not in ("admin", "user"):
        role = "user"

    if User.query.filter((User.username == username) | (User.email == email)).first():
        flash("Username or email already exists.", "danger")
        return redirect(url_for("settings.index"))

    u = User(username=username, email=email, role=role)
    u.set_password(password)
    db.session.add(u)
    db.session.commit()
    flash(f"User '{username}' created with {role} role.", "success")
    return redirect(url_for("settings.index"))


@settings_bp.route("/users/<int:user_id>/role", methods=["POST"])
@login_required
@admin_required
def user_role(user_id):
    u = User.query.get_or_404(user_id)
    if u.id == current_user.id:
        flash("Cannot change your own role.", "warning")
        return redirect(url_for("settings.index"))
    new_role = request.form.get("role", "user")
    if new_role not in ("admin", "user"):
        new_role = "user"
    u.role = new_role
    db.session.commit()
    flash(f"'{u.username}' role updated to {new_role}.", "success")
    return redirect(url_for("settings.index"))


@settings_bp.route("/users/<int:user_id>/toggle", methods=["POST"])
@login_required
@admin_required
def user_toggle(user_id):
    u = User.query.get_or_404(user_id)
    if u.id == current_user.id:
        flash("Cannot deactivate your own account.", "warning")
        return redirect(url_for("settings.index"))
    u.active = not u.active
    db.session.commit()
    flash(f"'{u.username}' {'activated' if u.active else 'deactivated'}.", "success")
    return redirect(url_for("settings.index"))


@settings_bp.route("/cert/upload", methods=["POST"])
@login_required
@admin_required
def upload_cert():
    cert_file = request.files.get("cert_file")
    key_file  = request.files.get("key_file")

    if not cert_file or not key_file or not cert_file.filename or not key_file.filename:
        flash("Both certificate and private key files are required.", "danger")
        return redirect(url_for("settings.index") + "#tls")

    cert_data = cert_file.read()
    key_data  = key_file.read()

    # Validate the pair loads correctly
    import tempfile
    cf_path = kf_path = None
    try:
        with tempfile.NamedTemporaryFile(suffix=".pem", delete=False) as cf:
            cf.write(cert_data)
            cf_path = cf.name
        with tempfile.NamedTemporaryFile(suffix=".pem", delete=False) as kf:
            kf.write(key_data)
            kf_path = kf.name
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cf_path, kf_path)
    except ssl.SSLError as e:
        flash(f"Certificate/key validation failed: {e}", "danger")
        return redirect(url_for("settings.index") + "#tls")
    finally:
        for _p in (cf_path, kf_path):
            if _p:
                try:
                    os.unlink(_p)
                except OSError:
                    pass

    os.makedirs(SSL_DIR, exist_ok=True)
    # Back up existing
    for path, name in [(CERT_PATH, "cert.pem"), (KEY_PATH, "key.pem")]:
        if os.path.exists(path):
            os.rename(path, path + ".bak")
    with open(CERT_PATH, "wb") as f:
        f.write(cert_data)
    with open(KEY_PATH, "wb") as f:
        f.write(key_data)
    os.chmod(KEY_PATH, 0o600)

    flash("Certificate uploaded successfully. Restart PwnBroker to activate it.", "success")
    return redirect(url_for("settings.index") + "#tls")


@settings_bp.route("/users/<int:user_id>/delete", methods=["POST"])
@login_required
@admin_required
def user_delete(user_id):
    u = User.query.get_or_404(user_id)
    if u.id == current_user.id:
        flash("Cannot delete your own account.", "warning")
        return redirect(url_for("settings.index"))
    db.session.delete(u)
    db.session.commit()
    flash("User deleted.", "success")
    return redirect(url_for("settings.index"))
