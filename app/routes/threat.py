import json
import secrets
import ipaddress
import os
from datetime import datetime, timezone, timedelta
from flask import (Blueprint, render_template, redirect, url_for, flash,
                   request, jsonify, Response)
from flask_login import login_required, current_user
from ..models import (ThreatConfig, EndpointAgent, AgentAlert, IOCRecord, SocCase,
                      PaloAltoFirewall, PaloAltoThreatLog)
from ..extensions import db
from .decorators import admin_required

threat_bp = Blueprint("threat", __name__, url_prefix="/threat")

_AGENT_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "static", "agent")


# ── helpers ──────────────────────────────────────────────────────────────────

def _get_cfg():
    cfg = ThreatConfig.query.first()
    if not cfg:
        cfg = ThreatConfig(registration_token=secrets.token_urlsafe(16))
        db.session.add(cfg)
        db.session.commit()
    elif not cfg.registration_token:
        cfg.registration_token = secrets.token_urlsafe(16)
        db.session.commit()
    return cfg


def _download_authorized(cfg):
    """Allow an authenticated browser session, or the pre-shared registration
    token as a query param — needed for non-interactive fetches (curl,
    Invoke-WebRequest) used by the documented headless install commands."""
    if current_user.is_authenticated:
        return True
    token = request.args.get("token", "")
    return bool(cfg.registration_token) and token == cfg.registration_token


def _is_private(ip):
    try:
        return ipaddress.ip_address(ip).is_private
    except Exception:
        return True


def _agent_auth():
    agent_id = request.headers.get("X-Agent-ID", "")
    token    = request.headers.get("X-Agent-Token", "")
    if not agent_id or not token:
        return None, (jsonify({"error": "Missing auth headers"}), 401)
    agent = EndpointAgent.query.filter_by(agent_id=agent_id).first()
    if not agent or agent.token != token:
        return None, (jsonify({"error": "Invalid credentials"}), 403)
    return agent, None


def _mark_offline_agents():
    now = datetime.now(timezone.utc)
    for a in EndpointAgent.query.filter_by(status="online").all():
        if a.last_seen:
            ls = a.last_seen if a.last_seen.tzinfo else a.last_seen.replace(tzinfo=timezone.utc)
            if (now - ls).total_seconds() > 300:
                a.status = "offline"
    db.session.commit()


# ── UI routes ─────────────────────────────────────────────────────────────────

@threat_bp.route("/")
@login_required
def index():
    _mark_offline_agents()
    total_lookups   = IOCRecord.query.count()
    malicious_count = IOCRecord.query.filter_by(verdict="malicious").count()
    suspicious_count= IOCRecord.query.filter_by(verdict="suspicious").count()
    agents_online   = EndpointAgent.query.filter_by(status="online").count()
    agents_total    = EndpointAgent.query.count()
    unacked         = AgentAlert.query.filter_by(acknowledged=False).count()
    recent_lookups  = IOCRecord.query.order_by(IOCRecord.created_at.desc()).limit(10).all()
    recent_alerts   = AgentAlert.query.order_by(AgentAlert.created_at.desc()).limit(10).all()

    paloalto_total      = PaloAltoFirewall.query.count()
    paloalto_ok         = PaloAltoFirewall.query.filter_by(status="ok").count()
    paloalto_error      = PaloAltoFirewall.query.filter_by(status="error").count()
    today_start         = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
    paloalto_logs_today = PaloAltoThreatLog.query.filter(PaloAltoThreatLog.created_at >= today_start).count()
    paloalto_critical   = PaloAltoThreatLog.query.filter(
        PaloAltoThreatLog.created_at >= today_start,
        PaloAltoThreatLog.severity.in_(["critical", "high"]),
    ).count()
    recent_paloalto = (PaloAltoThreatLog.query
                       .order_by(PaloAltoThreatLog.time_generated.desc())
                       .limit(10).all())

    return render_template("threat/index.html",
                           total_lookups=total_lookups,
                           malicious_count=malicious_count,
                           suspicious_count=suspicious_count,
                           agents_online=agents_online,
                           agents_total=agents_total,
                           unacked=unacked,
                           recent_lookups=recent_lookups,
                           recent_alerts=recent_alerts,
                           paloalto_total=paloalto_total,
                           paloalto_ok=paloalto_ok,
                           paloalto_error=paloalto_error,
                           paloalto_logs_today=paloalto_logs_today,
                           paloalto_critical=paloalto_critical,
                           recent_paloalto=recent_paloalto)


@threat_bp.route("/lookup", methods=["GET", "POST"])
@login_required
def lookup():
    result    = None
    error     = None
    indicator = ""

    if request.method == "POST":
        indicator = request.form.get("indicator", "").strip()
        if indicator:
            cfg   = _get_cfg()
            force = request.form.get("force") == "1"
            from ..threat.ioc_lookup import lookup as do_lookup
            result = do_lookup(indicator, cfg, user_id=current_user.id, force=force)
            if result.get("error"):
                error  = result["error"]
                result = None

    history = IOCRecord.query.order_by(IOCRecord.created_at.desc()).limit(30).all()
    return render_template("threat/lookup.html",
                           result=result, indicator=indicator,
                           history=history, error=error)


@threat_bp.route("/feed")
@login_required
def feed():
    cfg    = _get_cfg()
    pulses = []
    error  = None
    if cfg.otx_api_key:
        from ..threat.otx import get_pulses
        try:
            pulses = get_pulses(cfg.otx_api_key)
        except Exception as e:
            error = str(e)
    else:
        error = "OTX API key not configured — add it in Settings → Threat Intelligence."
    return render_template("threat/feed.html", pulses=pulses, error=error)


@threat_bp.route("/agents")
@login_required
def agents_list():
    _mark_offline_agents()
    agents = EndpointAgent.query.order_by(EndpointAgent.last_seen.desc()).all()
    return render_template("threat/agents.html", agents=agents)


@threat_bp.route("/agents/<int:agent_db_id>")
@login_required
def agent_detail(agent_db_id):
    agent  = EndpointAgent.query.get_or_404(agent_db_id)
    alerts = agent.alerts.order_by(AgentAlert.created_at.desc()).limit(100).all()
    return render_template("threat/agent_detail.html", agent=agent, alerts=alerts)


@threat_bp.route("/agents/<int:agent_db_id>/delete", methods=["POST"])
@login_required
@admin_required
def agent_delete(agent_db_id):
    agent = EndpointAgent.query.get_or_404(agent_db_id)
    db.session.delete(agent)
    db.session.commit()
    flash("Agent removed.", "success")
    return redirect(url_for("threat.agents_list"))


@threat_bp.route("/agents/<int:agent_db_id>/alerts/<int:alert_id>/ack", methods=["POST"])
@login_required
def alert_ack(agent_db_id, alert_id):
    alert = AgentAlert.query.filter_by(id=alert_id, agent_db_id=agent_db_id).first_or_404()
    alert.acknowledged = True
    db.session.commit()
    return jsonify({"ok": True})


@threat_bp.route("/ioc/<int:ioc_id>/delete", methods=["POST"])
@login_required
@admin_required
def ioc_delete(ioc_id):
    rec = IOCRecord.query.get_or_404(ioc_id)
    db.session.delete(rec)
    db.session.commit()
    flash("IOC record deleted.", "success")
    return redirect(url_for("threat.lookup"))


@threat_bp.route("/triage", methods=["GET", "POST"])
@login_required
def triage():
    pending   = SocCase.query.filter_by(status="pending").order_by(SocCase.created_at.desc()).all()
    alerted   = SocCase.query.filter_by(status="alerted").order_by(SocCase.reviewed_at.desc()).limit(20).all()
    dismissed = SocCase.query.filter_by(status="dismissed").order_by(SocCase.reviewed_at.desc()).limit(10).all()

    result = None
    error  = None
    ip     = ""

    if request.method == "POST" and "ip" in request.form:
        ip = request.form.get("ip", "").strip()
        if ip:
            try:
                ipaddress.ip_address(ip)
            except ValueError:
                error = f"'{ip}' is not a valid IP address. SOC triage requires an IP."
                ip = ""

        if ip and not error:
            cfg = _get_cfg()
            from ..threat.triage import run as triage_run
            result = triage_run(ip, cfg=cfg, vt_key=cfg.virustotal_api_key or None)

    return render_template("threat/triage.html",
                           pending=pending, alerted=alerted, dismissed=dismissed,
                           result=result, ip=ip, error=error)


@threat_bp.route("/triage/<int:case_id>/alert", methods=["POST"])
@login_required
@admin_required
def triage_alert(case_id):
    case = SocCase.query.get_or_404(case_id)
    notes = request.form.get("notes", "").strip()
    if notes:
        case.analyst_notes = notes
    case.status      = "alerted"
    case.reviewed_at = datetime.now(timezone.utc)
    case.reviewed_by = current_user.id
    db.session.commit()
    flash(f"Alert raised for {case.ioc} — confirmed by {case.source_count} source(s).", "danger")
    return redirect(url_for("threat.triage"))


@threat_bp.route("/triage/<int:case_id>/dismiss", methods=["POST"])
@login_required
@admin_required
def triage_dismiss(case_id):
    case = SocCase.query.get_or_404(case_id)
    notes = request.form.get("notes", "").strip()
    if notes:
        case.analyst_notes = notes
    case.status      = "dismissed"
    case.reviewed_at = datetime.now(timezone.utc)
    case.reviewed_by = current_user.id
    db.session.commit()
    flash(f"Case for {case.ioc} dismissed.", "info")
    return redirect(url_for("threat.triage"))


@threat_bp.route("/subdomains", methods=["GET", "POST"])
@login_required
def subdomains():
    result = None
    error  = None
    domain = ""

    if request.method == "POST":
        domain = request.form.get("domain", "").strip().lower()
        if domain:
            cfg = _get_cfg()
            from ..threat.subdomain import enumerate as sub_enum
            result = sub_enum(domain, dnsdumpster_key=cfg.dnsdumpster_api_key or None)
            if result["errors"] and not result["subdomains"]:
                error  = "; ".join(result["errors"])
                result = None

    return render_template("threat/subdomains.html",
                           result=result, domain=domain, error=error)


@threat_bp.route("/download")
@login_required
def download():
    cfg        = _get_cfg()
    server_url = request.url_root.rstrip("/")
    return render_template("threat/download.html", cfg=cfg, server_url=server_url)


@threat_bp.route("/download/agent")
def download_agent():
    cfg        = _get_cfg()
    if not _download_authorized(cfg):
        return Response("Unauthorized — log in or supply ?token=<registration token>.",
                        status=401, mimetype="text/plain")
    server_url = request.url_root.rstrip("/")
    path       = os.path.join(_AGENT_DIR, "pwnbroker_agent.py")
    with open(path) as f:
        content = f.read()
    content = content.replace("__PWNBROKER_SERVER__", server_url)
    content = content.replace("__REG_TOKEN__", cfg.registration_token or "")
    return Response(content, mimetype="text/x-python",
                    headers={"Content-Disposition": "attachment; filename=pwnbroker_agent.py"})


@threat_bp.route("/download/script/<platform>")
def download_script(platform):
    script_map = {
        "linux":   ("install_linux.sh",      "text/x-shellscript"),
        "mac":     ("install_mac.sh",        "text/x-shellscript"),
        "windows": ("install_windows.ps1",   "application/x-powershell"),
    }
    if platform not in script_map:
        return "Not found", 404
    filename, mime = script_map[platform]
    cfg        = _get_cfg()
    if not _download_authorized(cfg):
        return Response("Unauthorized — log in or supply ?token=<registration token>.",
                        status=401, mimetype="text/plain")
    server_url = request.url_root.rstrip("/")

    # Build substituted agent script to embed inline
    agent_path = os.path.join(_AGENT_DIR, "pwnbroker_agent.py")
    with open(agent_path) as f:
        agent_content = f.read()
    agent_content = agent_content.replace("__PWNBROKER_SERVER__", server_url)
    agent_content = agent_content.replace("__REG_TOKEN__", cfg.registration_token or "")

    path = os.path.join(_AGENT_DIR, filename)
    with open(path) as f:
        content = f.read()
    content = content.replace("__PWNBROKER_SERVER__", server_url)
    content = content.replace("__REG_TOKEN__", cfg.registration_token or "")
    content = content.replace("__AGENT_CONTENT__", agent_content)
    return Response(content, mimetype=mime,
                    headers={"Content-Disposition": f"attachment; filename={filename}"})


# ── Agent REST API (token-based, no session) ──────────────────────────────────

@threat_bp.route("/api/register", methods=["POST"])
def api_register():
    cfg  = _get_cfg()
    data = request.get_json(silent=True) or {}

    if cfg.registration_token and data.get("reg_token") != cfg.registration_token:
        return jsonify({"error": "Invalid registration token"}), 403

    agent_id = secrets.token_urlsafe(16)
    token    = secrets.token_urlsafe(32)
    now      = datetime.now(timezone.utc)

    agent = EndpointAgent(
        agent_id     = agent_id,
        token        = token,
        hostname     = (data.get("hostname") or "unknown")[:255],
        os_type      = (data.get("os")       or "unknown")[:50],
        os_version   = str(data.get("os_version") or "")[:512],
        ip_address   = (data.get("ip_address") or request.remote_addr or "")[:45],
        status       = "online",
        registered_at= now,
        last_seen    = now,
    )
    db.session.add(agent)
    db.session.commit()
    return jsonify({"agent_id": agent_id, "token": token})


@threat_bp.route("/api/heartbeat", methods=["POST"])
def api_heartbeat():
    agent, err = _agent_auth()
    if err:
        return err

    data = request.get_json(silent=True) or {}
    now  = datetime.now(timezone.utc)

    agent.last_seen  = now
    agent.status     = "online"
    agent.ip_address = (data.get("ip_address") or agent.ip_address or "")[:45]

    # Check new external IPs against AbuseIPDB
    cfg         = _get_cfg()
    new_count   = 0
    if cfg.abuseipdb_api_key:
        from ..threat.abuseipdb import check_ip as _abusecheck
        checked = set()
        for conn in (data.get("connections") or [])[:25]:
            ip = conn.get("remote_ip", "")
            if not ip or ip in checked or _is_private(ip):
                continue
            checked.add(ip)

            cached = IOCRecord.query.filter_by(indicator=ip, ioc_type="ip").first()
            if cached and cached.expires_at:
                exp = cached.expires_at if cached.expires_at.tzinfo else cached.expires_at.replace(tzinfo=timezone.utc)
                if exp > now:
                    if cached.verdict in ("malicious", "suspicious") and _secondary_confirmed(cached):
                        _ensure_alert(agent, ip, cached)
                    continue

            result = _abusecheck(ip, cfg.abuseipdb_api_key)
            if result and "error" not in result:
                rec = cached or IOCRecord()
                rec.indicator        = ip
                rec.ioc_type         = "ip"
                rec.threat_score     = result.get("threat_score", 0)
                rec.verdict          = result.get("verdict", "clean")
                rec.abuseipdb_result = json.dumps(result)
                rec.created_at       = now
                rec.expires_at       = now + timedelta(hours=24)

                if result.get("verdict") != "clean":
                    vt_ok = otx_ok = False
                    if cfg.virustotal_api_key:
                        from ..threat.virustotal import lookup as _vt_lookup
                        vt_res = _vt_lookup(ip, "ip", cfg.virustotal_api_key)
                        if "error" not in vt_res:
                            rec.vt_result = json.dumps(vt_res)
                            vt_ok = vt_res.get("verdict") in ("malicious", "suspicious")
                    if cfg.otx_api_key:
                        from ..threat.otx import lookup as _otx_lookup
                        otx_res = _otx_lookup(ip, "ip", cfg.otx_api_key)
                        if "error" not in otx_res:
                            rec.otx_result = json.dumps(otx_res)
                            otx_ok = otx_res.get("verdict") in ("malicious", "suspicious")

                    db.session.add(rec)
                    if vt_ok or otx_ok:
                        created = _ensure_alert(agent, ip, rec)
                        if created:
                            new_count += 1
                else:
                    db.session.add(rec)

    db.session.commit()

    pending = [
        {"id": a.id, "title": a.title, "severity": a.severity, "ioc": a.ioc}
        for a in agent.alerts.filter_by(acknowledged=False)
                              .order_by(AgentAlert.created_at.desc())
                              .limit(10).all()
    ]
    return jsonify({"status": "ok", "alerts": pending, "new_alerts": new_count})


def _secondary_confirmed(ioc_record):
    """True if a stored VT or OTX result confirms the IP is non-clean."""
    for field in (ioc_record.vt_result, ioc_record.otx_result):
        if field:
            try:
                if json.loads(field).get("verdict") in ("malicious", "suspicious"):
                    return True
            except Exception:
                pass
    return False



# ── Palo Alto (PAN-OS) threat log ingestion ────────────────────────────────

@threat_bp.route("/paloalto")
@login_required
def paloalto_list():
    firewalls   = PaloAltoFirewall.query.order_by(PaloAltoFirewall.name).all()
    error_count = sum(1 for fw in firewalls if fw.status == "error")
    today_start = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
    logs_today  = PaloAltoThreatLog.query.filter(PaloAltoThreatLog.created_at >= today_start).count()
    return render_template("threat/paloalto.html", firewalls=firewalls,
                           error_count=error_count, logs_today=logs_today)


@threat_bp.route("/paloalto/add", methods=["POST"])
@login_required
@admin_required
def paloalto_add():
    name       = request.form.get("name", "").strip()
    hostname   = request.form.get("hostname", "").strip()
    verify_ssl = request.form.get("verify_ssl") == "1"
    api_key    = request.form.get("api_key", "").strip()
    username   = request.form.get("username", "").strip()
    password   = request.form.get("password", "").strip()

    if not name or not hostname:
        flash("Name and hostname are required.", "danger")
        return redirect(url_for("threat.paloalto_list"))

    if not api_key:
        if username and password:
            from ..threat.paloalto import generate_api_key
            result = generate_api_key(hostname, username, password, verify_ssl=verify_ssl)
            if "error" in result:
                flash(f"Could not generate API key: {result['error']}", "danger")
                return redirect(url_for("threat.paloalto_list"))
            api_key = result["api_key"]
        else:
            flash("Provide either an API key or a username/password.", "danger")
            return redirect(url_for("threat.paloalto_list"))

    fw = PaloAltoFirewall(name=name, hostname=hostname, verify_ssl=verify_ssl,
                          api_key=api_key, username=username or None,
                          created_by=current_user.id)
    db.session.add(fw)
    db.session.commit()
    flash(f"Firewall '{name}' added.", "success")
    return redirect(url_for("threat.paloalto_list"))


@threat_bp.route("/paloalto/<int:fw_id>")
@login_required
def paloalto_detail(fw_id):
    fw       = PaloAltoFirewall.query.get_or_404(fw_id)
    severity = request.args.get("severity", "")
    category = request.args.get("category", "")
    page     = request.args.get("page", 1, type=int)
    per_page = 50

    query = PaloAltoThreatLog.query.filter_by(firewall_id=fw.id)
    if severity:
        query = query.filter_by(severity=severity)
    if category:
        query = query.filter_by(category=category)

    total = query.count()
    logs  = (query.order_by(PaloAltoThreatLog.time_generated.desc())
                  .offset((page - 1) * per_page).limit(per_page).all())
    total_pages = max(1, (total + per_page - 1) // per_page)

    categories = [c[0] for c in db.session.query(PaloAltoThreatLog.category)
                          .filter_by(firewall_id=fw.id).distinct().all() if c[0]]

    return render_template("threat/paloalto_detail.html", fw=fw, logs=logs,
                           severity=severity, category=category, categories=categories,
                           page=page, total_pages=total_pages, total=total)


@threat_bp.route("/paloalto/<int:fw_id>/edit", methods=["POST"])
@login_required
@admin_required
def paloalto_edit(fw_id):
    fw = PaloAltoFirewall.query.get_or_404(fw_id)
    fw.name       = request.form.get("name", fw.name).strip() or fw.name
    fw.hostname   = request.form.get("hostname", fw.hostname).strip() or fw.hostname
    fw.verify_ssl = request.form.get("verify_ssl") == "1"
    fw.enabled    = request.form.get("enabled") == "1"

    api_key = request.form.get("api_key", "").strip()
    if api_key:
        fw.api_key = api_key

    username = request.form.get("username", "").strip()
    password = request.form.get("password", "").strip()
    if username and password:
        from ..threat.paloalto import generate_api_key
        result = generate_api_key(fw.hostname, username, password, verify_ssl=fw.verify_ssl)
        if "error" in result:
            flash(f"Could not regenerate API key: {result['error']}", "danger")
            return redirect(url_for("threat.paloalto_detail", fw_id=fw.id))
        fw.api_key  = result["api_key"]
        fw.username = username

    db.session.commit()
    flash(f"Firewall '{fw.name}' updated.", "success")
    return redirect(url_for("threat.paloalto_detail", fw_id=fw.id))


@threat_bp.route("/paloalto/<int:fw_id>/delete", methods=["POST"])
@login_required
@admin_required
def paloalto_delete(fw_id):
    fw   = PaloAltoFirewall.query.get_or_404(fw_id)
    name = fw.name
    db.session.delete(fw)
    db.session.commit()
    flash(f"Firewall '{name}' removed.", "success")
    return redirect(url_for("threat.paloalto_list"))


@threat_bp.route("/paloalto/<int:fw_id>/test", methods=["POST"])
@login_required
@admin_required
def paloalto_test(fw_id):
    fw = PaloAltoFirewall.query.get_or_404(fw_id)
    if not fw.api_key:
        flash("No API key configured for this firewall yet.", "danger")
        return redirect(url_for("threat.paloalto_detail", fw_id=fw.id))

    from ..threat.paloalto import test_connection
    result = test_connection(fw.hostname, fw.api_key, verify_ssl=fw.verify_ssl)
    if "error" in result:
        fw.status     = "error"
        fw.last_error = result["error"][:2000]
        db.session.commit()
        flash(f"Connection test failed: {result['error']}", "danger")
    else:
        fw.status     = "ok"
        fw.last_error = None
        db.session.commit()
        flash(f"Connected — {result.get('hostname') or fw.hostname} "
              f"(PAN-OS {result.get('sw_version', 'unknown')})", "success")
    return redirect(url_for("threat.paloalto_detail", fw_id=fw.id))


@threat_bp.route("/paloalto/<int:fw_id>/poll", methods=["POST"])
@login_required
@admin_required
def paloalto_poll(fw_id):
    fw = PaloAltoFirewall.query.get_or_404(fw_id)
    if not fw.api_key:
        flash("No API key configured for this firewall yet.", "danger")
        return redirect(url_for("threat.paloalto_detail", fw_id=fw.id))

    from ..scheduler.jobs import poll_paloalto_firewall
    result = poll_paloalto_firewall(fw)
    if "error" in result:
        flash(f"Poll failed: {result['error']}", "danger")
    else:
        flash(f"Poll complete — {result.get('count', 0)} log entr{'y' if result.get('count') == 1 else 'ies'} fetched.", "success")
    return redirect(url_for("threat.paloalto_detail", fw_id=fw.id))


def _ensure_alert(agent, ip, ioc_record):
    """Create alert for ip on agent if one doesn't exist yet. Returns True if created."""
    if AgentAlert.query.filter_by(agent_db_id=agent.id, ioc=ip).first():
        return False

    confidence = 0
    isp        = "Unknown ISP"
    reports    = 0
    if ioc_record.abuseipdb_result:
        abuse      = json.loads(ioc_record.abuseipdb_result)
        confidence = abuse.get("confidence_score", 0)
        isp        = abuse.get("isp", isp)
        reports    = abuse.get("total_reports", 0)

    severity = "high" if confidence >= 50 else "medium"
    alert = AgentAlert(
        agent_db_id  = agent.id,
        alert_type   = "suspicious_connection",
        severity     = severity,
        title        = f"Suspicious outbound connection to {ip}",
        detail       = (f"AbuseIPDB confidence: {confidence}%, "
                        f"{reports} report(s). ISP: {isp}. "
                        f"Overall threat score: {ioc_record.threat_score}/100."),
        ioc          = ip,
        created_at   = datetime.now(timezone.utc),
    )
    db.session.add(alert)
    return True
