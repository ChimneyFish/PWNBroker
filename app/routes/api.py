from flask import Blueprint, jsonify
from flask_login import login_required
from ..models import (Scan, ScanResult, Target, Asset, EndpointAgent, SocCase, TimeConfig,
                      PaloAltoFirewall, PaloAltoThreatLog)
from ..extensions import db
import sqlalchemy as sa
from datetime import datetime, timezone, timedelta
from zoneinfo import ZoneInfo


def _app_tz():
    cfg = TimeConfig.query.first()
    name = (cfg.timezone if cfg else None) or "UTC"
    try:
        return ZoneInfo(name)
    except Exception:
        return ZoneInfo("UTC")


def _fmt(dt, fmt="%b %d %H:%M"):
    if dt is None:
        return "—"
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(_app_tz()).strftime(fmt)

api_bp = Blueprint("api", __name__, url_prefix="/api")


@api_bp.route("/scans/<int:scan_id>/status")
@login_required
def scan_status(scan_id):
    scan = Scan.query.get_or_404(scan_id)
    return jsonify({
        "id": scan.id,
        "status": scan.status,
        "vuln_count": scan.vuln_count,
        "critical_count": scan.critical_count,
        "duration": scan.duration,
    })


@api_bp.route("/dashboard/stats")
@login_required
def dashboard_stats():
    return jsonify({
        "total_scans": Scan.query.count(),
        "running_scans": Scan.query.filter_by(status="running").count(),
        "total_targets": Target.query.count(),
        "total_vulns": ScanResult.query.filter_by(result_type="vulnerability").count(),
        "critical_vulns": ScanResult.query.filter_by(result_type="vulnerability", severity="critical").count(),
    })


@api_bp.route("/dashboard/widgets")
@login_required
def dashboard_widgets():
    now = datetime.now(timezone.utc)

    # Severity breakdown
    vuln_rows = db.session.execute(
        sa.select(ScanResult.severity, sa.func.count(ScanResult.id))
        .where(ScanResult.result_type == "vulnerability")
        .group_by(ScanResult.severity)
    ).all()
    severity_map = {row[0]: row[1] for row in vuln_rows}

    # Scan trend – last 14 days
    trend_labels, trend_data = [], []
    for i in range(13, -1, -1):
        day = now - timedelta(days=i)
        start = day.replace(hour=0, minute=0, second=0, microsecond=0)
        end   = start + timedelta(days=1)
        count = Scan.query.filter(Scan.created_at >= start, Scan.created_at < end).count()
        trend_labels.append(day.strftime('%b %d'))
        trend_data.append(count)

    # Vulns by target – top 5
    vbt_rows = db.session.execute(
        sa.select(Target.name, sa.func.count(ScanResult.id).label('cnt'))
        .join(Scan, Scan.target_id == Target.id)
        .join(ScanResult, ScanResult.scan_id == Scan.id)
        .where(ScanResult.result_type == "vulnerability")
        .group_by(Target.id, Target.name)
        .order_by(sa.text('cnt DESC'))
        .limit(5)
    ).all()

    # Agent counts
    agent_stats = {
        'online':  EndpointAgent.query.filter_by(status="online").count(),
        'offline': EndpointAgent.query.filter_by(status="offline").count(),
        'unknown': EndpointAgent.query.filter_by(status="unknown").count(),
    }

    # Recent scans
    recent_scans = []
    for scan in Scan.query.order_by(Scan.created_at.desc()).limit(8).all():
        recent_scans.append({
            'id': scan.id,
            'name': scan.name,
            'target': scan.target.host,
            'status': scan.status,
            'vuln_count': scan.vuln_count,
            'critical_count': scan.critical_count,
            'created_at': _fmt(scan.created_at),
        })

    # Recent vulns
    recent_vulns = []
    for r in (ScanResult.query
              .filter_by(result_type="vulnerability")
              .order_by(ScanResult.created_at.desc())
              .limit(10).all()):
        recent_vulns.append({
            'severity': r.severity,
            'title': r.title,
            'host': r.host or '—',
            'cvss_score': r.cvss_score,
            'cve_id': r.cve_id,
        })

    # Palo Alto threat logs
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    paloalto_logs_today = PaloAltoThreatLog.query.filter(
        PaloAltoThreatLog.created_at >= today_start).count()

    recent_paloalto = []
    for log in (PaloAltoThreatLog.query
                .order_by(PaloAltoThreatLog.time_generated.desc())
                .limit(10).all()):
        recent_paloalto.append({
            'severity':    log.severity or 'informational',
            'threat_name': log.threat_name or '—',
            'src_ip':      log.src_ip or '—',
            'dst_ip':      log.dst_ip or '—',
            'category':    log.category or '—',
            'firewall':    log.firewall.name if log.firewall else '—',
            'time':        _fmt(log.time_generated) if log.time_generated else '—',
        })

    return jsonify({
        'stats': {
            'total_scans':    Scan.query.count(),
            'running_scans':  Scan.query.filter_by(status="running").count(),
            'total_targets':  Target.query.count(),
            'total_assets':   Asset.query.count(),
            'online_agents':  agent_stats['online'],
            'open_soc':       SocCase.query.filter(SocCase.status.in_(["pending", "alerted"])).count(),
            'critical_vulns': severity_map.get('critical', 0),
            'high_vulns':     severity_map.get('high', 0),
            'medium_vulns':   severity_map.get('medium', 0),
            'low_vulns':      severity_map.get('low', 0),
            'info_vulns':     severity_map.get('info', 0),
            'paloalto_firewalls':    PaloAltoFirewall.query.count(),
            'paloalto_logs_today':   paloalto_logs_today,
        },
        'severity_map':   severity_map,
        'trend':          {'labels': trend_labels, 'data': trend_data},
        'vuln_by_target': {
            'labels': [r[0] for r in vbt_rows],
            'data':   [r[1] for r in vbt_rows],
        },
        'agent_stats':  agent_stats,
        'recent_scans': recent_scans,
        'recent_vulns': recent_vulns,
        'recent_paloalto_logs': recent_paloalto,
    })
