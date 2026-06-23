from datetime import datetime, timezone, timedelta
from flask import Blueprint, render_template, redirect, url_for, request, jsonify
from flask_login import login_required, current_user
from ..models import VulnTicket, ScanResult, Scan, Target, User, _SLA_DAYS, CVEEnrichment
from ..extensions import db
from .decorators import admin_required

vulns_bp = Blueprint("vulns", __name__, url_prefix="/vulns")


def _derive_vuln_name(r):
    """Return a human-readable vulnerability name from a ScanResult."""
    if r.package_name:
        name = r.package_name
        if r.package_version:
            name += f" {r.package_version}"
        return name
    if r.description:
        d = r.description.strip()
        return d[:80] + ("..." if len(d) > 80 else "")
    return r.title or ""


def _auto_sync():
    """Create VulnTickets for vulnerability ScanResults not yet tracked, deduplicating by device+vuln."""
    now = datetime.now(timezone.utc)

    # Build two seen-sets: by scan_result_id (fast skip) and by (target, host, vuln-key) (dedup)
    tracked_sr  = set()
    tracked_key = set()
    for t in VulnTicket.query.with_entities(
        VulnTicket.scan_result_id, VulnTicket.target_id,
        VulnTicket.host_ip, VulnTicket.cve_id, VulnTicket.title
    ).all():
        tracked_sr.add(t.scan_result_id)
        tracked_key.add((t.target_id, t.host_ip or "", t.cve_id or t.title or ""))

    results = ScanResult.query.filter_by(result_type="vulnerability").all()

    changed = False
    for r in results:
        if r.id in tracked_sr:
            continue
        scan = r.scan
        if not scan or not scan.target_id:
            continue
        host    = r.host or ""
        vuln_key = r.cve_id or r.title or ""
        dedup_key = (scan.target_id, host, vuln_key)
        if dedup_key in tracked_key:
            continue  # same vuln on same device already has a ticket

        sla    = _SLA_DAYS.get(r.severity, 90)
        opened = scan.completed_at or scan.created_at or now
        if opened.tzinfo is None:
            opened = opened.replace(tzinfo=timezone.utc)
        db.session.add(VulnTicket(
            scan_result_id = r.id,
            target_id      = scan.target_id,
            title          = r.title,
            vuln_name      = _derive_vuln_name(r),
            host_ip        = host,
            severity       = r.severity,
            cve_id         = r.cve_id,
            cvss_score     = r.cvss_score,
            description    = r.description,
            remediation    = r.remediation,
            scan_type      = "dependency" if scan.scan_type == "osv" else "host",
            status         = "patched" if r.is_remediated else "open",
            sla_days       = sla,
            due_date       = opened + timedelta(days=sla),
            opened_at      = opened,
            patched_at     = now if r.is_remediated else None,
        ))
        tracked_key.add(dedup_key)
        changed = True

    # Backfill host_ip / vuln_name for tickets created before these fields existed
    for t in VulnTicket.query.filter(
        db.or_(VulnTicket.host_ip.is_(None), VulnTicket.vuln_name.is_(None))
    ).all():
        if t.scan_result:
            if t.host_ip is None:
                t.host_ip = t.scan_result.host or ""
            if t.vuln_name is None:
                t.vuln_name = _derive_vuln_name(t.scan_result)
            changed = True

    if changed:
        db.session.commit()



@vulns_bp.route("/")
@login_required
def index():
    _auto_sync()
    tickets = VulnTicket.query.all()

    open_t   = [t for t in tickets if not t.is_resolved]
    overdue  = [t for t in open_t  if t.sla_status == "overdue"]
    critical = [t for t in open_t  if t.severity == "critical"]
    patched  = [t for t in tickets if t.status == "patched"]

    # Group by individual device (target + specific host IP)
    by_device = {}
    for t in tickets:
        host = t.host_ip or t.target.host
        key  = (t.target_id, host)
        if key not in by_device:
            by_device[key] = {
                "target":   t.target,
                "host_ip":  host,
                "open":     0,
                "critical": 0, "high": 0, "medium": 0, "low": 0,
                "overdue":  0, "patched": 0,
            }
        row = by_device[key]
        if not t.is_resolved:
            row["open"] += 1
            if t.severity in row:
                row[t.severity] += 1
            if t.sla_status == "overdue":
                row["overdue"] += 1
        if t.status == "patched":
            row["patched"] += 1

    device_rows = sorted(by_device.values(), key=lambda x: x["open"], reverse=True)

    return render_template("vulns/index.html",
                           device_rows=device_rows,
                           total_open=len(open_t),
                           total_critical=len(critical),
                           total_overdue=len(overdue),
                           total_patched=len(patched))


@vulns_bp.route("/device/<int:target_id>")
@login_required
def device(target_id):
    _auto_sync()
    target      = Target.query.get_or_404(target_id)
    host_filter = request.args.get("host", "").strip()
    q           = VulnTicket.query.filter_by(target_id=target_id)
    if host_filter:
        q = q.filter_by(host_ip=host_filter)
    tickets = q.order_by(VulnTicket.severity, VulnTicket.status).all()
    users   = User.query.order_by(User.username).all()
    return render_template("vulns/device.html",
                           target=target, tickets=tickets, users=users,
                           host_filter=host_filter)


@vulns_bp.route("/tickets")
@login_required
def tickets():
    _auto_sync()
    status_f = request.args.get("status", "open")
    sev_f    = request.args.get("severity", "")

    q = VulnTicket.query
    if status_f == "open":
        q = q.filter(VulnTicket.status.in_(["open", "in_progress"]))
    elif status_f != "all":
        q = q.filter_by(status=status_f)
    if sev_f:
        q = q.filter_by(severity=sev_f)

    all_tickets = q.order_by(VulnTicket.due_date.asc()).all()
    users       = User.query.order_by(User.username).all()

    # Build enrichment lookup keyed by cve_id
    cve_ids     = {t.cve_id for t in all_tickets if t.cve_id}
    enrichments = {}
    if cve_ids:
        for e in CVEEnrichment.query.filter(CVEEnrichment.cve_id.in_(cve_ids)).all():
            enrichments[e.cve_id] = e

    return render_template("vulns/tickets.html",
                           tickets=all_tickets,
                           status_filter=status_f,
                           sev_filter=sev_f,
                           users=users,
                           enrichments=enrichments)


@vulns_bp.route("/tickets/<int:ticket_id>/update", methods=["POST"])
@login_required
@admin_required
def ticket_update(ticket_id):
    t          = VulnTicket.query.get_or_404(ticket_id)
    new_status = request.form.get("status", "").strip()
    notes      = request.form.get("notes",  "").strip()
    assigned   = request.form.get("assigned_to", "").strip()

    old_status = t.status
    if new_status and new_status != t.status:
        t.status = new_status
        if new_status == "patched" and not t.patched_at:
            t.patched_at = datetime.now(timezone.utc)
        elif new_status != "patched":
            t.patched_at = None
    if notes:
        existing = t.notes or ""
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M")
        t.notes = f"[{ts} {current_user.username}] {notes}\n{existing}".strip()
    old_assignee = t.assigned_to
    if assigned is not None:
        t.assigned_to = int(assigned) if assigned.isdigit() else None

    db.session.commit()

    from ..audit import log_action
    if new_status and new_status != old_status:
        log_action("vuln.status_change", entity_type="vuln_ticket", entity_id=t.id,
                   entity_name=t.vuln_name or t.title,
                   detail=f"{old_status} → {new_status}")
    if assigned is not None and t.assigned_to != old_assignee:
        log_action("vuln.assign", entity_type="vuln_ticket", entity_id=t.id,
                   entity_name=t.vuln_name or t.title)

    return jsonify({
        "ok":         True,
        "status":     t.status,
        "sla_status": t.sla_status,
        "days_open":  t.days_open,
    })
