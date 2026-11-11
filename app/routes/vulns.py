from datetime import datetime, timezone, timedelta
from flask import Blueprint, render_template, redirect, url_for, request, jsonify
from flask_login import login_required, current_user
from ..models import VulnTicket, ScanResult, Scan, Target, User, _SLA_DAYS, CVEEnrichment
from ..extensions import db
from ..grc.risk_sync import sync_risk_entry
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


def _proof_status(r):
    """Ticket status a finding should have based on what was proven.
    Findings that are only inferred (version banner / heuristic) don't become
    actionable tickets until an active check confirms them."""
    if r.is_inferred and r.verification_status != "confirmed":
        return "not_exploitable" if r.verification_status == "not_exploitable" else "unverified"
    return "patched" if r.is_remediated else "open"


def _note(t, text):
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M")
    t.notes = f"[{ts} system] {text}\n{t.notes or ''}".strip()


def _apply_newer_evidence(t, r, now):
    """A later scan re-tested a vuln that already has a ticket. Proof moves
    the ticket: confirmed → open, ruled out → not_exploitable. Tickets someone
    is handling by hand (in progress, accepted risk, …) aren't touched except
    to note a ruled-out result. Returns True if the ticket changed."""
    if not r.is_inferred and r.verification_status != "confirmed":
        return False
    new = _proof_status(r)
    if new == "open" and t.status in ("unverified", "not_exploitable"):
        sla = _SLA_DAYS.get(r.severity, 90)
        t.status, t.scan_result_id = "open", r.id
        t.opened_at, t.sla_days, t.due_date = now, sla, now + timedelta(days=sla)
        t.patched_at = None
        _note(t, "Reopened: a scan confirmed this is exploitable on the live service.")
        return True
    if new == "not_exploitable" and t.status == "unverified":
        t.status, t.scan_result_id = "not_exploitable", r.id
        _note(t, "Ruled out: the check for this CVE ran and the vulnerable behaviour was not present.")
        return True
    if (new == "not_exploitable" and t.status in ("open", "in_progress")
            and t.scan_result and t.scan_result.is_inferred):
        t.status, t.scan_result_id = "not_exploitable", r.id
        _note(t, "Closed: a rescan's check shows this is no longer exploitable "
                 "(fixed, or the vulnerable feature was disabled).")
        return True
    return False


def _auto_sync():
    """Create VulnTickets for vulnerability ScanResults not yet tracked,
    deduplicating by device+vuln. Version-only CVE matches get an
    "unverified"/"not_exploitable" ticket (not counted as open) unless an
    active check proved them; newer proof updates the existing ticket."""
    now = datetime.now(timezone.utc)

    by_key = {}   # (target, host, vuln-key) → ticket (dedup)
    for t in VulnTicket.query.all():
        by_key.setdefault((t.target_id, t.host_ip or "", t.cve_id or t.title or ""), t)

    # One verdict per (device, vuln, scan): the same CVE can be reported on
    # several ports of a host — proven on any port means exploitable; ruled
    # out only if every port was ruled out. Oldest scan first, so the newest
    # verdict is the one that sticks, and an older scan never overrides a
    # newer one (otherwise two ports with different verdicts would flip the
    # ticket back and forth on every page load).
    results = (ScanResult.query
               .filter(ScanResult.result_type.in_(("vulnerability", "unverified", "not_exploitable")))
               .order_by(ScanResult.scan_id, ScanResult.id).all())
    # Groups include results already linked to a ticket, so a scan's verdict
    # is always judged across all of its ports.
    groups = {}
    for r in results:
        scan = r.scan
        if not scan or not scan.target_id:
            continue
        key = (scan.target_id, r.host or "", r.cve_id or r.title or "")
        groups.setdefault((key, r.scan_id), []).append(r)

    def representative(rs):
        for r in rs:
            if r.verification_status == "confirmed" or not r.is_inferred:
                return r
        if all(r.verification_status == "not_exploitable" for r in rs):
            return rs[0]
        return next((r for r in rs if r.verification_status == "unconfirmed"), rs[0])

    changed = False
    for (dedup_key, scan_id), rs in sorted(groups.items(), key=lambda kv: kv[0][1]):
        r = representative(rs)
        scan = r.scan
        existing = by_key.get(dedup_key)
        if existing is not None:
            # same vuln on same device already has a ticket
            linked = existing.scan_result
            if linked is not None and linked.scan_id is not None and scan_id < linked.scan_id:
                continue  # older evidence than what the ticket already reflects
            if _apply_newer_evidence(existing, r, now):
                changed = True
            continue

        status = _proof_status(r)
        sla    = _SLA_DAYS.get(r.severity, 90)
        opened = scan.completed_at or scan.created_at or now
        if opened.tzinfo is None:
            opened = opened.replace(tzinfo=timezone.utc)
        t = VulnTicket(
            scan_result_id = r.id,
            target_id      = scan.target_id,
            title          = r.title,
            vuln_name      = _derive_vuln_name(r),
            host_ip        = r.host or "",
            severity       = r.severity,
            cve_id         = r.cve_id,
            cvss_score     = r.cvss_score,
            description    = r.description,
            remediation    = r.remediation,
            scan_type      = "dependency" if scan.scan_type == "osv" else "host",
            status         = status,
            sla_days       = sla,
            due_date       = opened + timedelta(days=sla),
            opened_at      = opened,
            patched_at     = now if status == "patched" else None,
        )
        db.session.add(t)
        db.session.flush()   # so t.scan_result resolves for later groups
        by_key[dedup_key] = t
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
        if t.is_unproven:
            continue
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
    unverified      = sum(1 for t in tickets if t.status == "unverified")
    not_exploitable = sum(1 for t in tickets if t.status == "not_exploitable")

    return render_template("vulns/index.html",
                           device_rows=device_rows,
                           total_unverified=unverified,
                           total_not_exploitable=not_exploitable,
                           verify_state=_verify_state,
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
    entering_accepted_risk = new_status == "accepted_risk" and old_status != "accepted_risk"
    leaving_accepted_risk  = old_status == "accepted_risk" and new_status and new_status != "accepted_risk"

    if entering_accepted_risk and not notes:
        return jsonify(ok=False, error="A justification is required to accept this risk."), 400

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

    risk = None
    if entering_accepted_risk:
        t.risk_justification = notes
        risk = sync_risk_entry(t, notes, current_user.id)
    elif leaving_accepted_risk and t.risk_entry:
        t.risk_entry.status    = "closed"
        t.risk_entry.closed_at = datetime.now(timezone.utc)

    db.session.commit()

    from ..audit import log_action
    if new_status and new_status != old_status:
        log_action("vuln.status_change", entity_type="vuln_ticket", entity_id=t.id,
                   entity_name=t.vuln_name or t.title,
                   detail=f"{old_status} → {new_status}")
    if entering_accepted_risk:
        log_action("risk.accept_from_vuln", entity_type="risk_entry", entity_id=risk.id,
                   entity_name=risk.title, detail=f"Vuln ticket #{t.id}: {notes[:200]}")
    if assigned is not None and t.assigned_to != old_assignee:
        log_action("vuln.assign", entity_type="vuln_ticket", entity_id=t.id,
                   entity_name=t.vuln_name or t.title)

    return jsonify({
        "ok":            True,
        "status":        t.status,
        "sla_status":    t.sla_status,
        "days_open":     t.days_open,
        "risk_entry_id": risk.id if risk else (t.risk_entry.id if t.risk_entry else None),
    })


# ── Re-verify unproven findings against the live services ──────────────────

_verify_state = {"running": False, "started": None, "summary": None, "error": None}


def _reverify_worker(app, ticket_ids):
    from ..scanner.verify import verify_results
    with app.app_context():
        try:
            tickets = VulnTicket.query.filter(VulnTicket.id.in_(ticket_ids)).all()
            rows = []
            for t in tickets:
                r = t.scan_result
                if not r or not r.cve_id or not r.port or not r.is_inferred:
                    continue
                # Re-test in place: the finding's verdict/evidence become the
                # latest check's (the evidence records when it was checked).
                r.verification_status, r.verification_evidence = "unconfirmed", None
                rows.append((t, r))
            summary = verify_results([r for _, r in rows])
            now = datetime.now(timezone.utc)
            for t, r in rows:
                _apply_newer_evidence(t, r, now)
            db.session.commit()
            _verify_state["summary"] = summary
        except Exception as e:  # pragma: no cover - surfaced on the page
            db.session.rollback()
            _verify_state["error"] = str(e)
        finally:
            _verify_state["running"] = False


@vulns_bp.route("/reverify", methods=["POST"])
@login_required
@admin_required
def reverify():
    """Re-test every unverified finding (e.g. after nuclei templates update or
    the service changed) without running full scans."""
    import threading
    from flask import current_app, flash
    if _verify_state["running"]:
        flash("Verification is already running.", "info")
        return redirect(url_for("vulns.index"))
    ids = [t.id for t in VulnTicket.query.filter_by(status="unverified").all()]
    if not ids:
        flash("Nothing to verify — there are no unverified findings.", "info")
        return redirect(url_for("vulns.index"))
    _verify_state.update(running=True, started=datetime.now(timezone.utc), summary=None, error=None)
    threading.Thread(target=_reverify_worker,
                     args=(current_app._get_current_object(), ids), daemon=True).start()
    from ..audit import log_action
    log_action("vuln.reverify", entity_type="vuln_ticket", entity_name=f"{len(ids)} findings")
    flash(f"Verifying {len(ids)} unverified findings against the live services…", "info")
    return redirect(url_for("vulns.index"))
