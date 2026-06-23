"""
Automatically assess compliance controls based on observable signals from
the PwnBroker database (assets, vulns, scans, policies, threat intel, etc.).
Designed to be idempotent: each run upserts ControlAssessment rows without
overwriting assessments that were manually set to a *better* status than
what auto-assessment would produce.

Signal → control mapping strategy:
  - compliant  : signal clearly met (count > threshold, config present)
  - partial    : signal partially met (count > 0 but below threshold)
  - non_compliant: signal clearly missing (count == 0, config absent)
  Only updates assessments tagged with the "auto" assessor tag so manual
  overrides (assessor_id is a real user) are never clobbered.
"""

import logging
from datetime import datetime, timezone

log = logging.getLogger(__name__)

# ── Signal → control_id mappings ─────────────────────────────────────────────
# Each entry: (control_id_prefix, signal_fn, compliant_threshold, notes_template)
# signal_fn receives db session and returns an integer count / bool.

_AUTO_ASSESSOR_MARKER = "auto"   # stored in notes to identify auto-assessed rows


def run_auto_assess(app=None):
    """
    Main entry point for the auto-assessment job.
    Call from scheduler or manually from the GRC dashboard.
    """
    _app = app or _get_app()
    with _app.app_context():
        from ..extensions import db
        from ..models import (
            Asset, VulnTicket, IOCRecord, ScheduledScan, Policy,
            User, ComplianceControl, ControlAssessment,
        )

        signals = _collect_signals(db, Asset, VulnTicket, IOCRecord,
                                   ScheduledScan, Policy, User)
        log.info("Auto-assess signals: %s", signals)

        mappings = _build_mappings(signals)
        now = datetime.now(timezone.utc)
        updated = 0

        for control_id_prefix, status, notes in mappings:
            # Match controls whose control_id starts with the prefix
            controls = ComplianceControl.query.filter(
                ComplianceControl.control_id.like(f"{control_id_prefix}%")
            ).all()

            for ctrl in controls:
                a = ctrl.assessment
                if a and _is_manual(a):
                    continue  # never overwrite manual assessments
                if not a:
                    a = ControlAssessment(control_id=ctrl.id)
                    db.session.add(a)
                a.status      = status
                a.notes       = notes
                a.assessed_at = now
                a.assessed_by = None  # null = auto
                updated += 1

        db.session.commit()
        log.info("Auto-assessment updated %d control(s).", updated)
        return updated


def _is_manual(assessment):
    """Return True if the assessment was set by a human (not auto)."""
    if assessment.assessed_by is not None:
        return True
    notes = assessment.notes or ""
    return _AUTO_ASSESSOR_MARKER not in notes


def _collect_signals(db, Asset, VulnTicket, IOCRecord, ScheduledScan, Policy, User):
    """Query the database and return a dict of named signals."""
    asset_count     = Asset.query.count()
    open_vulns      = VulnTicket.query.filter_by(status="open").count()
    critical_vulns  = (VulnTicket.query
                       .filter(VulnTicket.status == "open",
                               VulnTicket.severity.in_(["critical", "high"]))
                       .count())
    remediated_vulns = VulnTicket.query.filter_by(status="closed").count()

    ioc_count       = 0
    try:
        ioc_count = IOCRecord.query.count()
    except Exception:
        pass

    active_scans    = ScheduledScan.query.filter_by(active=True).count()
    active_policies = Policy.query.filter_by(status="active").count()
    total_policies  = Policy.query.count()
    user_count      = User.query.count()

    return {
        "assets":           asset_count,
        "open_vulns":       open_vulns,
        "critical_vulns":   critical_vulns,
        "remediated_vulns": remediated_vulns,
        "ioc_count":        ioc_count,
        "active_scans":     active_scans,
        "active_policies":  active_policies,
        "total_policies":   total_policies,
        "users":            user_count,
    }


def _build_mappings(s):
    """
    Return list of (control_id_prefix, status, notes) tuples.
    Covers all three frameworks seeded by seed.py.
    """
    results = []

    # ── Asset / hardware inventory ────────────────────────────────────────────
    if s["assets"] >= 5:
        inv_status = "compliant"
        inv_notes  = f"[auto] {s['assets']} assets discovered and inventoried via network scanning."
    elif s["assets"] > 0:
        inv_status = "partial"
        inv_notes  = f"[auto] {s['assets']} asset(s) found — inventory may be incomplete."
    else:
        inv_status = "non_compliant"
        inv_notes  = "[auto] No assets discovered. Run a network scan to populate inventory."

    # NIST CSF: ID.AM-01 (hardware inventory), ID.AM-02 (software/platform inv)
    results += [
        ("ID.AM-01", inv_status, inv_notes),
        ("ID.AM-02", inv_status, inv_notes),
    ]
    # CIS v8: CIS-01 (enterprise asset inventory), CIS-02 (software assets)
    results += [
        ("CIS-01", inv_status, inv_notes),
        ("CIS-02", inv_status, inv_notes),
    ]
    # ISO 27001: A.5.9 (inventory of information and other assets)
    results += [
        ("A.5.9", inv_status, inv_notes),
    ]

    # ── Vulnerability management ──────────────────────────────────────────────
    if s["open_vulns"] > 0 and s["remediated_vulns"] > 0:
        vuln_status = "partial"
        vuln_notes  = (f"[auto] {s['open_vulns']} open vuln(s), "
                       f"{s['remediated_vulns']} remediated. "
                       "Active patching in progress.")
    elif s["open_vulns"] > 0 and s["remediated_vulns"] == 0:
        vuln_status = "non_compliant"
        vuln_notes  = (f"[auto] {s['open_vulns']} open vuln(s) with no remediations recorded. "
                       "Begin patching cycle.")
    elif s["open_vulns"] == 0 and s["remediated_vulns"] > 0:
        vuln_status = "compliant"
        vuln_notes  = f"[auto] All known vulnerabilities remediated ({s['remediated_vulns']} closed)."
    else:
        vuln_status = "not_assessed"
        vuln_notes  = "[auto] No vulnerability data available. Run a CVE scan."

    results += [
        ("ID.RA-01", vuln_status, vuln_notes),   # NIST: asset vulns identified/documented
        ("ID.RA-02", vuln_status, vuln_notes),   # NIST: threat intel received
        ("CIS-07",   vuln_status, vuln_notes),   # CIS: continuous vuln management
        ("A.8.8",    vuln_status, vuln_notes),   # ISO: management of technical vulns
    ]

    # ── Critical vulnerabilities ──────────────────────────────────────────────
    if s["critical_vulns"] == 0 and s["open_vulns"] >= 0:
        crit_status = "compliant" if s["assets"] > 0 else "not_assessed"
        crit_notes  = "[auto] No critical/high vulnerabilities currently open."
    else:
        crit_status = "non_compliant"
        crit_notes  = (f"[auto] {s['critical_vulns']} critical/high vuln(s) require immediate attention.")

    results += [
        ("RC.RP-02", crit_status, crit_notes),  # NIST: recovery objectives prioritized
        ("RS.MI-02", crit_status, crit_notes),  # NIST: incidents contained
    ]

    # ── Threat intelligence / IOC monitoring ─────────────────────────────────
    if s["ioc_count"] >= 10:
        ti_status = "compliant"
        ti_notes  = f"[auto] {s['ioc_count']} IOC(s) tracked via threat intel integration."
    elif s["ioc_count"] > 0:
        ti_status = "partial"
        ti_notes  = f"[auto] {s['ioc_count']} IOC(s) collected — expand threat intel coverage."
    else:
        ti_status = "non_compliant"
        ti_notes  = "[auto] No IOCs recorded. Enable threat intel feeds in Threat Intel settings."

    results += [
        ("DE.CM-01", ti_status, ti_notes),   # NIST: networks monitored
        ("DE.CM-09", ti_status, ti_notes),   # NIST: computing infra monitored for anomalies
        ("CIS-13",   ti_status, ti_notes),   # CIS: network monitoring/defense
    ]

    # ── Incident response / SOC ───────────────────────────────────────────────
    # Use IOC alerts as a proxy for IR capability
    ir_status = "partial" if s["ioc_count"] > 0 else "non_compliant"
    ir_notes  = (
        "[auto] Threat intel feed active — IR capability partially demonstrated."
        if s["ioc_count"] > 0
        else "[auto] No incident/alert data found. Configure threat intel and alerting."
    )
    results += [
        ("RS.MA-01", ir_status, ir_notes),   # NIST: response activities coordinated
        ("RS.CO-02", ir_status, ir_notes),   # NIST: events reported
        ("CIS-17",   ir_status, ir_notes),   # CIS: incident response management
        ("A.5.29",   ir_status, ir_notes),   # ISO: IS during disruption
    ]

    # ── Continuous monitoring / active scans ──────────────────────────────────
    if s["active_scans"] >= 2:
        mon_status = "compliant"
        mon_notes  = f"[auto] {s['active_scans']} scheduled scan(s) providing continuous coverage."
    elif s["active_scans"] == 1:
        mon_status = "partial"
        mon_notes  = "[auto] 1 scheduled scan configured. Add more targets for full coverage."
    else:
        mon_status = "non_compliant"
        mon_notes  = "[auto] No active scheduled scans. Configure recurring scans for continuous monitoring."

    results += [
        ("DE.CM-03", mon_status, mon_notes),  # NIST: personnel activity monitored
        ("A.8.15",   mon_status, mon_notes),  # ISO: logging
        ("CIS-08",   mon_status, mon_notes),  # CIS: audit log management
    ]

    # ── Policy management ─────────────────────────────────────────────────────
    if s["active_policies"] >= 3:
        pol_status = "compliant"
        pol_notes  = f"[auto] {s['active_policies']} active polic(ies) defined."
    elif s["total_policies"] > 0:
        pol_status = "partial"
        pol_notes  = (f"[auto] {s['total_policies']} polic(ies) exist but only "
                      f"{s['active_policies']} are active.")
    else:
        pol_status = "non_compliant"
        pol_notes  = "[auto] No policies defined. Create policies in the Policy Library."

    results += [
        ("GV.PO-01", pol_status, pol_notes),  # NIST: policy for cybersecurity established
        ("GV.PO-02", pol_status, pol_notes),  # NIST: cybersecurity roles/responsibilities
        ("A.5.1",    pol_status, pol_notes),  # ISO: policies for information security
        ("A.5.2",    pol_status, pol_notes),  # ISO: information security roles
    ]

    # ── Access / identity management (basic heuristic) ───────────────────────
    if s["users"] > 0:
        aa_status = "partial"
        aa_notes  = (f"[auto] {s['users']} user account(s) managed. "
                     "Verify MFA and least-privilege configuration manually.")
    else:
        aa_status = "non_compliant"
        aa_notes  = "[auto] No user accounts found."

    results += [
        ("PR.AA-01", aa_status, aa_notes),   # NIST: identities managed
        ("PR.AA-03", aa_status, aa_notes),   # NIST: users, services auth'd
        ("CIS-04",   aa_status, aa_notes),   # CIS: controlled use of admin privileges
        ("CIS-05",   aa_status, aa_notes),   # CIS: account management
        ("A.8.5",    aa_status, aa_notes),   # ISO: secure authentication
    ]

    return results


def _get_app():
    from flask import current_app
    return current_app._get_current_object()
