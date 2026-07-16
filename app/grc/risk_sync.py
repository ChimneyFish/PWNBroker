"""
Shared logic for turning an accepted VulnTicket finding into (or refreshing)
its backing GRC RiskEntry, so accepting risk from the Vulnerability Tickets
pages and from GRC > Acceptable Risk go through the same, deduplicated path —
one ticket never spawns more than one risk-register entry.
"""
from ..extensions import db

SEVERITY_IMPACT = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}


def sync_risk_entry(ticket, justification, user_id):
    from ..models import RiskEntry, Asset

    asset = Asset.query.filter_by(ip_address=ticket.host_ip).first() if ticket.host_ip else None
    impact = SEVERITY_IMPACT.get(ticket.severity, 3)
    risk = ticket.risk_entry
    if risk:
        risk.description = justification
        risk.status       = "accepted"
        risk.closed_at    = None
        risk.impact       = impact
        if asset:
            risk.asset_id = asset.id
    else:
        risk = RiskEntry(
            title          = f"Accepted Risk: {ticket.vuln_name or ticket.title}",
            description    = justification,
            category       = "technical",
            likelihood     = 3,
            impact         = impact,
            status         = "accepted",
            owner_id       = ticket.assigned_to or user_id,
            asset_id       = asset.id if asset else None,
            created_by     = user_id,
            vuln_ticket_id = ticket.id,
        )
        db.session.add(risk)
        db.session.flush()
    return risk
