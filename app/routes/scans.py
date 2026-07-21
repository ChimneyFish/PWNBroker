import json
import os
import threading
from flask import Blueprint, render_template, redirect, url_for, flash, request, jsonify, current_app
from flask_login import login_required, current_user
from ..models import Scan, Target, ScheduledScan, ScanResult, AtlassianConfig, AssetGroup, Asset, Tag, VulnTicket
from ..extensions import db
from ..scheduler.jobs import _next_run_from_cron
from ..validators import is_valid_port_range
from .decorators import admin_required

scans_bp = Blueprint("scans", __name__, url_prefix="/scans")

_DAYS   = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"]
_MONTHS = ["", "Jan", "Feb", "Mar", "Apr", "May", "Jun",
           "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]


def cron_to_human(expr: str) -> str:
    """Convert a 5-field cron expression to a readable English description."""
    if not expr:
        return expr
    parts = expr.strip().split()
    if len(parts) != 5:
        return expr
    minute, hour, day, month, weekday = parts

    def _time(h, m):
        try:
            return f"{int(h):02d}:{int(m):02d}"
        except ValueError:
            return f"{h}:{m}"

    def _day_names(spec):
        names = []
        for seg in spec.split(","):
            seg = seg.strip()
            if "-" in seg:
                a, b = seg.split("-", 1)
                for i in range(int(a), int(b) + 1):
                    names.append(_DAYS[i % 7])
            else:
                names.append(_DAYS[int(seg) % 7])
        return ", ".join(names)

    if minute == "*" and hour == "*" and day == "*" and month == "*" and weekday == "*":
        return "Every minute"
    if minute.startswith("*/") and hour == "*" and day == "*" and month == "*" and weekday == "*":
        n = minute[2:]
        return f"Every {n} minute{'s' if n != '1' else ''}"
    if hour.startswith("*/") and day == "*" and month == "*" and weekday == "*":
        n = hour[2:]
        return f"Every {n} hour{'s' if n != '1' else ''}"
    if hour == "*" and day == "*" and month == "*" and weekday == "*":
        return "Every hour" if minute == "0" else f"Every hour at :{minute.zfill(2)}"
    if day == "*" and month == "*" and weekday == "*":
        return f"Daily at {_time(hour, minute)}"
    if day == "*" and month == "*" and weekday != "*":
        try:
            days_str = _day_names(weekday)
        except (ValueError, IndexError):
            days_str = weekday
        return f"Weekly on {days_str} at {_time(hour, minute)}"
    if month == "*" and weekday == "*" and day != "*":
        return f"Monthly on day {day} at {_time(hour, minute)}"
    if weekday == "*" and month != "*" and day != "*":
        try:
            month_name = _MONTHS[int(month)]
        except (ValueError, IndexError):
            month_name = month
        return f"Yearly on {month_name} {day} at {_time(hour, minute)}"
    return expr


SCAN_TYPES = [
    ("full",      "Full Scan (Ports + CVE + Web + Subdomains)"),
    ("port",      "Port & Service Scan"),
    ("web",       "Web Vulnerability Scan"),
    ("cve",       "CVE Lookup Only"),
    ("subdomain", "Subdomain Enumeration"),
]


def _group_assets(group: AssetGroup) -> list[Asset]:
    """Return the Asset list for a group, matching the logic in assets.py."""
    if group.group_type == "tag" and group.tag_id:
        return Asset.query.filter(Asset.tags.any(Tag.id == group.tag_id)).all()
    if group.group_type == "network" and group.target_id:
        return Asset.query.filter_by(target_id=group.target_id).all()
    return list(group.manual_assets)


def _target_for_ip(ip: str) -> Target:
    """Find or create a per-IP Target record."""
    t = Target.query.filter_by(host=ip).first()
    if not t:
        t = Target(name=ip, host=ip, created_by=None)
        db.session.add(t)
        db.session.flush()
    return t


@scans_bp.route("/")
@login_required
def index():
    scans     = Scan.query.order_by(Scan.created_at.desc()).all()
    scheduled = ScheduledScan.query.order_by(ScheduledScan.created_at.desc()).all()
    # Build group name lookup for scheduled scans that target a group
    group_ids = {s.asset_group_id for s in scheduled if s.asset_group_id}
    group_map = {g.id: g for g in AssetGroup.query.filter(AssetGroup.id.in_(group_ids)).all()} if group_ids else {}
    return render_template("scans/index.html", scans=scans, scheduled=scheduled,
                           cron_to_human=cron_to_human, group_map=group_map)


@scans_bp.route("/new", methods=["GET", "POST"])
@login_required
@admin_required
def new():
    targets = Target.query.order_by(Target.name).all()
    groups  = AssetGroup.query.order_by(AssetGroup.name).all()
    for g in groups:
        g._member_count = len(_group_assets(g))

    if request.method == "POST":
        raw_target = request.form.get("target_id", "").strip()
        name       = request.form.get("name", "").strip()
        scan_type  = request.form.get("scan_type", "full")
        port_range = request.form.get("port_range", "1-1024").strip()
        scan_path  = request.form.get("scan_path", "").strip() if scan_type == "osv" else None

        if not raw_target or not name:
            flash("Target and scan name are required.", "danger")
            return render_template("scans/new.html", targets=targets, groups=groups, scan_types=SCAN_TYPES)
        if not is_valid_port_range(port_range):
            flash(f"'{port_range}' isn't a valid port range (e.g. 1-1024 or 22,80,443).", "danger")
            return render_template("scans/new.html", targets=targets, groups=groups, scan_types=SCAN_TYPES)

        # ── Asset group ──────────────────────────────────────────────────────
        if raw_target.startswith("g:"):
            group_id = int(raw_target[2:])
            group    = AssetGroup.query.get_or_404(group_id)

            # A "network" group mirrors every asset under one subnet Target —
            # scan that subnet directly so newly-appeared devices are found
            # too, instead of only rescanning IPs already in the asset list.
            if group.group_type == "network" and group.target_id:
                target_obj = Target.query.get_or_404(group.target_id)
                scan = Scan(
                    name=f"{name} — {group.name}", target_id=target_obj.id, scan_type=scan_type,
                    port_range=port_range, created_by=current_user.id, status="pending",
                )
                db.session.add(scan)
                db.session.commit()

                from ..audit import log_action
                log_action("scan.create", entity_type="scan", entity_id=scan.id, entity_name=scan.name,
                           detail=f"Type: {scan_type} | Network group: {group.name} ({target_obj.host})")

                from ..scanner.engine import run_scan
                app = current_app._get_current_object()
                threading.Thread(target=run_scan, args=(scan.id, app), daemon=True).start()
                flash(f"Scan '{scan.name}' started against {target_obj.host}.", "success")
                return redirect(url_for("scans.view", scan_id=scan.id))

            # Manual/tag groups: arbitrary hosts, not one contiguous subnet —
            # launch one scan per member asset.
            assets = _group_assets(group)
            if not assets:
                flash(f"Group '{group.name}' has no assets.", "warning")
                return render_template("scans/new.html", targets=targets, groups=groups, scan_types=SCAN_TYPES)

            app = current_app._get_current_object()
            from ..scanner.engine import run_scan
            from ..audit import log_action
            launched = 0
            for asset in assets:
                t = _target_for_ip(asset.ip_address)
                scan = Scan(
                    name=f"{name} — {asset.ip_address}",
                    target_id=t.id, scan_type=scan_type,
                    port_range=port_range, created_by=current_user.id, status="pending",
                )
                db.session.add(scan)
                db.session.flush()
                log_action("scan.create", entity_type="scan", entity_id=scan.id,
                           entity_name=scan.name,
                           detail=f"Type: {scan_type} | Group: {group.name}")
                threading.Thread(target=run_scan, args=(scan.id, app), daemon=True).start()
                launched += 1
            db.session.commit()
            flash(f"Started {launched} scan{'s' if launched != 1 else ''} for group '{group.name}'.", "success")
            return redirect(url_for("scans.index"))

        # ── Single target ──────────────────────────────────────────────────
        target_id = int(raw_target)
        if scan_type == "osv" and scan_path and not os.path.isdir(scan_path):
            flash(f"Directory not found: {scan_path}", "danger")
            return render_template("scans/new.html", targets=targets, groups=groups, scan_types=SCAN_TYPES)

        scan = Scan(name=name, target_id=target_id, scan_type=scan_type,
                    port_range=port_range, scan_path=scan_path,
                    created_by=current_user.id, status="pending")
        db.session.add(scan)
        db.session.commit()

        from ..audit import log_action
        target_obj = Target.query.get(target_id)
        log_action("scan.create", entity_type="scan", entity_id=scan.id, entity_name=name,
                   detail=f"Type: {scan_type} | Target: {target_obj.name if target_obj else target_id}")

        from ..scanner.engine import run_scan
        app = current_app._get_current_object()
        threading.Thread(target=run_scan, args=(scan.id, app), daemon=True).start()
        flash(f"Scan '{name}' started.", "success")
        return redirect(url_for("scans.view", scan_id=scan.id))

    return render_template("scans/new.html", targets=targets, groups=groups, scan_types=SCAN_TYPES)


@scans_bp.route("/<int:scan_id>")
@login_required
def view(scan_id):
    scan = Scan.query.get_or_404(scan_id)
    results = scan.results.order_by(ScanResult.severity, ScanResult.result_type).all()
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    results.sort(key=lambda r: severity_order.get(r.severity, 5))
    atlassian_cfg = AtlassianConfig.query.first()
    jira_enabled = bool(atlassian_cfg and atlassian_cfg.enabled and atlassian_cfg.jira_enabled)
    existing_tickets = {t.result_id: t for t in scan.jira_tickets.all()}

    # Findings already accepted as risk on this target, keyed by (host, cve-or-title), so a
    # re-appearing finding in a later scan shows as pre-accepted instead of being re-triaged
    # from scratch — without hiding it from the results.
    accepted_risk = {}
    if scan.target_id:
        for t in VulnTicket.query.filter_by(target_id=scan.target_id, status="accepted_risk").all():
            accepted_risk[(t.host_ip or "", t.cve_id or t.title or "")] = t

    # Parse triage raw_data so the template gets clean dicts, not JSON strings
    triage_data = {}
    for r in results:
        if r.result_type == "triage" and r.raw_data:
            try:
                triage_data[r.host] = json.loads(r.raw_data)
            except (ValueError, TypeError):
                pass

    return render_template("scans/view.html", scan=scan, results=results,
                           jira_enabled=jira_enabled, existing_tickets=existing_tickets,
                           triage_data=triage_data, accepted_risk=accepted_risk)


@scans_bp.route("/<int:scan_id>/delete", methods=["POST"])
@login_required
@admin_required
def delete(scan_id):
    scan = Scan.query.get_or_404(scan_id)
    scan_name = scan.name
    db.session.delete(scan)
    db.session.commit()
    from ..audit import log_action
    log_action("scan.delete", entity_type="scan", entity_id=scan_id, entity_name=scan_name)
    flash("Scan deleted.", "success")
    return redirect(url_for("scans.index"))


@scans_bp.route("/schedule/new", methods=["GET", "POST"])
@login_required
@admin_required
def schedule_new():
    targets = Target.query.order_by(Target.name).all()
    groups  = AssetGroup.query.order_by(AssetGroup.name).all()
    for g in groups:
        g._member_count = len(_group_assets(g))

    if request.method == "POST":
        name       = request.form.get("name", "").strip()
        raw_target = request.form.get("target_id", "").strip()
        scan_type  = request.form.get("scan_type", "full")
        port_range = request.form.get("port_range", "1-1024").strip()
        cron       = request.form.get("cron_expression", "").strip()

        if not name or not raw_target or not cron:
            flash("All fields are required.", "danger")
            return render_template("scans/schedule_new.html", targets=targets,
                                   groups=groups, scan_types=SCAN_TYPES)
        if not is_valid_port_range(port_range):
            flash(f"'{port_range}' isn't a valid port range (e.g. 1-1024 or 22,80,443).", "danger")
            return render_template("scans/schedule_new.html", targets=targets,
                                   groups=groups, scan_types=SCAN_TYPES)

        next_run = _next_run_from_cron(cron)

        if raw_target.startswith("g:"):
            group_id = int(raw_target[2:])
            group    = AssetGroup.query.get_or_404(group_id)
            # Resolve a placeholder target_id (required by NOT NULL on existing rows).
            # The scheduler uses asset_group_id at fire time and ignores this value.
            assets   = _group_assets(group)
            placeholder_tid = None
            for a in assets:
                if a.target_id:
                    placeholder_tid = a.target_id
                    break
            if placeholder_tid is None:
                placeholder_tid = (targets[0].id if targets else None)
            if placeholder_tid is None:
                flash("Cannot create scheduled group scan: no targets exist yet.", "danger")
                return redirect(url_for("scans.schedule_new"))

            sched = ScheduledScan(
                name=name, target_id=placeholder_tid, asset_group_id=group_id,
                scan_type=scan_type, port_range=port_range, cron_expression=cron,
                created_by=current_user.id, next_run=next_run,
            )
        else:
            sched = ScheduledScan(
                name=name, target_id=int(raw_target), scan_type=scan_type,
                port_range=port_range, cron_expression=cron,
                created_by=current_user.id, next_run=next_run,
            )

        db.session.add(sched)
        db.session.commit()
        flash(f"Scheduled scan '{name}' created.", "success")
        return redirect(url_for("scans.index"))

    return render_template("scans/schedule_new.html", targets=targets,
                           groups=groups, scan_types=SCAN_TYPES)


@scans_bp.route("/schedule/<int:sched_id>/toggle", methods=["POST"])
@login_required
@admin_required
def schedule_toggle(sched_id):
    sched = ScheduledScan.query.get_or_404(sched_id)
    sched.active = not sched.active
    db.session.commit()
    return jsonify({"active": sched.active})


@scans_bp.route("/schedule/<int:sched_id>/delete", methods=["POST"])
@login_required
@admin_required
def schedule_delete(sched_id):
    sched = ScheduledScan.query.get_or_404(sched_id)
    db.session.delete(sched)
    db.session.commit()
    flash("Scheduled scan deleted.", "success")
    return redirect(url_for("scans.index"))


@scans_bp.route("/<int:scan_id>/remediate/<int:result_id>", methods=["POST"])
@login_required
@admin_required
def remediate(scan_id, result_id):
    result = ScanResult.query.filter_by(id=result_id, scan_id=scan_id).first_or_404()
    result.is_remediated = not result.is_remediated
    db.session.commit()
    return jsonify({"remediated": result.is_remediated})
