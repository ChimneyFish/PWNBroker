import threading
from datetime import datetime, timezone
from flask import Blueprint, render_template, redirect, url_for, request, jsonify, flash, current_app
from flask_login import login_required, current_user
from ..models import Asset, Tag, AssetGroup, Target, ScanResult, VulnTicket, Scan, asset_tags
from ..extensions import db
from .decorators import admin_required

assets_bp = Blueprint("assets", __name__, url_prefix="/assets")


def _is_valid_host(h):
    """Return True if the host value looks like an IP address (not a URL or CIDR range)."""
    if not h:
        return False
    h = h.strip()
    if h.startswith(("http://", "https://", "/")):
        return False
    if "/" in h:  # CIDR ranges like 192.168.1.0/24
        return False
    return True


def _sync_assets():
    """Discover assets from scan results and upsert into the assets table."""
    # Build map of (ip, target_id) -> latest scan timestamp
    host_map = {}
    for r in ScanResult.query.filter(ScanResult.host.isnot(None)).all():
        scan = r.scan
        if not scan or not scan.target_id:
            continue
        host = r.host.strip()
        if not _is_valid_host(host):
            continue
        ts  = scan.completed_at or scan.created_at
        key = (host, scan.target_id)
        if key not in host_map or (ts and (not host_map[key] or ts > host_map[key])):
            host_map[key] = ts

    if not host_map:
        return

    existing = {(a.ip_address, a.target_id): a for a in Asset.query.all()}
    changed  = False

    for (ip, target_id), last_seen in host_map.items():
        if (ip, target_id) in existing:
            asset = existing[(ip, target_id)]
            if last_seen and (not asset.last_seen or last_seen > asset.last_seen):
                asset.last_seen = last_seen
                changed = True
        else:
            db.session.add(Asset(
                ip_address = ip,
                target_id  = target_id,
                first_seen = last_seen,
                last_seen  = last_seen,
            ))
            changed = True

    if changed:
        db.session.commit()


def _open_vuln_counts():
    """Return dict of asset_id -> open vuln count."""
    from sqlalchemy import func
    rows = (
        db.session.query(VulnTicket.target_id, VulnTicket.host_ip,
                         func.count(VulnTicket.id))
        .filter(VulnTicket.status.in_(["open", "in_progress"]))
        .group_by(VulnTicket.target_id, VulnTicket.host_ip)
        .all()
    )
    counts = {}
    for target_id, host_ip, cnt in rows:
        counts[(target_id, host_ip)] = cnt
    return counts


@assets_bp.route("/")
@login_required
def index():
    _sync_assets()
    tag_filter = request.args.get("tag", type=int)
    q = Asset.query
    if tag_filter:
        q = q.filter(Asset.tags.any(Tag.id == tag_filter))
    assets  = q.order_by(Asset.ip_address).all()
    tags    = Tag.query.order_by(Tag.label).all()
    counts  = _open_vuln_counts()
    return render_template("assets/index.html",
                           assets=assets, tags=tags,
                           tag_filter=tag_filter, counts=counts)


@assets_bp.route("/<int:asset_id>/tag", methods=["POST"])
@login_required
def assign_tag(asset_id):
    asset  = Asset.query.get_or_404(asset_id)
    tag_id = request.form.get("tag_id", type=int)
    if not tag_id:
        return jsonify(ok=False, error="No tag specified"), 400
    tag = Tag.query.get_or_404(tag_id)
    if tag not in asset.tags:
        asset.tags.append(tag)
        db.session.commit()
    return jsonify(ok=True, tag_id=tag.id, label=tag.label, color=tag.color)


@assets_bp.route("/<int:asset_id>/untag/<int:tag_id>", methods=["POST"])
@login_required
def remove_tag(asset_id, tag_id):
    asset = Asset.query.get_or_404(asset_id)
    tag   = Tag.query.get_or_404(tag_id)
    if tag in asset.tags:
        asset.tags.remove(tag)
        db.session.commit()
    return jsonify(ok=True)


@assets_bp.route("/<int:asset_id>/notes", methods=["POST"])
@login_required
def update_notes(asset_id):
    asset = Asset.query.get_or_404(asset_id)
    asset.notes = request.form.get("notes", "").strip()
    db.session.commit()
    return jsonify(ok=True)


@assets_bp.route("/<int:asset_id>/hostname", methods=["POST"])
@login_required
def update_hostname(asset_id):
    asset = Asset.query.get_or_404(asset_id)
    asset.hostname = request.form.get("hostname", "").strip() or None
    db.session.commit()
    return jsonify(ok=True, hostname=asset.hostname)


@assets_bp.route("/tags/create", methods=["POST"])
@login_required
@admin_required
def create_tag():
    label = request.form.get("label", "").strip()
    color = request.form.get("color", "#0bbcd4").strip()
    if not label:
        flash("Tag label is required.", "warning")
        return redirect(url_for("assets.index"))
    if Tag.query.filter_by(label=label).first():
        flash(f"Tag '{label}' already exists.", "warning")
        return redirect(url_for("assets.index"))
    db.session.add(Tag(label=label, color=color, created_by=current_user.id))
    db.session.commit()
    return redirect(url_for("assets.index"))


@assets_bp.route("/tags/<int:tag_id>/delete", methods=["POST"])
@login_required
@admin_required
def delete_tag(tag_id):
    tag = Tag.query.get_or_404(tag_id)
    db.session.delete(tag)
    db.session.commit()
    return jsonify(ok=True)


@assets_bp.route("/<int:asset_id>/quick-scan", methods=["POST"])
@login_required
@admin_required
def quick_scan(asset_id):
    asset = Asset.query.get_or_404(asset_id)
    scan_type = request.form.get("scan_type", "port")
    if scan_type not in ("port", "cve", "full", "web"):
        scan_type = "port"

    # Re-use an existing per-IP target if one exists, otherwise create one
    target = Target.query.filter_by(host=asset.ip_address).first()
    if not target:
        if asset.target and asset.target.host == asset.ip_address:
            target = asset.target
        else:
            target = Target(name=asset.ip_address, host=asset.ip_address,
                            created_by=current_user.id)
            db.session.add(target)
            db.session.flush()

    labels = {"port": "Port Scan", "cve": "CVE Lookup", "full": "Full Scan", "web": "Web Scan"}
    scan = Scan(
        name=f"Quick {labels.get(scan_type, scan_type)}: {asset.ip_address}",
        target_id=target.id,
        scan_type=scan_type,
        port_range="1-1024",
        created_by=current_user.id,
        status="pending",
    )
    db.session.add(scan)
    db.session.commit()

    from ..audit import log_action
    log_action("scan.create", entity_type="scan", entity_id=scan.id, entity_name=scan.name,
               detail=f"Quick {scan_type} on asset {asset.ip_address}")

    app = current_app._get_current_object()
    threading.Thread(target=_launch_scan, args=(scan.id, asset.ip_address, app), daemon=True).start()

    return jsonify(ok=True, scan_id=scan.id)


def _launch_scan(scan_id, asset_ip, app):
    from ..scanner.engine import run_scan
    try:
        run_scan(scan_id, app)
    except Exception as e:
        app.logger.error("Quick scan %s failed: %s", scan_id, e)
    _auto_close_resolved_vulns(scan_id, asset_ip, app)


def _auto_close_resolved_vulns(scan_id, asset_ip, app):
    """Close open VulnTickets for asset_ip that were not re-detected by scan_id."""
    try:
        with app.app_context():
            from datetime import datetime, timezone as tz
            from ..models import Scan, ScanResult, VulnTicket
            from ..extensions import db

            scan = db.session.get(Scan, scan_id)
            # Only act when scan succeeded and the type actually checks for vulns
            if not scan or scan.status != "done" or scan.scan_type not in ("full", "web"):
                return

            new_vulns     = ScanResult.query.filter_by(scan_id=scan_id, result_type="vulnerability").all()
            found_cves    = {r.cve_id for r in new_vulns if r.cve_id}
            found_titles  = {r.title.strip().lower() for r in new_vulns if r.title}

            open_tickets = VulnTicket.query.filter(
                VulnTicket.host_ip == asset_ip,
                VulnTicket.status.in_(["open", "in_progress"]),
            ).all()

            now = datetime.now(tz.utc)
            closed = 0
            for t in open_tickets:
                still_present = (
                    (t.cve_id and t.cve_id in found_cves)
                    or (t.title and t.title.strip().lower() in found_titles)
                )
                if not still_present:
                    t.status     = "patched"
                    t.patched_at = now
                    note = (f"[{now.strftime('%Y-%m-%d %H:%M')} auto] "
                            f"Not detected in quick {scan.scan_type} scan #{scan_id}")
                    t.notes = f"{note}\n{t.notes or ''}".strip()
                    closed += 1

            if closed:
                db.session.commit()
                from ..audit import log_action
                log_action("vuln.auto_close", entity_type="asset", entity_name=asset_ip,
                           detail=f"Auto-closed {closed} vuln(s) not re-detected in quick {scan.scan_type} scan #{scan_id}")
    except Exception as e:
        app.logger.error("Auto-close vulns failed for %s after scan %s: %s", asset_ip, scan_id, e)


# ── Asset Groups ──────────────────────────────────────────────────────────────

def _resolve_group_assets(group):
    """Return the Asset list for a group regardless of type."""
    if group.group_type == "tag" and group.tag_id:
        return Asset.query.filter(Asset.tags.any(Tag.id == group.tag_id)).all()
    if group.group_type == "network" and group.target_id:
        return Asset.query.filter_by(target_id=group.target_id).all()
    return group.manual_assets  # manual


@assets_bp.route("/groups")
@login_required
def groups():
    all_groups = AssetGroup.query.order_by(AssetGroup.name).all()
    # Attach resolved member list so template doesn't need to branch
    for g in all_groups:
        g._members = _resolve_group_assets(g)
    tags     = Tag.query.order_by(Tag.label).all()
    networks = Target.query.order_by(Target.name).all()
    all_assets = Asset.query.order_by(Asset.ip_address).all()
    return render_template("assets/groups.html",
                           groups=all_groups, tags=tags,
                           networks=networks, all_assets=all_assets)


@assets_bp.route("/groups/<int:group_id>")
@login_required
def group_detail(group_id):
    group   = AssetGroup.query.get_or_404(group_id)
    members = _resolve_group_assets(group)
    member_ids = {a.id for a in members}
    # Assets eligible to be added (manual groups only)
    available = []
    if group.group_type == "manual":
        available = Asset.query.filter(
            ~Asset.id.in_(member_ids)
        ).order_by(Asset.ip_address).all() if member_ids else \
            Asset.query.order_by(Asset.ip_address).all()
    counts = _open_vuln_counts()
    return render_template("assets/group_detail.html",
                           group=group, members=members,
                           available=available, counts=counts)


@assets_bp.route("/groups/create", methods=["POST"])
@login_required
@admin_required
def create_group():
    name       = request.form.get("name", "").strip()
    desc       = request.form.get("description", "").strip()
    color      = request.form.get("color", "#0bbcd4").strip()
    gtype      = request.form.get("group_type", "manual")
    tag_id     = request.form.get("tag_id",     type=int) or None
    target_id  = request.form.get("target_id",  type=int) or None

    if not name:
        flash("Group name is required.", "warning")
        return redirect(url_for("assets.groups"))

    g = AssetGroup(name=name, description=desc, color=color,
                   group_type=gtype, tag_id=tag_id, target_id=target_id,
                   created_by=current_user.id)
    db.session.add(g)
    db.session.commit()
    return redirect(url_for("assets.group_detail", group_id=g.id))


@assets_bp.route("/groups/<int:group_id>/delete", methods=["POST"])
@login_required
@admin_required
def delete_group(group_id):
    group = AssetGroup.query.get_or_404(group_id)
    db.session.delete(group)
    db.session.commit()
    return redirect(url_for("assets.groups"))


@assets_bp.route("/groups/<int:group_id>/add", methods=["POST"])
@login_required
def group_add_asset(group_id):
    group    = AssetGroup.query.get_or_404(group_id)
    asset_id = request.form.get("asset_id", type=int)
    if group.group_type != "manual":
        return jsonify(ok=False, error="Not a manual group"), 400
    asset = Asset.query.get_or_404(asset_id)
    if asset not in group.manual_assets:
        group.manual_assets.append(asset)
        db.session.commit()
    return jsonify(ok=True, asset_id=asset.id,
                   ip=asset.ip_address, hostname=asset.hostname or "",
                   os=asset.os_name or "")


@assets_bp.route("/groups/<int:group_id>/remove/<int:asset_id>", methods=["POST"])
@login_required
def group_remove_asset(group_id, asset_id):
    group = AssetGroup.query.get_or_404(group_id)
    asset = Asset.query.get_or_404(asset_id)
    if group.group_type != "manual":
        return jsonify(ok=False, error="Not a manual group"), 400
    if asset in group.manual_assets:
        group.manual_assets.remove(asset)
        db.session.commit()
    return jsonify(ok=True)
