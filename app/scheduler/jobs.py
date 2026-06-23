from datetime import datetime, timezone
from ..extensions import scheduler, db


def register_jobs(app):
    scheduler.add_job(
        id="check_scheduled_scans",
        func=_run_scheduled_scans,
        args=[app],
        trigger="interval",
        minutes=1,
        replace_existing=True,
    )
    scheduler.add_job(
        id="check_scheduled_reports",
        func=_run_scheduled_reports,
        args=[app],
        trigger="interval",
        minutes=1,
        replace_existing=True,
    )
    scheduler.add_job(
        id="check_domain_changes",
        func=_run_domain_monitor,
        args=[app],
        trigger="interval",
        minutes=360,  # every 6 hours
        replace_existing=True,
    )
    # CVE enrichment: EPSS + NVD + ATT&CK — daily at 02:00 UTC
    scheduler.add_job(
        id="refresh_cve_enrichments",
        func=_run_cve_enrichment,
        args=[app],
        trigger="interval",
        hours=24,
        replace_existing=True,
    )
    # Compliance auto-assessment — every 6 hours
    scheduler.add_job(
        id="auto_assess_compliance",
        func=_run_auto_assess,
        args=[app],
        trigger="interval",
        hours=6,
        replace_existing=True,
    )


def _run_scheduled_scans(app):
    with app.app_context():
        from ..models import ScheduledScan, Scan, AssetGroup, Asset, Tag, Target
        import threading
        now = datetime.now(timezone.utc)
        due = ScheduledScan.query.filter(
            ScheduledScan.active == True,
            ScheduledScan.next_run <= now,
        ).all()

        for sched in due:
            sched.last_run = now
            sched.next_run = _next_run_from_cron(sched.cron_expression)
            db.session.commit()

            from ..scanner.engine import run_scan

            if sched.asset_group_id:
                # Expand group to current members and launch per-IP scans
                group  = db.session.get(AssetGroup, sched.asset_group_id)
                assets = _resolve_group_assets(group) if group else []
                for asset in assets:
                    tgt = Target.query.filter_by(host=asset.ip_address).first()
                    if not tgt:
                        tgt = Target(name=asset.ip_address, host=asset.ip_address)
                        db.session.add(tgt)
                        db.session.flush()
                    scan = Scan(
                        name=f"{sched.name} — {asset.ip_address}",
                        target_id=tgt.id,
                        scan_type=sched.scan_type,
                        port_range=sched.port_range,
                        created_by=sched.created_by,
                        status="pending",
                    )
                    db.session.add(scan)
                    db.session.flush()
                    db.session.commit()
                    threading.Thread(target=run_scan, args=(scan.id, app), daemon=True).start()
            else:
                scan = Scan(
                    name=f"{sched.name} (scheduled)",
                    target_id=sched.target_id,
                    scan_type=sched.scan_type,
                    port_range=sched.port_range,
                    created_by=sched.created_by,
                    status="pending",
                )
                db.session.add(scan)
                db.session.flush()
                db.session.commit()
                threading.Thread(target=run_scan, args=(scan.id, app), daemon=True).start()


def _resolve_group_assets(group):
    """Expand an AssetGroup to its current Asset list."""
    from ..models import Asset, Tag
    if group.group_type == "tag" and group.tag_id:
        return Asset.query.filter(Asset.tags.any(Tag.id == group.tag_id)).all()
    if group.group_type == "network" and group.target_id:
        return Asset.query.filter_by(target_id=group.target_id).all()
    return list(group.manual_assets)


def _run_scheduled_reports(app):
    with app.app_context():
        from ..models import ScheduledReport
        now = datetime.now(timezone.utc)
        due = ScheduledReport.query.filter(
            ScheduledReport.active == True,
            ScheduledReport.next_send <= now,
        ).all()

        for sched in due:
            from ..email_utils.mailer import send_scheduled_report
            try:
                send_scheduled_report(app, sched)
            except Exception as e:
                app.logger.error(f"Report email failed for {sched.name}: {e}")

            sched.last_sent = now
            sched.next_send = _next_run_from_cron(sched.cron_expression)
            db.session.commit()


def _run_domain_monitor(app):
    with app.app_context():
        from ..models import Target, ThreatConfig
        from ..routes.targets import _apply_domain_records
        from datetime import timedelta
        now = datetime.now(timezone.utc)
        cutoff = now - timedelta(hours=6)

        targets = Target.query.filter(
            Target.target_type == "domain",
            db.or_(Target.last_enum_at == None, Target.last_enum_at < cutoff),
        ).all()

        for target in targets:
            cfg = ThreatConfig.query.first()
            dnsdumpster_key = cfg.dnsdumpster_api_key if cfg else None
            from ..threat.subdomain import enumerate_dns_records
            try:
                records = enumerate_dns_records(target.host, dnsdumpster_key)
            except Exception as e:
                app.logger.error(f"Domain monitor failed for {target.host}: {e}")
                continue
            _apply_domain_records(target, records)

        db.session.commit()


def _run_cve_enrichment(app):
    try:
        from ..grc.enrichment import enrich_all_cves
        enrich_all_cves(app)
    except Exception as e:
        app.logger.error(f"CVE enrichment job failed: {e}")


def _run_auto_assess(app):
    try:
        from ..grc.auto_assess import run_auto_assess
        with app.app_context():
            run_auto_assess(app)
    except Exception as e:
        app.logger.error(f"Auto-assessment job failed: {e}")


def _next_run_from_cron(cron_expr: str):
    from apscheduler.triggers.cron import CronTrigger
    parts = cron_expr.split()
    if len(parts) != 5:
        from datetime import timedelta
        return datetime.now(timezone.utc) + timedelta(hours=1)
    trigger = CronTrigger(
        minute=parts[0], hour=parts[1],
        day=parts[2], month=parts[3], day_of_week=parts[4],
        timezone="UTC",
    )
    return trigger.get_next_fire_time(None, datetime.now(timezone.utc))
