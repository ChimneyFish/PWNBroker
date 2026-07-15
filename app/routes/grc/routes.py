import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path

from flask import (Blueprint, render_template, redirect, url_for, request,
                   jsonify, flash, current_app, make_response, send_file, abort)
from flask_login import login_required, current_user
from werkzeug.utils import secure_filename

from ...models import (RiskEntry, ComplianceFramework, ComplianceControl,
                       ControlAssessment, Policy, User, Asset, CVEEnrichment,
                       VulnTicket, EvidenceFile)
from ...extensions import db
from ..decorators import admin_required

_ALLOWED_EXTS = {
    ".pdf", ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp",
    ".doc", ".docx", ".xls", ".xlsx", ".csv", ".ppt", ".pptx",
    ".txt", ".log", ".md", ".zip", ".7z",
}
_MAX_MB = 32


def _fmt_size(n):
    if n < 1024:
        return f"{n} B"
    if n < 1024 * 1024:
        return f"{n / 1024:.1f} KB"
    return f"{n / (1024 * 1024):.1f} MB"

grc_bp = Blueprint("grc", __name__, url_prefix="/grc")


def _ensure_seeded():
    from .seed import seed_frameworks
    seed_frameworks(db, ComplianceFramework, ComplianceControl)


# ── Dashboard ─────────────────────────────────────────────────────────────────

@grc_bp.route("/")
@login_required
def index():
    _ensure_seeded()
    risks     = RiskEntry.query.all()
    open_r    = [r for r in risks if r.is_open]
    frameworks = ComplianceFramework.query.all()

    # Compliance summary per framework
    fw_summary = []
    for fw in frameworks:
        total   = fw.controls.count()
        assessed = (db.session.query(ControlAssessment)
                    .join(ComplianceControl)
                    .filter(ComplianceControl.framework_id == fw.id,
                            ControlAssessment.status != "not_assessed")
                    .count())
        compliant = (db.session.query(ControlAssessment)
                     .join(ComplianceControl)
                     .filter(ComplianceControl.framework_id == fw.id,
                             ControlAssessment.status == "compliant")
                     .count())
        fw_summary.append({
            "framework": fw,
            "total":     total,
            "assessed":  assessed,
            "compliant": compliant,
            "pct":       round(compliant / total * 100) if total else 0,
        })

    policies = Policy.query.all()

    # Risk heatmap: count risks per (likelihood, impact) cell
    heatmap = {}
    for r in open_r:
        key = (r.likelihood, r.impact)
        heatmap[key] = heatmap.get(key, 0) + 1

    # EPSS top-risk CVEs
    top_cves = (CVEEnrichment.query
                .filter(CVEEnrichment.epss_score.isnot(None))
                .order_by(CVEEnrichment.epss_score.desc())
                .limit(10).all())

    # ATT&CK tactic coverage: count distinct tactics across all enriched CVEs
    import json
    tactic_counts: dict[str, int] = {}
    for e in CVEEnrichment.query.filter(CVEEnrichment.attack_techniques.isnot(None)).all():
        try:
            techs = json.loads(e.attack_techniques or "[]")
        except Exception:
            techs = []
        for t in techs:
            tac = t.get("tactic", "Unknown")
            tactic_counts[tac] = tactic_counts.get(tac, 0) + 1

    # Enrichment freshness
    enriched_count = CVEEnrichment.query.filter(CVEEnrichment.epss_fetched_at.isnot(None)).count()
    total_cve_count = (VulnTicket.query
                       .with_entities(VulnTicket.cve_id)
                       .filter(VulnTicket.cve_id.isnot(None))
                       .distinct().count())

    return render_template("grc/index.html",
                           risks=risks, open_risks=open_r,
                           fw_summary=fw_summary, policies=policies,
                           heatmap=heatmap,
                           top_cves=top_cves,
                           tactic_counts=tactic_counts,
                           enriched_count=enriched_count,
                           total_cve_count=total_cve_count)


# ── Acceptable Risk ───────────────────────────────────────────────────────────

@grc_bp.route("/risks")
@login_required
def risks():
    _ensure_seeded()
    status_f   = request.args.get("status", "open")
    category_f = request.args.get("category", "")
    q = RiskEntry.query
    if status_f == "open":
        q = q.filter(RiskEntry.status.in_(["open", "in_treatment"]))
    elif status_f != "all":
        q = q.filter_by(status=status_f)
    if category_f:
        q = q.filter_by(category=category_f)
    all_risks = q.order_by(RiskEntry.created_at.desc()).all()
    users  = User.query.order_by(User.username).all()
    assets = Asset.query.order_by(Asset.ip_address).all()
    return render_template("grc/risks.html", risks=all_risks,
                           status_filter=status_f, category_filter=category_f,
                           users=users, assets=assets)


@grc_bp.route("/risks/create", methods=["POST"])
@login_required
@admin_required
def create_risk():
    r = RiskEntry(
        title           = request.form.get("title", "").strip(),
        description     = request.form.get("description", "").strip(),
        category        = request.form.get("category", "technical"),
        likelihood      = int(request.form.get("likelihood", 3)),
        impact          = int(request.form.get("impact", 3)),
        status          = request.form.get("status", "open"),
        owner_id        = request.form.get("owner_id", type=int) or None,
        asset_id        = request.form.get("asset_id", type=int) or None,
        mitigation_plan = request.form.get("mitigation_plan", "").strip(),
        target_date     = _parse_date(request.form.get("target_date", "")),
        created_by      = current_user.id,
    )
    if not r.title:
        flash("Title is required.", "warning")
        return redirect(url_for("grc.risks"))
    db.session.add(r)
    db.session.commit()
    from ...audit import log_action
    log_action("risk.create", entity_type="risk", entity_id=r.id, entity_name=r.title,
               detail=f"Score: {r.risk_score} ({r.risk_level})")
    flash(f"Risk '{r.title}' created.", "success")
    return redirect(url_for("grc.risks"))


@grc_bp.route("/risks/<int:risk_id>/update", methods=["POST"])
@login_required
@admin_required
def update_risk(risk_id):
    r = RiskEntry.query.get_or_404(risk_id)
    r.title            = request.form.get("title", r.title).strip()
    r.description      = request.form.get("description", "").strip()
    r.category         = request.form.get("category", r.category)
    r.likelihood       = int(request.form.get("likelihood", r.likelihood))
    r.impact           = int(request.form.get("impact", r.impact))
    r.status           = request.form.get("status", r.status)
    r.owner_id         = request.form.get("owner_id", type=int) or None
    r.asset_id         = request.form.get("asset_id", type=int) or None
    r.mitigation_plan  = request.form.get("mitigation_plan", "").strip()
    r.target_date      = _parse_date(request.form.get("target_date", ""))
    rl = request.form.get("residual_likelihood", type=int)
    ri = request.form.get("residual_impact", type=int)
    r.residual_likelihood = rl or None
    r.residual_impact     = ri or None
    if r.status in ("mitigated", "closed", "accepted", "transferred") and not r.closed_at:
        r.closed_at = datetime.now(timezone.utc)
    db.session.commit()
    from ...audit import log_action
    log_action("risk.update", entity_type="risk", entity_id=r.id, entity_name=r.title,
               detail=f"Status: {r.status} | Score: {r.risk_score}")
    return jsonify(ok=True, risk_score=r.risk_score, risk_level=r.risk_level, status=r.status)


@grc_bp.route("/risks/<int:risk_id>/delete", methods=["POST"])
@login_required
@admin_required
def delete_risk(risk_id):
    r = RiskEntry.query.get_or_404(risk_id)
    title = r.title
    db.session.delete(r)
    db.session.commit()
    from ...audit import log_action
    log_action("risk.delete", entity_type="risk", entity_id=risk_id, entity_name=title)
    flash("Risk deleted.", "info")
    return redirect(url_for("grc.risks"))


# ── Compliance ────────────────────────────────────────────────────────────────

@grc_bp.route("/compliance")
@login_required
def compliance():
    _ensure_seeded()
    frameworks = ComplianceFramework.query.all()
    summaries  = []
    for fw in frameworks:
        total     = fw.controls.count()
        by_status = {}
        for a in (db.session.query(ControlAssessment)
                  .join(ComplianceControl)
                  .filter(ComplianceControl.framework_id == fw.id).all()):
            by_status[a.status] = by_status.get(a.status, 0) + 1
        compliant = by_status.get("compliant", 0)
        partial   = by_status.get("partial", 0)
        non_c     = by_status.get("non_compliant", 0)
        n_a       = by_status.get("not_applicable", 0)
        assessed  = compliant + partial + non_c + n_a
        summaries.append({
            "framework": fw,
            "total":      total,
            "compliant":  compliant,
            "partial":    partial,
            "non_compliant": non_c,
            "not_applicable": n_a,
            "not_assessed": total - assessed,
            "pct": round(compliant / max(total - n_a, 1) * 100),
        })
    return render_template("grc/compliance.html", summaries=summaries)


@grc_bp.route("/compliance/<int:framework_id>")
@login_required
def framework_detail(framework_id):
    _ensure_seeded()
    fw       = ComplianceFramework.query.get_or_404(framework_id)
    controls = fw.controls.all()
    by_cat = {}
    for c in controls:
        by_cat.setdefault(c.category, []).append(c)
    users = User.query.order_by(User.username).all()
    # Evidence counts per control for badge display
    from sqlalchemy import func
    ev_counts = dict(
        db.session.query(EvidenceFile.control_id, func.count(EvidenceFile.id))
        .filter(EvidenceFile.control_id.in_([c.id for c in controls]))
        .group_by(EvidenceFile.control_id)
        .all()
    )
    return render_template("grc/framework_detail.html",
                           fw=fw, by_cat=by_cat, users=users, ev_counts=ev_counts)


@grc_bp.route("/compliance/assess/<int:control_id>", methods=["POST"])
@login_required
def assess_control(control_id):
    ctrl   = ComplianceControl.query.get_or_404(control_id)
    status = request.form.get("status", "not_assessed")
    notes  = request.form.get("notes", "").strip()
    evidence = request.form.get("evidence", "").strip()

    a = ctrl.assessment
    if not a:
        a = ControlAssessment(control_id=ctrl.id)
        db.session.add(a)
    a.status      = status
    a.notes       = notes
    a.evidence    = evidence
    a.assessed_by = current_user.id
    a.assessed_at = datetime.now(timezone.utc)
    db.session.commit()
    from ...audit import log_action
    log_action("compliance.assess", entity_type="control", entity_id=ctrl.id,
               entity_name=ctrl.control_id,
               detail=f"{ctrl.title[:60]} → {status}")
    return jsonify(ok=True, status=status)


# ── Policies ──────────────────────────────────────────────────────────────────

@grc_bp.route("/policies")
@login_required
def policies():
    _ensure_seeded()
    status_f = request.args.get("status", "")
    q = Policy.query
    if status_f:
        q = q.filter_by(status=status_f)
    all_policies = q.order_by(Policy.title).all()
    users = User.query.order_by(User.username).all()
    return render_template("grc/policies.html",
                           policies=all_policies, status_filter=status_f, users=users)


@grc_bp.route("/policies/create", methods=["POST"])
@login_required
@admin_required
def create_policy():
    p = Policy(
        title       = request.form.get("title", "").strip(),
        category    = request.form.get("category", "general"),
        description = request.form.get("description", "").strip(),
        version     = request.form.get("version", "1.0").strip(),
        status      = request.form.get("status", "draft"),
        owner_id    = request.form.get("owner_id", type=int) or None,
        review_date = _parse_date(request.form.get("review_date", "")),
        created_by  = current_user.id,
    )
    if not p.title:
        flash("Title is required.", "warning")
        return redirect(url_for("grc.policies"))
    db.session.add(p)
    db.session.commit()
    from ...audit import log_action
    log_action("policy.create", entity_type="policy", entity_id=p.id,
               entity_name=p.title, detail=f"Category: {p.category} | Status: {p.status}")
    flash(f"Policy '{p.title}' created. Now write it, upload a document, or apply a template.", "success")
    return redirect(url_for("grc.policy_detail", policy_id=p.id))


@grc_bp.route("/policies/<int:policy_id>/update", methods=["POST"])
@login_required
@admin_required
def update_policy(policy_id):
    p = Policy.query.get_or_404(policy_id)
    p.title       = request.form.get("title", p.title).strip()
    p.category    = request.form.get("category", p.category)
    p.description = request.form.get("description", "").strip()
    p.version     = request.form.get("version", p.version).strip()
    old_status    = p.status
    p.status      = request.form.get("status", p.status)
    p.owner_id    = request.form.get("owner_id", type=int) or None
    p.review_date = _parse_date(request.form.get("review_date", ""))
    p.updated_at  = datetime.now(timezone.utc)
    if p.status == "active" and old_status != "active":
        p.approved_by = current_user.id
        p.approved_at = datetime.now(timezone.utc)
    db.session.commit()
    from ...audit import log_action
    log_action("policy.update", entity_type="policy", entity_id=p.id,
               entity_name=p.title, detail=f"Status: {p.status} | Version: {p.version}")
    return jsonify(ok=True, status=p.status)


@grc_bp.route("/policies/<int:policy_id>/delete", methods=["POST"])
@login_required
@admin_required
def delete_policy(policy_id):
    p = Policy.query.get_or_404(policy_id)
    db.session.delete(p)
    db.session.commit()
    flash("Policy deleted.", "info")
    return redirect(url_for("grc.policies"))


@grc_bp.route("/policies/<int:policy_id>")
@login_required
def policy_detail(policy_id):
    p = Policy.query.get_or_404(policy_id)
    users = User.query.order_by(User.username).all()
    files = EvidenceFile.query.filter_by(policy_id=p.id).order_by(EvidenceFile.uploaded_at.desc()).all()
    return render_template("grc/policy_detail.html", p=p, users=users, files=files)


@grc_bp.route("/policies/<int:policy_id>/content", methods=["POST"])
@login_required
@admin_required
def update_policy_content(policy_id):
    p = Policy.query.get_or_404(policy_id)
    p.content = request.form.get("content", "")
    p.updated_at = datetime.now(timezone.utc)
    db.session.commit()
    from ...audit import log_action
    log_action("policy.content_update", entity_type="policy", entity_id=p.id, entity_name=p.title)
    return jsonify(ok=True)


@grc_bp.route("/policies/<int:policy_id>/export")
@login_required
def export_policy(policy_id):
    p = Policy.query.get_or_404(policy_id)
    fmt = request.args.get("fmt", "pdf").lower()
    safe = "".join(c if c.isalnum() or c in " -_" else "" for c in p.title).strip().replace(" ", "_") or "policy"

    if fmt == "pdf":
        from ...reports.policy_export import generate_policy_pdf
        pdf_bytes = generate_policy_pdf(p)
        resp = make_response(pdf_bytes)
        resp.headers["Content-Type"] = "application/pdf"
        resp.headers["Content-Disposition"] = f'attachment; filename="{safe}.pdf"'
        return resp

    if fmt in ("md", "txt"):
        body = p.content or p.description or ""
        resp = make_response(body)
        resp.headers["Content-Type"] = "text/markdown" if fmt == "md" else "text/plain"
        resp.headers["Content-Disposition"] = f'attachment; filename="{safe}.{fmt}"'
        return resp

    abort(400)


# ── Policy Templates ──────────────────────────────────────────────────────────

@grc_bp.route("/policies/templates")
@login_required
def policy_templates():
    from ...grc.policy_templates import TEMPLATES, categories
    by_cat = {}
    for t in TEMPLATES:
        by_cat.setdefault(t["category"], []).append(t)
    policy_id = request.args.get("policy_id", type=int)
    return render_template("grc/policy_templates.html", by_cat=by_cat, cat_order=categories(),
                           policy_id=policy_id)


@grc_bp.route("/policies/templates/<key>")
@login_required
def policy_template_detail(key):
    from ...grc.policy_templates import get_template, render
    tpl = get_template(key)
    if not tpl:
        abort(404)
    users = User.query.order_by(User.username).all()
    preview = render(tpl["body"])
    policy_id = request.args.get("policy_id", type=int)
    target_policy = Policy.query.get(policy_id) if policy_id else None
    return render_template("grc/policy_template_detail.html", tpl=tpl, users=users, preview=preview,
                           policy_id=policy_id, target_policy=target_policy)


@grc_bp.route("/policies/templates/<key>/generate", methods=["POST"])
@login_required
@admin_required
def generate_policy_from_template(key):
    from ...grc.policy_templates import get_template, render
    tpl = get_template(key)
    if not tpl:
        abort(404)

    company_name = request.form.get("company_name", "").strip()
    owner_id     = request.form.get("owner_id", type=int) or None
    review_cycle = request.form.get("review_cycle", "Annually").strip() or "Annually"
    effective    = request.form.get("effective_date", "").strip()
    review_date  = _parse_date(request.form.get("review_date", ""))
    existing_id  = request.form.get("policy_id", type=int) or None

    owner_name = ""
    if owner_id:
        u = User.query.get(owner_id)
        owner_name = u.username if u else ""

    rendered = render(
        tpl["body"],
        COMPANY_NAME=company_name,
        EFFECTIVE_DATE=effective,
        POLICY_OWNER=owner_name,
        REVIEW_CYCLE=review_cycle,
    )

    from ...audit import log_action

    if existing_id:
        # Apply this template to a policy the user already created, rather than
        # spawning a second, disconnected record.
        p = Policy.query.get_or_404(existing_id)
        if not p.title and company_name:
            p.title = f"{company_name} {tpl['title']}".strip()
        if not p.description:
            p.description = tpl["summary"]
        p.content      = rendered
        p.template_key = tpl["key"]
        if owner_id:
            p.owner_id = owner_id
        if review_date:
            p.review_date = review_date
        p.updated_at = datetime.now(timezone.utc)
        db.session.commit()
        log_action("policy.apply_template", entity_type="policy", entity_id=p.id,
                   entity_name=p.title, detail=f"Template: {tpl['key']}")
        flash(f"Template applied to '{p.title}'. Review and customize it before activating.", "success")
    else:
        p = Policy(
            title        = f"{company_name} {tpl['title']}".strip() if company_name else tpl["title"],
            category     = tpl["category"],
            description  = tpl["summary"],
            content      = rendered,
            template_key = tpl["key"],
            version      = "1.0",
            status       = "draft",
            owner_id     = owner_id,
            review_date  = review_date,
            created_by   = current_user.id,
        )
        db.session.add(p)
        db.session.commit()
        log_action("policy.generate_from_template", entity_type="policy", entity_id=p.id,
                   entity_name=p.title, detail=f"Template: {tpl['key']}")
        flash(f"Policy '{p.title}' generated from template. Review and customize it before activating.", "success")

    return redirect(url_for("grc.policy_detail", policy_id=p.id))


@grc_bp.route("/policies/<int:policy_id>/import", methods=["POST"])
@login_required
@admin_required
def import_policy_document(policy_id):
    """Extract text from an uploaded .docx/.txt/.md file into the policy's
    content, and keep the original file attached as the document of record."""
    p = Policy.query.get_or_404(policy_id)
    f = request.files.get("file")
    if not f or not f.filename:
        flash("Select a .docx, .txt, or .md file to upload.", "warning")
        return redirect(url_for("grc.policy_detail", policy_id=p.id))

    from ...grc.doc_import import SUPPORTED_EXTS, extract_text
    ext = Path(f.filename).suffix.lower()
    if ext not in SUPPORTED_EXTS:
        flash("Unsupported file type. Upload a .docx, .txt, or .md file.", "warning")
        return redirect(url_for("grc.policy_detail", policy_id=p.id))

    data = f.read()
    if len(data) > _MAX_MB * 1024 * 1024:
        flash(f"File exceeds {_MAX_MB} MB limit.", "warning")
        return redirect(url_for("grc.policy_detail", policy_id=p.id))

    try:
        content = extract_text(f.filename, data)
    except Exception:
        flash("Could not read that file — make sure it's a valid .docx, .txt, or .md file.", "danger")
        return redirect(url_for("grc.policy_detail", policy_id=p.id))

    p.content = content
    p.updated_at = datetime.now(timezone.utc)

    stored_name = uuid.uuid4().hex + ext
    upload_dir  = Path(current_app.config["EVIDENCE_UPLOAD_DIR"])
    upload_dir.mkdir(parents=True, exist_ok=True)
    (upload_dir / stored_name).write_bytes(data)
    ev = EvidenceFile(
        policy_id   = p.id,
        filename    = secure_filename(f.filename),
        stored_name = stored_name,
        file_size   = len(data),
        mime_type   = f.mimetype,
        description = "Original uploaded policy document",
        uploaded_by = current_user.id,
    )
    db.session.add(ev)
    db.session.commit()

    from ...audit import log_action
    log_action("policy.import_document", entity_type="policy", entity_id=p.id,
               entity_name=p.title, detail=f"Imported from {f.filename}")
    flash(f"Imported content from {f.filename}.", "success")
    return redirect(url_for("grc.policy_detail", policy_id=p.id))


# ── On-demand enrichment / auto-assess triggers ───────────────────────────────

@grc_bp.route("/enrich/trigger", methods=["POST"])
@login_required
@admin_required
def trigger_enrichment():
    """Kick off CVE enrichment in a background thread."""
    from flask import current_app
    app = current_app._get_current_object()

    def _job():
        from ...grc.enrichment import enrich_all_cves
        try:
            enrich_all_cves(app)
        except Exception as e:
            app.logger.error("On-demand enrichment failed: %s", e)

    t = threading.Thread(target=_job, daemon=True)
    t.start()
    from ...audit import log_action
    log_action("enrichment.trigger", detail="CVE enrichment started manually")
    return jsonify(ok=True, message="CVE enrichment started in background.")


@grc_bp.route("/assess/trigger", methods=["POST"])
@login_required
@admin_required
def trigger_auto_assess():
    """Run compliance auto-assessment immediately."""
    from ...grc.auto_assess import run_auto_assess
    try:
        updated = run_auto_assess()
        from ...audit import log_action
        log_action("assess.trigger", detail=f"Auto-assessment updated {updated} control(s)")
        return jsonify(ok=True, updated=updated)
    except Exception as e:
        return jsonify(ok=False, error=str(e)), 500


# ── Evidence files ────────────────────────────────────────────────────────────

@grc_bp.route("/evidence/list")
@login_required
def evidence_list():
    """Return JSON list of evidence files for a control, framework, or policy."""
    control_id   = request.args.get("control_id",   type=int)
    framework_id = request.args.get("framework_id", type=int)
    policy_id    = request.args.get("policy_id",    type=int)
    if control_id:
        files = EvidenceFile.query.filter_by(control_id=control_id).order_by(EvidenceFile.uploaded_at.desc()).all()
    elif framework_id:
        files = EvidenceFile.query.filter_by(framework_id=framework_id, control_id=None).order_by(EvidenceFile.uploaded_at.desc()).all()
    elif policy_id:
        files = EvidenceFile.query.filter_by(policy_id=policy_id).order_by(EvidenceFile.uploaded_at.desc()).all()
    else:
        return jsonify(ok=False, error="Specify control_id, framework_id, or policy_id"), 400

    return jsonify(ok=True, files=[{
        "id":          f.id,
        "filename":    f.filename,
        "size":        _fmt_size(f.file_size),
        "mime_type":   f.mime_type or "",
        "description": f.description or "",
        "uploaded_at": f.uploaded_at.strftime("%Y-%m-%d %H:%M"),
        "uploader":    f.uploader.username if f.uploader else "system",
    } for f in files])


@grc_bp.route("/evidence/upload", methods=["POST"])
@login_required
@admin_required
def evidence_upload():
    control_id   = request.form.get("control_id",   type=int)
    framework_id = request.form.get("framework_id", type=int)
    policy_id    = request.form.get("policy_id",    type=int)
    description  = request.form.get("description",  "").strip()
    f = request.files.get("file")

    if not f or not f.filename:
        return jsonify(ok=False, error="No file selected"), 400

    ext = Path(f.filename).suffix.lower()
    if ext not in _ALLOWED_EXTS:
        return jsonify(ok=False, error=f"File type '{ext}' is not allowed"), 400

    data = f.read()
    if len(data) > _MAX_MB * 1024 * 1024:
        return jsonify(ok=False, error=f"File exceeds {_MAX_MB} MB limit"), 400

    stored_name = uuid.uuid4().hex + ext
    upload_dir  = Path(current_app.config["EVIDENCE_UPLOAD_DIR"])
    upload_dir.mkdir(parents=True, exist_ok=True)
    (upload_dir / stored_name).write_bytes(data)

    ev = EvidenceFile(
        framework_id = framework_id,
        control_id   = control_id,
        policy_id    = policy_id,
        filename     = secure_filename(f.filename),
        stored_name  = stored_name,
        file_size    = len(data),
        mime_type    = f.mimetype or "application/octet-stream",
        description  = description,
        uploaded_by  = current_user.id,
    )
    db.session.add(ev)
    db.session.commit()

    from ...audit import log_action
    target = f"control {control_id}" if control_id else f"framework {framework_id}"
    log_action("evidence.upload", entity_type="evidence", entity_id=ev.id,
               entity_name=ev.filename, detail=f"Attached to {target}")

    return jsonify(ok=True, id=ev.id, filename=ev.filename,
                   size=_fmt_size(ev.file_size), mime_type=ev.mime_type or "",
                   description=ev.description or "",
                   uploaded_at=ev.uploaded_at.strftime("%Y-%m-%d %H:%M"),
                   uploader=current_user.username)


@grc_bp.route("/evidence/<int:ev_id>/download")
@login_required
def evidence_download(ev_id):
    ev   = EvidenceFile.query.get_or_404(ev_id)
    path = Path(current_app.config["EVIDENCE_UPLOAD_DIR"]) / ev.stored_name
    if not path.exists():
        abort(404)
    return send_file(path, as_attachment=True, download_name=ev.filename,
                     mimetype=ev.mime_type or "application/octet-stream")


@grc_bp.route("/evidence/<int:ev_id>/delete", methods=["POST"])
@login_required
@admin_required
def evidence_delete(ev_id):
    ev = EvidenceFile.query.get_or_404(ev_id)
    path = Path(current_app.config["EVIDENCE_UPLOAD_DIR"]) / ev.stored_name
    try:
        path.unlink(missing_ok=True)
    except Exception:
        pass
    name = ev.filename
    db.session.delete(ev)
    db.session.commit()
    from ...audit import log_action
    log_action("evidence.delete", entity_type="evidence", entity_id=ev_id, entity_name=name)
    return jsonify(ok=True)


# ── Audit report ──────────────────────────────────────────────────────────────

@grc_bp.route("/compliance/<int:framework_id>/report")
@login_required
def compliance_report(framework_id):
    fw = ComplianceFramework.query.get_or_404(framework_id)
    controls = fw.controls.all()

    by_cat = {}
    for c in controls:
        by_cat.setdefault(c.category, []).append(c)

    # Build evidence lookup by control id
    all_evidence = EvidenceFile.query.filter(
        EvidenceFile.control_id.in_([c.id for c in controls])
    ).all()
    evidence_by_control = {}
    for ev in all_evidence:
        evidence_by_control.setdefault(ev.control_id, []).append(ev)

    from ...reports.compliance_report import generate_compliance_pdf
    pdf_bytes = generate_compliance_pdf(fw, by_cat, evidence_by_control)

    safe = (fw.short_name or fw.name).replace(" ", "_")
    filename = f"audit_{safe}_{datetime.now(timezone.utc).strftime('%Y%m%d')}.pdf"

    resp = make_response(pdf_bytes)
    resp.headers["Content-Type"]        = "application/pdf"
    resp.headers["Content-Disposition"] = f'attachment; filename="{filename}"'
    return resp


# ── Helpers ───────────────────────────────────────────────────────────────────

def _parse_date(s):
    if not s:
        return None
    try:
        return datetime.strptime(s, "%Y-%m-%d").replace(tzinfo=timezone.utc)
    except ValueError:
        return None
