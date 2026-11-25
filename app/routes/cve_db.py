"""CVE Database — the local NVD + CVE.org mirror scans pull from."""
import json
import threading

from flask import Blueprint, abort, current_app, flash, jsonify, redirect, render_template, request, url_for
from flask_login import login_required

from ..cve_mirror import query
from .decorators import admin_required

cve_db_bp = Blueprint("cve_db", __name__, url_prefix="/cve-db")


def _status_payload():
    from ..cve_mirror.sync import progress_snapshot
    s = query.stats()
    src = {}
    for name in ("nvd", "cveorg", "msrc"):
        st = s["sources"].get(name)
        src[name] = {
            "status": st.status if st else "never",
            "message": st.message if st else "",
            "records": st.records if st else 0,
            "last_sync_at": st.last_sync_at.isoformat() + "Z" if st and st.last_sync_at else None,
            "last_full_at": st.last_full_at.isoformat() + "Z" if st and st.last_full_at else None,
        }
    return {"ready": s["ready"], "total": s["total"], "rejected": s["rejected"],
            "nvd_backlog": s["nvd_backlog"], "cpe_rows": s["cpe_rows"],
            "newest": str(s["newest"]) if s["newest"] else None,
            "sources": src, "progress": progress_snapshot()}


@cve_db_bp.route("/")
@login_required
def index():
    q = request.args.get("q", "").strip()
    results = query.search(q) if q else []
    return render_template("cve_db/index.html", st=_status_payload(), q=q, results=results)


@cve_db_bp.route("/status.json")
@login_required
def status_json():
    return jsonify(_status_payload())


@cve_db_bp.route("/cve/<cve_id>")
@login_required
def detail(cve_id):
    r = query.get_cve(cve_id)
    if not r:
        abort(404)
    from ..extensions import db
    from ..models import MirrorCpeMatch
    matches = (db.session.query(MirrorCpeMatch).filter_by(cve_id=r["cve_id"])
               .order_by(MirrorCpeMatch.source, MirrorCpeMatch.vendor, MirrorCpeMatch.product).limit(500).all())
    try:
        cwes = json.loads(r.get("cwe_ids") or "[]")
    except ValueError:
        cwes = []
    return render_template("cve_db/detail.html", r=r, matches=matches, cwes=cwes,
                           refs=query.references(r))


@cve_db_bp.route("/sync", methods=["POST"])
@login_required
@admin_required
def sync():
    from ..cve_mirror.sync import run_sync, SyncBusy
    full = request.form.get("full") == "1"
    app = current_app._get_current_object()

    def _worker():
        try:
            run_sync(app, full=full)
        except SyncBusy:
            pass
        except Exception as e:
            app.logger.error("Manual CVE mirror sync failed: %s", e)

    threading.Thread(target=_worker, name="cve-mirror-sync", daemon=True).start()
    flash(("Full re-download" if full else "Sync") + " of the CVE database started — "
          "this page updates as it runs.", "info")
    return redirect(url_for("cve_db.index"))
