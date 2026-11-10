from flask import Blueprint, current_app, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required

from .. import licensing
from ..audit import log_action

license_bp = Blueprint("license", __name__, url_prefix="/license")


@license_bp.route("/")
@login_required
def index():
    return render_template(
        "license/index.html",
        st=licensing.status(current_app),
        install_id=licensing.install_id(current_app),
    )


@license_bp.route("/", methods=["POST"])
@login_required
def upload():
    if not current_user.is_admin:
        flash("Only an administrator can install a license.", "danger")
        return redirect(url_for("license.index"))

    f = request.files.get("license_file")
    text = request.form.get("license_text", "")
    if f and f.filename:
        raw = f.read(64 * 1024)
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            text = ""
    if not text.strip():
        flash("Choose a license file or paste the license text.", "warning")
        return redirect(url_for("license.index"))

    try:
        payload = licensing.install_license(text, current_app)
    except licensing.LicenseError as e:
        flash(str(e), "danger")
        return redirect(url_for("license.index"))

    log_action("license.install", entity_type="license",
               entity_name=payload["customer"],
               detail=f"License {payload.get('license_id')} installed, expires {payload['expires']}")
    flash(f"License installed — licensed to {payload['customer']} through {payload['expires']}.", "success")
    return redirect(url_for("license.index"))
