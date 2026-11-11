"""Settings → Updates. The web app never updates itself: it only writes
settings/request files into data/, which the root-run updater
(updater/pwnbroker_updater.py, via pwnbroker-updater.path/.timer) acts on."""
import json
import os
import tarfile

from flask import Blueprint, current_app, flash, redirect, render_template, request, url_for
from flask_login import login_required

from ..audit import log_action
from ..version import __version__
from .decorators import admin_required

updates_bp = Blueprint("updates", __name__, url_prefix="/updates")

CHANNELS = ("stable", "beta")
UPDATER_UNIT = "/etc/systemd/system/pwnbroker-updater.timer"


def _data_dir():
    return current_app.config.get("UPDATE_DATA_DIR") or os.path.join(
        os.path.dirname(current_app.root_path), "data")


def _read(name, default):
    try:
        with open(os.path.join(_data_dir(), name)) as f:
            return json.load(f)
    except (FileNotFoundError, ValueError):
        return default


def _write(name, obj):
    path = os.path.join(_data_dir(), name)
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(obj, f)
    os.replace(tmp, path)


def _settings():
    s = {"auto_update": True, "channel": "stable", "window_start": 2, "window_end": 5}
    s.update({k: v for k, v in _read("update_settings.json", {}).items() if k in s})
    return s


def _request(action):
    _write("update_request.json", {"action": action})


@updates_bp.route("/")
@login_required
@admin_required
def index():
    return render_template(
        "updates/index.html",
        version=__version__,
        st=_read("update_status.json", {}),
        settings=_settings(),
        pending=_read("update_request.json", None),
        updater_installed=os.path.exists(current_app.config.get("UPDATER_UNIT", UPDATER_UNIT)),
    )


@updates_bp.route("/settings", methods=["POST"])
@login_required
@admin_required
def save_settings():
    def hour(name, default):
        try:
            v = int(request.form.get(name, default))
        except ValueError:
            v = default
        return min(max(v, 0), 23)

    s = {
        "auto_update": request.form.get("auto_update") == "on",
        "channel": request.form.get("channel") if request.form.get("channel") in CHANNELS else "stable",
        "window_start": hour("window_start", 2),
        "window_end": hour("window_end", 5),
    }
    _write("update_settings.json", s)
    log_action("updates.settings", detail=json.dumps(s))
    flash("Update settings saved.", "success")
    return redirect(url_for("updates.index"))


@updates_bp.route("/check", methods=["POST"])
@login_required
@admin_required
def check():
    _request("check")
    flash("Checking for updates — this page will show the result in a few seconds.", "info")
    return redirect(url_for("updates.index"))


@updates_bp.route("/install", methods=["POST"])
@login_required
@admin_required
def install():
    _request("install")
    log_action("updates.install", detail="Install of latest release requested")
    flash("Update requested. PWNBroker will restart in a minute or two; running scans will be interrupted.", "warning")
    return redirect(url_for("updates.index"))


@updates_bp.route("/offline", methods=["POST"])
@login_required
@admin_required
def offline():
    f = request.files.get("bundle")
    if not f or not f.filename:
        flash("Choose a .pwnupdate file.", "warning")
        return redirect(url_for("updates.index"))
    dest = os.path.join(_data_dir(), "update_offline.pwnupdate")
    f.save(dest)
    # Cheap sanity check only; the updater verifies the signature before installing.
    try:
        with tarfile.open(dest) as t:
            ok = {"manifest.json", "manifest.sig"} <= set(t.getnames())
    except (tarfile.TarError, OSError):
        ok = False
    if not ok:
        os.remove(dest)
        flash("That isn't a PWNBroker update bundle.", "danger")
        return redirect(url_for("updates.index"))
    _request("install_offline")
    log_action("updates.offline", detail=f"Offline update bundle uploaded: {f.filename}")
    flash("Update bundle uploaded. It will be verified and installed in a minute or two.", "warning")
    return redirect(url_for("updates.index"))
