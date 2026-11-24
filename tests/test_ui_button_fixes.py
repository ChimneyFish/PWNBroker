"""Regressions for buttons that looked like they worked but did the wrong thing
(found by clicking through every page of the app)."""
import pytest

from app.extensions import db


def _policy(app, **kw):
    from app.models import Policy
    with app.app_context():
        p = Policy(title="Acceptable Use", description="Who may use company systems and how.",
                   version="1.0", status="draft", **kw)
        db.session.add(p)
        db.session.commit()
        return p.id


def test_policy_edit_save_keeps_description(app, admin_client):
    """GRC > Policies > Edit > Save sends status/version/owner/review only —
    it used to blank the policy's description every time."""
    from app.models import Policy
    pid = _policy(app)
    r = admin_client.post(f"/grc/policies/{pid}/update",
                          data={"status": "active", "version": "1.1", "owner_id": "", "review_date": ""})
    assert r.get_json() == {"ok": True, "status": "active"}
    with app.app_context():
        p = db.session.get(Policy, pid)
        assert p.description == "Who may use company systems and how."
        assert p.version == "1.1" and p.status == "active"


def test_policy_update_still_sets_description_when_sent(app, admin_client):
    from app.models import Policy
    pid = _policy(app)
    admin_client.post(f"/grc/policies/{pid}/update", data={"description": "  New text  "})
    with app.app_context():
        assert db.session.get(Policy, pid).description == "New text"


@pytest.mark.parametrize("url,ttype", [("/backdoor/new", "local_path"), ("/bloodhound/new", "ad_domain")])
def test_start_scan_explains_missing_targets(app, admin_client, url, ttype):
    """With no eligible targets the required dropdown is empty, so Start Scan
    only produced a browser 'select an item' bubble — looked dead."""
    html = admin_client.get(url).get_data(as_text=True)
    assert 'id="no-targets"' in html
    assert '<button type="button" class="btn btn-primary" disabled' in html
    assert '<button type="submit" class="btn btn-primary">' not in html

    from app.models import Target
    with app.app_context():
        db.session.add(Target(name="eligible", host="/srv/code" if ttype == "local_path" else "corp.local",
                              target_type=ttype))
        db.session.commit()
    html = admin_client.get(url).get_data(as_text=True)
    assert 'id="no-targets"' not in html
    assert '<button type="submit" class="btn btn-primary">' in html
