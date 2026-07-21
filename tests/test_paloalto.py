import re
from datetime import datetime, timezone
from unittest.mock import patch


def _csrf_token(client, path="/threat/paloalto"):
    r = client.get(path)
    return re.search(r'name="csrf-token" content="([^"]+)"', r.data.decode()).group(1)


def test_add_list_detail_delete_firewall(app, admin_client):
    token = _csrf_token(admin_client)
    r = admin_client.post("/threat/paloalto/add", data={
        "name": "TestFW", "hostname": "198.51.100.5", "verify_ssl": "1",
        "api_key": "fake-key", "csrf_token": token,
    }, follow_redirects=True)
    assert r.status_code == 200
    assert b"TestFW" in r.data

    with app.app_context():
        from app.models import PaloAltoFirewall
        fw = PaloAltoFirewall.query.filter_by(name="TestFW").first()
        assert fw is not None
        fw_id = fw.id

    r = admin_client.get(f"/threat/paloalto/{fw_id}")
    assert r.status_code == 200

    token2 = _csrf_token(admin_client, f"/threat/paloalto/{fw_id}")
    r = admin_client.post(f"/threat/paloalto/{fw_id}/delete",
                          data={"csrf_token": token2}, follow_redirects=True)
    assert r.status_code == 200
    with app.app_context():
        from app.models import PaloAltoFirewall
        assert PaloAltoFirewall.query.filter_by(name="TestFW").first() is None


def test_invalid_hostname_rejected(admin_client):
    token = _csrf_token(admin_client)
    r = admin_client.post("/threat/paloalto/add", data={
        "name": "BadFW", "hostname": "; rm -rf /", "api_key": "x", "csrf_token": token,
    }, follow_redirects=True)
    assert b"BadFW" not in r.data


def test_credentials_encrypted_at_rest(app, admin_client):
    from sqlalchemy import text
    from app.extensions import db

    token = _csrf_token(admin_client)
    admin_client.post("/threat/paloalto/add", data={
        "name": "EncFW", "hostname": "198.51.100.6", "verify_ssl": "1",
        "api_key": "super-secret-value", "csrf_token": token,
    }, follow_redirects=True)

    with app.app_context():
        raw = db.session.execute(
            text("SELECT api_key FROM paloalto_firewalls WHERE hostname='198.51.100.6'")
        ).scalar()
        assert raw.startswith("enc:v1:")

        from app.models import PaloAltoFirewall
        fw = PaloAltoFirewall.query.filter_by(hostname="198.51.100.6").first()
        assert fw.api_key == "super-secret-value"


def test_ingestion_auto_triages_public_source_ip(app, admin_client):
    from app.extensions import db
    from app.models import PaloAltoFirewall, SocCase

    with app.app_context():
        fw = PaloAltoFirewall(name="SimFW", hostname="198.51.100.9",
                              api_key="fake", verify_ssl=True)
        db.session.add(fw)
        db.session.commit()
        fw_id = fw.id

    fake_entry = {
        "seqno": 1,
        "time_generated": datetime.now(timezone.utc).replace(microsecond=0),
        "src_ip": "45.33.32.156", "src_port": 4444,
        "dst_ip": "10.0.0.5", "dst_port": 443,
        "nat_src_ip": None, "nat_dst_ip": None,
        "rule_name": "Allow-Outbound", "application": "ssl",
        "threat_name": "Test.Trojan.Gen", "threat_id": "1",
        "category": "command-and-control", "subtype": "spyware",
        "severity": "critical", "action": "reset-both",
        "from_zone": "untrust", "to_zone": "trust",
        "inbound_if": "ethernet1/3", "outbound_if": None,
        "direction": "client-to-server", "raw_xml": "<entry/>",
    }

    with app.app_context():
        from app.models import PaloAltoFirewall as _FW
        from app.scheduler.jobs import poll_paloalto_firewall
        fw = _FW.query.get(fw_id)
        with patch("app.threat.paloalto.query_threat_logs",
                   return_value={"logs": [fake_entry], "count": 1}):
            poll_paloalto_firewall(fw)

        case = SocCase.query.filter_by(ioc="45.33.32.156", status="pending").first()
        assert case is not None
        assert case.verdict == "malicious"
        assert "PaloAlto" in case.flagging_sources

        # the private dst_ip should not get a case of its own
        assert SocCase.query.filter_by(ioc="10.0.0.5").first() is None
