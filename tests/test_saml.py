"""SAML tests mock python3-saml's OneLogin_Saml2_Auth for the ACS-flow tests
— there's no real IdP available in this environment, so these verify the
app's own domain-gating/provisioning/email-resolution logic, not the XML
signature validation itself (that's python3-saml's job). The metadata-parsing
test below exercises the real parser against a hand-written fixture, since
that doesn't require a network call or a live IdP."""
from unittest.mock import patch, MagicMock

_EMAIL_CLAIM = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"
_UPN_CLAIM = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name"


def _configure_saml(app, allowed_domains="example.com", auto_provision=True, saml_enabled=True):
    from app.extensions import db
    from app.models import SSOConfig
    with app.app_context():
        cfg = SSOConfig(
            saml_enabled=saml_enabled,
            saml_idp_entity_id="https://sts.windows.net/tenant-guid/",
            saml_idp_sso_url="https://login.microsoftonline.com/tenant-guid/saml2",
            saml_idp_x509_cert="FAKECERT",
            allowed_domains=allowed_domains, auto_provision=auto_provision,
        )
        db.session.add(cfg)
        db.session.commit()


def _mock_auth(nameid, errors=None, authenticated=True, attrs=None):
    auth = MagicMock()
    auth.process_response.return_value = None
    auth.get_errors.return_value = errors or []
    auth.is_authenticated.return_value = authenticated
    auth.get_nameid.return_value = nameid
    auth.get_attributes.return_value = attrs or {}
    return auth


def test_domain_not_allowed_is_rejected(app, client):
    _configure_saml(app, allowed_domains="example.com")
    with patch("app.routes.auth.OneLogin_Saml2_Auth", return_value=_mock_auth("someone@evil.com")):
        r = client.post("/login/sso/saml/acs", follow_redirects=True)
    assert "/login" in r.request.path
    with app.app_context():
        from app.models import User
        assert User.query.filter_by(email="someone@evil.com").first() is None


def test_allowed_domain_auto_provisions_new_user(app, client):
    _configure_saml(app, allowed_domains="example.com", auto_provision=True)
    with patch("app.routes.auth.OneLogin_Saml2_Auth", return_value=_mock_auth("newhire@example.com")):
        r = client.post("/login/sso/saml/acs", follow_redirects=True)
    assert r.status_code == 200
    with app.app_context():
        from app.models import User
        u = User.query.filter_by(email="newhire@example.com").first()
        assert u is not None
        assert u.role == "user"


def test_auto_provision_disabled_requires_existing_account(app, client):
    _configure_saml(app, allowed_domains="example.com", auto_provision=False)
    with patch("app.routes.auth.OneLogin_Saml2_Auth", return_value=_mock_auth("nosuchuser@example.com")):
        r = client.post("/login/sso/saml/acs", follow_redirects=True)
    assert "/login" in r.request.path
    with app.app_context():
        from app.models import User
        assert User.query.filter_by(email="nosuchuser@example.com").first() is None


def test_existing_account_logs_in_via_saml_without_provisioning(app, client):
    from app.extensions import db
    from app.models import User
    with app.app_context():
        u = User(username="existing", email="existing@example.com", role="user")
        u.set_password("whatever")
        db.session.add(u)
        db.session.commit()

    _configure_saml(app, allowed_domains="example.com", auto_provision=False)
    with patch("app.routes.auth.OneLogin_Saml2_Auth", return_value=_mock_auth("existing@example.com")):
        r = client.post("/login/sso/saml/acs", follow_redirects=True)
    assert r.status_code == 200
    assert "/login" not in r.request.path


def test_empty_allowed_domains_never_auto_provisions(app, client):
    """An empty allowlist must never silently mean 'allow everyone' —
    same invariant as the OIDC SSO path, reused here via the shared
    _finish_sso_login helper."""
    _configure_saml(app, allowed_domains="", auto_provision=True)
    with patch("app.routes.auth.OneLogin_Saml2_Auth", return_value=_mock_auth("anyone@anywhere.com")):
        r = client.post("/login/sso/saml/acs", follow_redirects=True)
    assert "/login" in r.request.path
    with app.app_context():
        from app.models import User
        assert User.query.filter_by(email="anyone@anywhere.com").first() is None


def test_disabled_saml_redirects_to_login(client):
    r = client.get("/login/sso/saml", follow_redirects=True)
    assert "/login" in r.request.path
    r2 = client.post("/login/sso/saml/acs", follow_redirects=True)
    assert "/login" in r2.request.path


def test_saml_errors_reject_login(app, client):
    _configure_saml(app, allowed_domains="example.com")
    with patch("app.routes.auth.OneLogin_Saml2_Auth",
               return_value=_mock_auth("someone@example.com", errors=["signature_error"])):
        r = client.post("/login/sso/saml/acs", follow_redirects=True)
    assert "/login" in r.request.path
    with app.app_context():
        from app.models import User
        assert User.query.filter_by(email="someone@example.com").first() is None


def test_not_authenticated_rejects_login(app, client):
    _configure_saml(app, allowed_domains="example.com")
    with patch("app.routes.auth.OneLogin_Saml2_Auth",
               return_value=_mock_auth("someone@example.com", authenticated=False)):
        r = client.post("/login/sso/saml/acs", follow_redirects=True)
    assert "/login" in r.request.path


def test_email_claim_preferred_over_ambiguous_nameid(app, client):
    """NameID and the UPN claim are both syntactically email-shaped whether
    or not they're the user's real email — the explicit emailaddress claim
    must win when present."""
    _configure_saml(app, allowed_domains="example.com", auto_provision=True)
    auth = _mock_auth("someuser@tenant.onmicrosoft.com",
                       attrs={_EMAIL_CLAIM: ["realuser@example.com"]})
    with patch("app.routes.auth.OneLogin_Saml2_Auth", return_value=auth):
        r = client.post("/login/sso/saml/acs", follow_redirects=True)
    assert r.status_code == 200
    with app.app_context():
        from app.models import User
        assert User.query.filter_by(email="realuser@example.com").first() is not None
        assert User.query.filter_by(email="someuser@tenant.onmicrosoft.com").first() is None


def test_upn_claim_used_when_nameid_and_email_claim_absent(app, client):
    _configure_saml(app, allowed_domains="example.com", auto_provision=True)
    auth = _mock_auth("", attrs={_UPN_CLAIM: ["fallback@example.com"]})
    with patch("app.routes.auth.OneLogin_Saml2_Auth", return_value=auth):
        r = client.post("/login/sso/saml/acs", follow_redirects=True)
    assert r.status_code == 200
    with app.app_context():
        from app.models import User
        assert User.query.filter_by(email="fallback@example.com").first() is not None


def test_no_resolvable_email_rejects_with_guidance(app, client):
    _configure_saml(app, allowed_domains="example.com")
    with patch("app.routes.auth.OneLogin_Saml2_Auth", return_value=_mock_auth("not-an-email-nameid")):
        r = client.post("/login/sso/saml/acs", follow_redirects=True)
    assert "/login" in r.request.path


def test_metadata_endpoint_is_public_and_well_formed(client):
    r = client.get("/login/sso/saml/metadata")
    assert r.status_code == 200
    assert "xml" in r.content_type
    assert b"saml/acs" in r.data


def test_idp_metadata_parser_maps_onto_config_fields():
    """Exercises the real onelogin parser (no mock, no network) against a
    hand-written minimal IdP metadata fixture, to verify the settings-route
    mapping code (settings.py's upload_saml_metadata) will see the shape it
    expects — including the x509certMulti.signing list Entra typically uses."""
    from onelogin.saml2.idp_metadata_parser import OneLogin_Saml2_IdPMetadataParser

    fixture = b"""<?xml version="1.0"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata"
                   xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
                   entityID="https://sts.windows.net/tenant-guid/">
  <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <KeyDescriptor use="signing">
      <ds:KeyInfo>
        <ds:X509Data>
          <ds:X509Certificate>MIICfakecertificatedataforfixtureonly==</ds:X509Certificate>
        </ds:X509Data>
      </ds:KeyInfo>
    </KeyDescriptor>
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
                          Location="https://login.microsoftonline.com/tenant-guid/saml2"/>
  </IDPSSODescriptor>
</EntityDescriptor>"""

    parsed = OneLogin_Saml2_IdPMetadataParser.parse(fixture)
    idp = parsed["idp"]
    assert idp["entityId"] == "https://sts.windows.net/tenant-guid/"
    assert idp["singleSignOnService"]["url"] == "https://login.microsoftonline.com/tenant-guid/saml2"
    cert = (idp.get("x509certMulti") or {}).get("signing", [None])[0] or idp.get("x509cert")
    assert cert == "MIICfakecertificatedataforfixtureonly=="


def test_upload_metadata_requires_admin(client):
    r = client.post("/settings/sso/saml/metadata", data={}, follow_redirects=True)
    assert "/login" in r.request.path


def test_upload_metadata_saves_parsed_config(admin_client, app):
    fixture = b"""<?xml version="1.0"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata"
                   xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
                   entityID="https://sts.windows.net/tenant-guid/">
  <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <KeyDescriptor use="signing">
      <ds:KeyInfo>
        <ds:X509Data>
          <ds:X509Certificate>MIICfakecertificatedataforfixtureonly==</ds:X509Certificate>
        </ds:X509Data>
      </ds:KeyInfo>
    </KeyDescriptor>
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
                          Location="https://login.microsoftonline.com/tenant-guid/saml2"/>
  </IDPSSODescriptor>
</EntityDescriptor>"""
    from io import BytesIO
    r = admin_client.post(
        "/settings/sso/saml/metadata",
        data={"metadata_file": (BytesIO(fixture), "metadata.xml")},
        content_type="multipart/form-data",
        follow_redirects=True,
    )
    assert r.status_code == 200
    with app.app_context():
        from app.models import SSOConfig
        cfg = SSOConfig.query.first()
        assert cfg.saml_idp_entity_id == "https://sts.windows.net/tenant-guid/"
        assert cfg.saml_idp_sso_url == "https://login.microsoftonline.com/tenant-guid/saml2"
        assert cfg.saml_idp_x509_cert == "MIICfakecertificatedataforfixtureonly=="
