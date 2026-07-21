from app import crypto


def test_encrypt_decrypt_roundtrip(app):
    with app.app_context():
        encrypted = crypto.encrypt("hello-secret")
        assert encrypted != "hello-secret"
        assert encrypted.startswith("enc:v1:")
        assert crypto.decrypt(encrypted) == "hello-secret"


def test_encrypt_is_idempotent(app):
    with app.app_context():
        once = crypto.encrypt("some-api-key")
        twice = crypto.encrypt(once)
        assert once == twice


def test_encrypt_decrypt_noop_for_empty_values(app):
    with app.app_context():
        assert crypto.encrypt(None) is None
        assert crypto.encrypt("") == ""
        assert crypto.decrypt(None) is None
        assert crypto.decrypt("") == ""


def test_decrypt_passes_through_legacy_plaintext(app):
    with app.app_context():
        assert crypto.decrypt("plain-old-value") == "plain-old-value"
