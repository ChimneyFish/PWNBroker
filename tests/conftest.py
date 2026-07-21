import os
os.environ.setdefault("SECRET_KEY", "test-secret-key-not-for-production")

import pytest
from config import Config
from app import create_app
from app.extensions import db as _db


class TestConfig(Config):
    TESTING = True
    WTF_CSRF_ENABLED = False
    RATELIMIT_ENABLED = False
    SESSION_COOKIE_SECURE = False


@pytest.fixture()
def app(tmp_path):
    TestConfig.SQLALCHEMY_DATABASE_URI = f"sqlite:///{tmp_path / 'test.db'}"
    application = create_app(TestConfig)
    yield application


@pytest.fixture()
def client(app):
    return app.test_client()


@pytest.fixture()
def admin_client(app, client):
    """A client logged in as the seeded admin, with the forced first-login
    password change already satisfied so tests can navigate anywhere."""
    with app.app_context():
        from app.models import User
        admin = User.query.filter_by(username="admin").first()
        admin.must_change_password = False
        _db.session.commit()
    client.post("/login", data={"username": "admin", "password": "admin"})
    return client
