def test_login_page_loads(client):
    r = client.get("/login")
    assert r.status_code == 200


def test_login_failure(client):
    r = client.post("/login", data={"username": "admin", "password": "wrong"})
    assert r.status_code == 200
    assert b"Invalid username or password" in r.data


def test_login_success_forces_password_change(client):
    r = client.post("/login", data={"username": "admin", "password": "admin"},
                     follow_redirects=True)
    assert r.status_code == 200
    assert "/users/profile" in r.request.path


def test_forced_password_change_blocks_navigation(client):
    client.post("/login", data={"username": "admin", "password": "admin"})
    r = client.get("/targets/", follow_redirects=True)
    assert "/users/profile" in r.request.path


def test_password_change_clears_forced_flag(app, client):
    client.post("/login", data={"username": "admin", "password": "admin"})
    r = client.post("/users/profile", data={
        "email": "admin@localhost",
        "current_password": "admin",
        "new_password": "NewSecurePW123!",
    }, follow_redirects=True)
    assert r.status_code == 200

    with app.app_context():
        from app.models import User
        admin = User.query.filter_by(username="admin").first()
        assert admin.must_change_password is False

    r = client.get("/targets/", follow_redirects=True)
    assert "/targets/" in r.request.path


def test_login_rate_limited_after_repeated_failures(tmp_path):
    # Rate limiting needs its own app instance created with RATELIMIT_ENABLED
    # already True — Flask-Limiter reads this once at init, not per-request.
    from config import Config
    from app import create_app

    class _RateLimitedConfig(Config):
        TESTING = True
        WTF_CSRF_ENABLED = False
        RATELIMIT_ENABLED = True
        SESSION_COOKIE_SECURE = False

    _RateLimitedConfig.SQLALCHEMY_DATABASE_URI = f"sqlite:///{tmp_path / 'ratelimit.db'}"
    app = create_app(_RateLimitedConfig)
    client = app.test_client()

    statuses = [
        client.post("/login", data={"username": "admin", "password": "wrong"}).status_code
        for _ in range(10)
    ]
    assert 429 in statuses
