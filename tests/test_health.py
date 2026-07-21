def test_healthz_ok(client):
    r = client.get("/healthz")
    assert r.status_code == 200
    assert r.get_json()["status"] == "ok"


def test_404_page(client):
    r = client.get("/this-does-not-exist")
    assert r.status_code == 404
