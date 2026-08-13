"""Tests for the CISA KEV catalog integration (app/grc/enrichment.py).

No network access is used — refresh_kev_cache() has its HTTP session
mocked out, and build_kev_index()/get_kev_index() are exercised against a
fixture file written directly to a tmp path.
"""
import json
from unittest.mock import MagicMock, patch

from app.grc import enrichment


_SAMPLE_CATALOG = {
    "vulnerabilities": [
        {
            "cveID": "CVE-2024-9999",
            "dateAdded": "2024-06-01",
            "dueDate": "2024-06-22",
            "knownRansomwareCampaignUse": "Known",
        },
        {
            "cveID": "cve-2024-1111",  # lowercase in the wild — index should normalize
            "dateAdded": "2024-01-15",
            "dueDate": "",
            "knownRansomwareCampaignUse": "Unknown",
        },
    ]
}


def test_build_kev_index_parses_fields(tmp_path, monkeypatch):
    cache = tmp_path / "cisa_kev.json"
    cache.write_text(json.dumps(_SAMPLE_CATALOG))
    monkeypatch.setattr(enrichment, "_KEV_CACHE", str(cache))

    index = enrichment.build_kev_index()

    assert set(index) == {"CVE-2024-9999", "CVE-2024-1111"}
    entry = index["CVE-2024-9999"]
    assert entry["date_added"].strftime("%Y-%m-%d") == "2024-06-01"
    assert entry["due_date"].strftime("%Y-%m-%d") == "2024-06-22"
    assert entry["ransomware"] is True

    entry2 = index["CVE-2024-1111"]
    assert entry2["due_date"] is None
    assert entry2["ransomware"] is False


def test_build_kev_index_missing_cache_returns_empty(tmp_path, monkeypatch):
    monkeypatch.setattr(enrichment, "_KEV_CACHE", str(tmp_path / "does_not_exist.json"))
    assert enrichment.build_kev_index() == {}


def test_build_kev_index_skips_entries_without_cve_id(tmp_path, monkeypatch):
    cache = tmp_path / "cisa_kev.json"
    cache.write_text(json.dumps({"vulnerabilities": [{"dateAdded": "2024-01-01"}]}))
    monkeypatch.setattr(enrichment, "_KEV_CACHE", str(cache))
    assert enrichment.build_kev_index() == {}


def test_refresh_kev_cache_writes_response_to_disk(tmp_path, monkeypatch):
    cache = tmp_path / "nested" / "cisa_kev.json"
    monkeypatch.setattr(enrichment, "_KEV_CACHE", str(cache))

    fake_resp = MagicMock()
    fake_resp.text = json.dumps(_SAMPLE_CATALOG)
    fake_resp.raise_for_status = MagicMock()
    with patch.object(enrichment._SESSION, "get", return_value=fake_resp) as mock_get:
        assert enrichment.refresh_kev_cache() is True

    mock_get.assert_called_once()
    assert json.loads(cache.read_text()) == _SAMPLE_CATALOG


def test_refresh_kev_cache_returns_false_on_request_failure(tmp_path, monkeypatch):
    monkeypatch.setattr(enrichment, "_KEV_CACHE", str(tmp_path / "cisa_kev.json"))
    with patch.object(enrichment._SESSION, "get", side_effect=Exception("network down")):
        assert enrichment.refresh_kev_cache() is False


def test_get_kev_index_skips_refresh_when_cache_is_fresh(monkeypatch):
    monkeypatch.setattr(enrichment, "_kev_cache_fresh", lambda: True)
    monkeypatch.setattr(enrichment, "refresh_kev_cache",
                         MagicMock(side_effect=AssertionError("should not refresh a fresh cache")))
    monkeypatch.setattr(enrichment, "build_kev_index", lambda: {"CVE-2024-9999": {}})

    assert enrichment.get_kev_index() == {"CVE-2024-9999": {}}


def test_get_kev_index_refreshes_when_cache_is_stale(monkeypatch):
    monkeypatch.setattr(enrichment, "_kev_cache_fresh", lambda: False)
    refresh_mock = MagicMock()
    monkeypatch.setattr(enrichment, "refresh_kev_cache", refresh_mock)
    monkeypatch.setattr(enrichment, "build_kev_index", lambda: {})

    enrichment.get_kev_index()

    refresh_mock.assert_called_once()
