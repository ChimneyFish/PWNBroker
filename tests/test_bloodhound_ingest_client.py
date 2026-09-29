"""Tests for app/bloodhound/api_client.py's ingest (file-upload) methods —
start_file_upload, upload_file_data, end_file_upload, get_job_status, and
list_completed_tasks. Paths/shapes are confirmed against BloodHound CE's
published OpenAPI spec (see api_client.py's module docstring); these tests
verify BHClient calls the right path/method/content-type and parses the
documented response shape, with requests.request mocked throughout.
"""
from unittest.mock import patch

import pytest
import requests

from app.bloodhound.api_client import BHClient, BloodHoundAPIError


def _fake_response(status_code, json_body):
    resp = requests.Response()
    resp.status_code = status_code
    import json as _json
    resp._content = _json.dumps(json_body).encode()
    return resp


@pytest.fixture()
def client():
    return BHClient("http://localhost:8080", "token-id", "token-key")


class TestStartFileUpload:
    def test_posts_to_start_path_and_returns_job_id(self, client):
        captured = {}

        def fake_request(method, url, **kwargs):
            captured["method"] = method
            captured["url"] = url
            return _fake_response(201, {"data": {"id": 99}})

        with patch("app.bloodhound.api_client.requests.request", side_effect=fake_request):
            job_id = client.start_file_upload()

        assert job_id == 99
        assert captured["method"] == "POST"
        assert captured["url"] == "http://localhost:8080/api/v2/file-upload/start"

    def test_raises_on_error_status(self, client):
        with patch("app.bloodhound.api_client.requests.request",
                   return_value=_fake_response(401, {"error": "unauthorized"})):
            with pytest.raises(BloodHoundAPIError):
                client.start_file_upload()


class TestUploadFileData:
    def test_uploads_zip_bytes_with_correct_content_type(self, client):
        captured = {}

        def fake_request(method, url, data=None, headers=None, **kwargs):
            captured["method"] = method
            captured["url"] = url
            captured["data"] = data
            captured["content_type"] = headers["Content-Type"]
            return _fake_response(202, {})

        with patch("app.bloodhound.api_client.requests.request", side_effect=fake_request):
            client.upload_file_data(99, b"PK\x03\x04fakezip", content_type="application/zip")

        assert captured["method"] == "POST"
        assert captured["url"] == "http://localhost:8080/api/v2/file-upload/99"
        assert captured["data"] == b"PK\x03\x04fakezip"
        assert captured["content_type"] == "application/zip"

    def test_raises_on_error_status(self, client):
        with patch("app.bloodhound.api_client.requests.request",
                   return_value=_fake_response(400, {"error": "bad zip"})):
            with pytest.raises(BloodHoundAPIError):
                client.upload_file_data(99, b"junk")


class TestEndFileUpload:
    def test_posts_to_end_path(self, client):
        captured = {}

        def fake_request(method, url, **kwargs):
            captured["method"] = method
            captured["url"] = url
            return _fake_response(200, {})

        with patch("app.bloodhound.api_client.requests.request", side_effect=fake_request):
            client.end_file_upload(99)

        assert captured["method"] == "POST"
        assert captured["url"] == "http://localhost:8080/api/v2/file-upload/99/end"

    def test_raises_on_error_status(self, client):
        with patch("app.bloodhound.api_client.requests.request",
                   return_value=_fake_response(404, {"error": "not found"})):
            with pytest.raises(BloodHoundAPIError):
                client.end_file_upload(99)


class TestGetJobStatus:
    def test_filters_by_id_and_returns_first_row(self, client):
        captured = {}

        def fake_request(method, url, **kwargs):
            captured["method"] = method
            captured["url"] = url
            return _fake_response(200, {"data": [{"id": 99, "status": 2, "status_message": "done"}]})

        with patch("app.bloodhound.api_client.requests.request", side_effect=fake_request):
            job = client.get_job_status(99)

        assert captured["method"] == "GET"
        assert captured["url"] == "http://localhost:8080/api/v2/file-upload?id=eq:99"
        assert job == {"id": 99, "status": 2, "status_message": "done"}

    def test_raises_when_job_not_found(self, client):
        with patch("app.bloodhound.api_client.requests.request",
                   return_value=_fake_response(200, {"data": []})):
            with pytest.raises(BloodHoundAPIError):
                client.get_job_status(99)

    def test_raises_on_error_status(self, client):
        with patch("app.bloodhound.api_client.requests.request",
                   return_value=_fake_response(500, {"error": "boom"})):
            with pytest.raises(BloodHoundAPIError):
                client.get_job_status(99)


class TestListCompletedTasks:
    def test_gets_completed_tasks_path(self, client):
        captured = {}

        def fake_request(method, url, **kwargs):
            captured["method"] = method
            captured["url"] = url
            return _fake_response(200, {"data": [{"id": 1, "file_name": "computers.json", "errors": []}]})

        with patch("app.bloodhound.api_client.requests.request", side_effect=fake_request):
            tasks = client.list_completed_tasks(99)

        assert captured["method"] == "GET"
        assert captured["url"] == "http://localhost:8080/api/v2/file-upload/99/completed-tasks"
        assert tasks == [{"id": 1, "file_name": "computers.json", "errors": []}]

    def test_raises_on_error_status(self, client):
        with patch("app.bloodhound.api_client.requests.request",
                   return_value=_fake_response(404, {"error": "not found"})):
            with pytest.raises(BloodHoundAPIError):
                client.list_completed_tasks(99)
