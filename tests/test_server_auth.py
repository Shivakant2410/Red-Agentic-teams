import pytest
from fastapi.testclient import TestClient

from redteam.server import create_app


def test_non_loopback_bind_requires_a_strong_api_token(tmp_path, monkeypatch):
    monkeypatch.delenv("RED_API_TOKEN", raising=False)
    with pytest.raises(RuntimeError, match="RED_API_TOKEN is required"):
        create_app(tmp_path, dashboard_dir=None, control_plane=("0.0.0.0", 8000))


def test_api_token_protects_api_but_health_remains_available(tmp_path, monkeypatch):
    token = "t" * 48
    monkeypatch.setenv("RED_API_TOKEN", token)
    client = TestClient(create_app(
        tmp_path, dashboard_dir=None, control_plane=("0.0.0.0", 8000)))

    assert client.get("/api/health").status_code == 200
    assert client.get("/api/runs").status_code == 401
    assert client.get("/api/runs", headers={"Authorization": f"Bearer {token}"}).status_code == 200


def test_same_origin_dashboard_can_use_cookie_free_api_session(tmp_path, monkeypatch):
    monkeypatch.setenv("RED_API_TOKEN", "s" * 48)
    client = TestClient(create_app(
        tmp_path, dashboard_dir=None, control_plane=("0.0.0.0", 8000)))
    response = client.get("/api/runs", headers={
        "Host": "console.example.test",
        "Origin": "http://console.example.test",
    })
    assert response.status_code == 200


def test_cors_is_an_explicit_allowlist_not_wildcard(tmp_path, monkeypatch):
    monkeypatch.delenv("RED_API_TOKEN", raising=False)
    monkeypatch.delenv("RED_CORS_ORIGINS", raising=False)
    client = TestClient(create_app(tmp_path, dashboard_dir=None))

    allowed = client.options("/api/runs", headers={
        "Origin": "http://localhost:3000",
        "Access-Control-Request-Method": "GET",
    })
    denied = client.options("/api/runs", headers={
        "Origin": "https://attacker.example",
        "Access-Control-Request-Method": "GET",
    })
    assert allowed.headers.get("access-control-allow-origin") == "http://localhost:3000"
    assert "access-control-allow-origin" not in denied.headers


def test_wildcard_cors_configuration_is_rejected(tmp_path, monkeypatch):
    monkeypatch.setenv("RED_CORS_ORIGINS", "*")
    with pytest.raises(RuntimeError, match="wildcard is forbidden"):
        create_app(tmp_path, dashboard_dir=None)
