"""Dashboard "New engagement" form: client URL + authorization -> the narrowest scope."""

from __future__ import annotations

import datetime as _dt
import socket
from pathlib import Path

import pytest
import yaml
from fastapi.testclient import TestClient

import redteam.server as server_mod
from redteam.config import load_engagement
from redteam.engagement_builder import (EngagementForm, FormError, build_engagement_doc,
                                        parse_url, preflight)

TODAY = _dt.date.today()
ENDS = (TODAY + _dt.timedelta(days=7)).isoformat()


def _form(**kw) -> EngagementForm:
    base = dict(client="Acme", targets=["https://app.acme.example/login"],
                authorized_by="Jane CISO", ticket="SOW-42", ends=ENDS)
    base.update(kw)
    return EngagementForm(**base)


def _public_resolver(host, port):
    return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0))]


def _loopback_resolver(host, port):
    return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 0))]


# -- scope derivation ---------------------------------------------------------------

def test_scope_is_exactly_the_typed_host_port_scheme(tmp_path):
    doc = build_engagement_doc(_form(targets=["https://app.acme.example/login",
                                              "http://api.acme.example:8443/v1"]))
    assert doc["scope"]["allowed_hosts"] == ["api.acme.example", "app.acme.example"]
    assert doc["scope"]["allowed_ports"] == [443, 8443]
    assert doc["scope"]["allowed_schemes"] == ["http", "https"]
    assert doc["scope"]["allow_private_ranges"] is False
    p = tmp_path / "e.yaml"
    p.write_text(yaml.safe_dump(doc), encoding="utf-8")
    eng = load_engagement(p)            # same validator as a hand-written file
    assert eng.is_active and eng.ticket == "SOW-42"


def test_bare_host_defaults_to_https_443():
    assert parse_url("acme.example").url == "https://acme.example:443/"


@pytest.mark.parametrize("bad", [
    "ftp://acme.example", "https://*.acme.example", "https://user:pw@acme.example",
    "https://", "https://bad_host!.example", "https://acme.example:99999",
])
def test_rejects_anything_wider_or_odd(bad):
    with pytest.raises(FormError):
        parse_url(bad)


@pytest.mark.parametrize("field,value,msg", [
    ("authorized_by", "", "authorized by"),
    ("ticket", " ", "authorization reference"),
    ("client", "", "client name"),
    ("ends", "2001-01-01", "past"),
    ("ends", (TODAY + _dt.timedelta(days=400)).isoformat(), "longer than"),
    ("targets", [], "at least one"),
])
def test_authorization_and_window_are_required(field, value, msg):
    with pytest.raises(FormError, match=msg):
        build_engagement_doc(_form(**{field: value}))


# -- the Check button ---------------------------------------------------------------

def test_check_never_fetches_without_authorization():
    calls = []
    out = preflight(_form(ticket=""), resolver=_public_resolver,
                    fetch=lambda u: calls.append(u))
    assert calls == [] and not out["ok"]
    assert any("authorization reference" in e for e in out["errors"])


def test_check_probes_once_per_url_when_in_scope():
    calls = []
    out = preflight(_form(), resolver=_public_resolver,
                    fetch=lambda u: calls.append(u) or {"ok": True, "status": 200})
    assert out["ok"] and calls == ["https://app.acme.example:443/login"]
    assert out["targets"][0]["reachable"]["status"] == 200


def test_check_blocks_internal_address_unless_ticked():
    calls = []
    out = preflight(_form(), resolver=_loopback_resolver, fetch=calls.append)
    assert not out["ok"] and calls == []
    assert "internal address" in out["targets"][0]["error"]


def test_check_warns_that_kali_cannot_reach_localhost():
    out = preflight(_form(targets=["http://localhost:3000"], allow_private_ranges=True),
                    resolver=_loopback_resolver)
    assert out["ok"]
    assert any("sandbox itself" in w for w in out["warnings"])


def test_check_refuses_scope_covering_the_control_plane():
    out = preflight(_form(targets=["http://127.0.0.1:8000"], allow_private_ranges=True),
                    resolver=_loopback_resolver, control_plane=("127.0.0.1", 8000))
    assert not out["ok"] and "self-targeting" in out["errors"][0]


# -- the endpoints ------------------------------------------------------------------

@pytest.fixture()
def client(tmp_path, monkeypatch):
    launched = []

    def fake_execute_run(opts):
        launched.append(opts)
        return {}

    monkeypatch.setattr(server_mod, "execute_run", fake_execute_run)
    app = server_mod.create_app(runs_root=tmp_path / "runs", dashboard_dir=None)
    return TestClient(app), tmp_path / "runs", launched


def _body(**kw):
    base = dict(client="Acme", targets=["https://app.acme.example/"],
                authorized_by="Jane CISO", ticket="SOW-42", ends=ENDS,
                objective="Find authorization flaws", confirm_authorized=True)
    base.update(kw)
    return base


def test_launch_requires_attestation(client):
    c, _, launched = client
    r = c.post("/api/engagements/launch", json=_body(confirm_authorized=False))
    assert r.status_code == 400 and launched == []


def test_launch_writes_scoped_engagement_and_starts_run(client):
    c, runs_root, _ = client
    r = c.post("/api/engagements/launch", json=_body())
    assert r.status_code == 202, r.text
    body = r.json()
    assert body["scope"]["allowed_hosts"] == ["app.acme.example"]
    run_eng = Path(body["out_dir"]) / "engagement.yaml"
    assert run_eng.exists()
    assert load_engagement(run_eng).allowed_hosts == ("app.acme.example",)
    manifest = (Path(body["out_dir"]) / "manifest.json").read_text(encoding="utf-8")
    assert "https://app.acme.example:443/" in manifest   # target folded into objective
    # the engagements folder is not mistaken for a run
    assert [x["run_id"] for x in c.get("/api/runs").json()["runs"]] == [body["run_id"]]


def test_launch_bad_form_is_400_and_leaves_nothing(client):
    c, runs_root, launched = client
    r = c.post("/api/engagements/launch", json=_body(targets=["https://*.acme.example"]))
    assert r.status_code == 400 and launched == []
    assert not list((runs_root / "_engagements").glob("*.yaml")) \
        if (runs_root / "_engagements").exists() else True


def test_check_endpoint_without_probe_sends_nothing(client, monkeypatch):
    import redteam.engagement_builder as eb
    monkeypatch.setattr(eb, "http_probe", lambda u: pytest.fail("probe sent"))
    c, _, _ = client
    r = c.post("/api/engagements/check", json=_body(probe=False))
    assert r.status_code == 200
    assert r.json()["scope"]["allowed_ports"] == [443]
