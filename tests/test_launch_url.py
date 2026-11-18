"""Builder 04 URL-first engagement creation — redteam.launch unit tests.

Every rejection must be fail-closed with an operator-actionable message, and
every generated engagement must load through the REAL config loader (the same
authority the whole run pipeline uses) with the exact authorized host/ports and
everything else excluded.
"""

from __future__ import annotations

import datetime as _dt

import pytest

from redteam.config import load_engagement
from redteam.launch import (INTENSITY_PRESETS, LaunchError, build_engagement,
                            parse_target_url, write_launch_artifacts)

_AUTH = {
    "confirmed": True,
    "authorized_by": "Shivakant, security owner",
    "ticket": "ROE-2026-041",
    "starts": "2026-11-18",
    "ends": "2026-11-25",
    "allow_private_ranges": False,
    "excluded_hosts": [],
}


def _auth(**over):
    a = dict(_AUTH)
    a.update(over)
    return a


# ---------------------------------------------------------------- URL parsing

def test_parse_https_target_normalizes_host_and_default_port():
    r = parse_target_url("https://Demo.Testfire.net/login")
    assert r == {"scheme": "https", "host": "demo.testfire.net", "port": 443}


def test_parse_explicit_port_wins():
    r = parse_target_url("http://127.0.0.1:8901/api/", allow_private_ranges=True)
    assert r == {"scheme": "http", "host": "127.0.0.1", "port": 8901}


def test_parse_rejects_schemeless_and_bad_schemes():
    for bad in ("demo.testfire.net", "ftp://demo.testfire.net",
                "file:///etc/passwd", "javascript:alert(1)"):
        with pytest.raises(LaunchError):
            parse_target_url(bad)


def test_parse_rejects_embedded_credentials():
    with pytest.raises(LaunchError, match="credentials"):
        parse_target_url("https://admin:hunter2@demo.testfire.net")


def test_parse_rejects_missing_or_invalid_host():
    with pytest.raises(LaunchError):
        parse_target_url("https://")
    with pytest.raises(LaunchError):
        parse_target_url("https://not a host.example.com")
    with pytest.raises(LaunchError):
        parse_target_url("https://bad_label.example.com")
    with pytest.raises(LaunchError):
        parse_target_url("https://singleword")  # not FQDN, not localhost/IP


def test_parse_rejects_out_of_range_port():
    with pytest.raises(LaunchError):
        parse_target_url("https://demo.testfire.net:99999")


def test_parse_private_targets_fail_closed_without_optin():
    for url in ("http://127.0.0.1:8901/", "http://192.168.1.10/",
                "http://localhost:8000/", "http://10.0.0.5/"):
        with pytest.raises(LaunchError, match="private|loopback"):
            parse_target_url(url)
    # explicit opt-in authorizes the local-lab target
    assert parse_target_url("http://localhost:8000/",
                            allow_private_ranges=True)["host"] == "localhost"
    assert parse_target_url("http://10.0.0.5/", allow_private_ranges=True)["host"] == "10.0.0.5"


def test_parse_public_ip_is_allowed_without_private_optin():
    # a genuinely public unicast address needs no private-range optin
    r = parse_target_url("http://93.184.216.34/")
    assert r["host"] == "93.184.216.34" and r["port"] == 80


# ------------------------------------------------------------- authorization

def test_build_fails_closed_without_confirmation():
    with pytest.raises(LaunchError, match="confirmation"):
        build_engagement("https://demo.testfire.net", "assess",
                         _auth(confirmed=False))


def test_build_fails_closed_without_authorized_by_or_ticket():
    with pytest.raises(LaunchError, match="authorized_by"):
        build_engagement("https://demo.testfire.net", "assess", _auth(authorized_by=""))
    with pytest.raises(LaunchError, match="ticket"):
        build_engagement("https://demo.testfire.net", "assess", _auth(ticket=""))


def test_build_fails_closed_on_bad_window_or_objective():
    with pytest.raises(LaunchError):
        build_engagement("https://demo.testfire.net", "assess",
                         _auth(starts="2026-11-25", ends="2026-11-18"))
    with pytest.raises(LaunchError):
        build_engagement("https://demo.testfire.net", "assess",
                         _auth(starts="18/11/2026"))
    with pytest.raises(LaunchError, match="objective"):
        build_engagement("https://demo.testfire.net", "   ", _auth())


def test_build_fail_closed_unknown_intensity():
    with pytest.raises(LaunchError, match="intensity"):
        build_engagement("https://demo.testfire.net", "assess", _auth(),
                         intensity="unrestricted")


# --------------------------------------------------------------- engagement

def test_generated_engagement_loads_with_exact_scope(tmp_path):
    data, summary = build_engagement(
        "https://demo.testfire.net/bank/login.aspx",
        "Assess the authorized web application for security weaknesses.",
        _auth())
    path = write_launch_artifacts(tmp_path / "run", data, summary)
    assert (tmp_path / "run" / "authorization.json").exists()

    eng = load_engagement(path)  # the REAL loader must accept it
    assert eng.allowed_hosts == ("demo.testfire.net",)
    assert eng.allowed_ports == (443,)
    assert eng.allowed_schemes == ("https",)
    assert eng.excluded_hosts == ()
    assert eng.allow_private_ranges is False
    assert eng.authorized_by == "Shivakant, security owner"
    assert eng.ticket == "ROE-2026-041"
    assert eng.starts == _dt.date(2026, 11, 18)
    assert eng.max_requests_per_second == INTENSITY_PRESETS["standard"][0]
    assert eng.max_total_requests == INTENSITY_PRESETS["standard"][1]
    assert eng.objective is not None and "security weaknesses" in eng.objective.description


def test_excluded_hosts_and_intensity_flow_through(tmp_path):
    data, summary = build_engagement(
        "http://127.0.0.1:8901/", "lab assessment",
        _auth(allow_private_ranges=True,
              excluded_hosts=["127.0.0.1:9999"]),
        intensity="low", max_run_seconds=900, max_llm_tokens=50000)
    path = write_launch_artifacts(tmp_path / "run", data, summary)
    eng = load_engagement(path)
    assert eng.allowed_hosts == ("127.0.0.1",)
    assert eng.allowed_ports == (8901,)
    assert eng.allow_private_ranges is True
    assert eng.excluded_hosts == ("127.0.0.1:9999",)
    assert eng.max_requests_per_second == INTENSITY_PRESETS["low"][0]
    assert eng.max_total_requests == INTENSITY_PRESETS["low"][1]
    assert eng.max_run_seconds == 900 and eng.max_llm_tokens == 50000


def test_authorization_record_has_no_secret_fields(tmp_path):
    data, summary = build_engagement("https://demo.testfire.net", "assess", _auth())
    path = write_launch_artifacts(tmp_path / "run", data, summary)
    import json
    record = json.loads((tmp_path / "run" / "authorization.json").read_text())
    blob = json.dumps(record).lower()
    for forbidden in ("api_key", "api key", "password", "secret", "credential"):
        assert forbidden not in blob, f"authorization.json leaks {forbidden!r}"
    assert record["confirmed"] is True
    assert record["authorized_by"] == "Shivakant, security owner"
    assert record["host"] == "demo.testfire.net"
