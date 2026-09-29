"""Tests for the scope guard — the safety-critical boundary.

Run with:  pytest -q
These use an injected resolver so no real DNS or network calls happen.
"""

from __future__ import annotations

import datetime as _dt

import pytest

from redteam.config import Engagement
from redteam.scope import ScopeGuard, ScopeViolation


def _engagement(**overrides) -> Engagement:
    base = dict(
        name="t", client="c", authorized_by="a", ticket="ref",
        starts=_dt.date.today() - _dt.timedelta(days=1),
        ends=_dt.date.today() + _dt.timedelta(days=1),
        allowed_hosts=("*.staging.acme.example", "api.acme.example", "203.0.113.0/28"),
        excluded_hosts=("payments.staging.acme.example",),
        allowed_ports=(80, 443),
        allowed_schemes=("http", "https"),
        max_requests_per_second=3.0,
        max_total_requests=100,
        allow_private_ranges=False,
        require_approval_for=(),
        raw={},
    )
    base.update(overrides)
    return Engagement(**base)


def _resolver_returning(ip: str):
    def _resolve(host, port):
        return [(2, 1, 6, "", (ip, 0))]
    return _resolve


def test_allows_in_scope_host():
    guard = ScopeGuard(_engagement(), resolver=_resolver_returning("203.0.113.5"))
    target = guard.check("https://api.acme.example/v1/users")
    assert target.host == "api.acme.example"
    assert target.port == 443


def test_allows_wildcard_subdomain():
    guard = ScopeGuard(_engagement(), resolver=_resolver_returning("203.0.113.5"))
    assert guard.check("https://app.staging.acme.example").host == "app.staging.acme.example"


def test_rejects_out_of_scope_host():
    guard = ScopeGuard(_engagement(), resolver=_resolver_returning("203.0.113.5"))
    with pytest.raises(ScopeViolation):
        guard.check("https://evil.example")


def test_exclusion_wins_over_allow():
    guard = ScopeGuard(_engagement(), resolver=_resolver_returning("203.0.113.5"))
    with pytest.raises(ScopeViolation):
        guard.check("https://payments.staging.acme.example")


def test_rejects_disallowed_port():
    guard = ScopeGuard(_engagement(), resolver=_resolver_returning("203.0.113.5"))
    with pytest.raises(ScopeViolation):
        guard.check("https://api.acme.example:8080")


def test_blocks_host_resolving_to_private_ip():
    # In-scope by name, but DNS points to an internal address -> blocked (SSRF guard).
    guard = ScopeGuard(_engagement(), resolver=_resolver_returning("10.0.0.5"))
    with pytest.raises(ScopeViolation):
        guard.check("https://api.acme.example")


def test_allows_private_ip_when_roe_opts_in():
    guard = ScopeGuard(_engagement(allow_private_ranges=True),
                       resolver=_resolver_returning("10.0.0.5"))
    assert guard.check("https://api.acme.example").host == "api.acme.example"


def test_rejects_when_engagement_inactive():
    past = _engagement(
        starts=_dt.date.today() - _dt.timedelta(days=10),
        ends=_dt.date.today() - _dt.timedelta(days=5),
    )
    guard = ScopeGuard(past, resolver=_resolver_returning("203.0.113.5"))
    with pytest.raises(ScopeViolation):
        guard.check("https://api.acme.example")
