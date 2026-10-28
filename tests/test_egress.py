"""Tests for egress-plan computation — the sandbox's scope-to-firewall translation."""

from __future__ import annotations

import datetime as _dt

from redteam.config import Engagement, LlmConfig, SandboxConfig
from redteam.sandbox.egress import build_egress_plan


def _engagement(hosts):
    return Engagement(
        name="t", client="c", authorized_by="a", ticket="ref",
        starts=_dt.date.today() - _dt.timedelta(days=1),
        ends=_dt.date.today() + _dt.timedelta(days=1),
        allowed_hosts=tuple(hosts), excluded_hosts=(),
        allowed_ports=(80, 443), allowed_schemes=("http", "https"),
        max_requests_per_second=3.0, max_total_requests=100,
        allow_private_ranges=False, require_approval_for=(),
        llm=LlmConfig(), sandbox=SandboxConfig(), raw={},
    )


def _resolver_returning(ip):
    def _resolve(host, port):
        return [(2, 1, 6, "", (ip, 0))]
    return _resolve


def test_cidr_passes_through():
    plan = build_egress_plan(_engagement(["203.0.113.0/28"]))
    assert "203.0.113.0/28" in plan.allowed_cidrs


def test_ip_becomes_host_route():
    plan = build_egress_plan(_engagement(["203.0.113.10"]))
    assert "203.0.113.10/32" in plan.allowed_cidrs


def test_hostname_resolved_to_ip(monkeypatch):
    plan = build_egress_plan(_engagement(["api.acme.example"]),
                             resolver=_resolver_returning("203.0.113.5"))
    assert "203.0.113.5/32" in plan.allowed_cidrs
    assert plan.resolved["api.acme.example"] == ["203.0.113.5"]


def test_wildcard_is_skipped_with_warning():
    plan = build_egress_plan(_engagement(["*.staging.acme.example"]),
                             resolver=_resolver_returning("203.0.113.5"))
    assert "*.staging.acme.example" in plan.skipped_wildcards
    assert any("wildcard" in w for w in plan.warnings)


def test_empty_allowlist_warns():
    plan = build_egress_plan(_engagement(["*.staging.acme.example"]))
    assert plan.allowed_cidrs == []
    assert any("EMPTY" in w for w in plan.warnings)
