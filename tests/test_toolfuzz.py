"""tests for redteam/toolfuzz.py — W4 self-fuzzing of the tool registry
(paper rec 4). Deterministic, deny-all context, exec-class tools lint-only.
"""

from __future__ import annotations

import datetime as dt
import json
from pathlib import Path

import pytest

from redteam.audit import AuditLog
from redteam.findings import FindingStore
from redteam.ratelimit import RateLimiter
from redteam.scope import ScopeGuard
from redteam.tools import ToolContext, build_registry
from redteam.tools.jwt import JwtInspectTool
from redteam.toolfuzz import (
    CLEAN_REJECT,
    CRASH,
    EXECUTED,
    LINT_ISSUE,
    LINT_OK,
    SKIPPED,
    fuzz_registry,
    fuzz_tool,
    lint_schema,
    mutations,
)


class _DenyResolver:
    def __call__(self, host, port):
        return []          # nothing resolves: every network path fails closed


def _deny_ctx(tmp_path: Path) -> ToolContext:
    eng = type("E", (), {})()          # ScopeGuard only needs RoE fields via check();
    # build a REAL engagement-shaped stub through the same fields tests use:
    from redteam.config import Engagement, LlmConfig, SandboxConfig
    eng = Engagement(name="fuzz", client="c", authorized_by="fuzz-owner",
                     ticket="ROE-FUZZ-1",
                     starts=dt.date.today() - dt.timedelta(days=1),
                     ends=dt.date.today() + dt.timedelta(days=1),
                     allowed_hosts=("fuzz.invalid",), excluded_hosts=(),
                     allowed_ports=(80,), allowed_schemes=("http",),
                     max_requests_per_second=10.0, max_total_requests=50,
                     allow_private_ranges=False, require_approval_for=(),
                     llm=LlmConfig(), sandbox=SandboxConfig(), raw={})
    return ToolContext(
        scope=ScopeGuard(eng, resolver=lambda h, p: []),
        limiter=RateLimiter(100.0, 1000),
        audit=type("A", (), {"record": lambda *a, **k: None})(),
        findings=FindingStore(tmp_path / "f.json"),
        approve=lambda a, d: False,     # fail closed: fuzzing approves nothing
    )


# -- lint ------------------------------------------------------------------------------

class _HonestTool:
    name = "honest"

    def schema(self):
        return {"name": "honest", "description": "does one thing",
                "input_schema": {"type": "object",
                                 "properties": {"url": {"type": "string",
                                                        "description": "target"}},
                                 "required": ["url"]}}

    def run(self, ctx, **kwargs):
        if not isinstance(kwargs.get("url"), str):
            raise TypeError("url must be a string")
        return "ok"


class _LyingTool:
    name = "liar"

    def schema(self):
        # required claims a property that does not exist — the model WILL send it
        return {"name": "liar", "description": "x",
                "input_schema": {"type": "object", "properties": {},
                                 "required": ["ghost"]}}

    def run(self, ctx, **kwargs):
        return "ran anyway"


class _CrashyTool:
    name = "crashy"

    def schema(self):
        return {"name": "crashy", "description": "x",
                "input_schema": {"type": "object",
                                 "properties": {"q": {"type": "string"}}}}

    def run(self, ctx, **kwargs):
        raise ZeroDivisionError("unexpected arithmetic in validation")


def test_lint_catches_required_not_in_properties():
    problems = lint_schema(_LyingTool())
    assert any("required" in p and "ghost" in p for p in problems)


def test_lint_catches_schema_that_raises():
    class _Thrower:
        name = "thrower"
        def schema(self):
            raise RuntimeError("db down while linting")
        def run(self, ctx, **kwargs):
            return "never"
    problems = lint_schema(_Thrower())
    assert any("schema() raised" in p for p in problems)


def test_lint_clean_on_honest_tool():
    assert lint_schema(_HonestTool()) == []


# -- dispatch mutations --------------------------------------------------------------------

def test_mutations_are_derived_from_the_tools_own_schema():
    cases = mutations(_HonestTool().schema())
    names = [c for c, _ in cases]
    assert "missing-required" in names
    assert any(n.startswith("wrong-type-url") for n in names)
    assert any(n.startswith("injection-") for n in names)
    assert "unknown-key" in names
    # all deterministic: same schema, same cases, twice
    assert [n for n, _ in cases] == [n for n, _ in mutations(_HonestTool().schema())]


def test_honest_tool_clean_rejects_wrong_type_but_executes_valid_string(tmp_path):
    report = __import__("redteam.toolfuzz", fromlist=["ToolFuzzReport"]).ToolFuzzReport()
    fuzz_tool(_HonestTool(), _deny_ctx(tmp_path), report)
    outcomes = {(r["case"], r["outcome"]) for r in report.results}
    assert ("wrong-type-url", CLEAN_REJECT) in outcomes
    # injection strings ARE strings: the tool runs (its own contract allows strings);
    # the deny-all scope is what stops any real effect — recorded as EXECUTED, not crash
    assert any(o == EXECUTED for _, o in outcomes)
    assert not any(o == CRASH for _, o in outcomes)


def test_crashy_tool_is_flagged(tmp_path):
    from redteam.toolfuzz import ToolFuzzReport
    report = ToolFuzzReport()
    fuzz_tool(_CrashyTool(), _deny_ctx(tmp_path), report)
    assert any(r["outcome"] == CRASH and "ZeroDivisionError" in r["detail"]
               for r in report.results)


def test_exec_class_tool_is_lint_only(tmp_path):
    from redteam.toolfuzz import ToolFuzzReport
    report = ToolFuzzReport()

    class _KaliLike:
        name = "kali_exec"
        def schema(self):
            return {"name": "kali_exec", "description": "run a command",
                    "input_schema": {"type": "object",
                                     "properties": {"cmd": {"type": "string"}}}}
        def run(self, ctx, **kwargs):
            raise AssertionError("dispatch fuzzing must NEVER reach an exec tool")

    fuzz_tool(_KaliLike(), _deny_ctx(tmp_path), report, dispatch=False)
    assert ("dispatch", SKIPPED) in {(r["case"], r["outcome"])
                                     for r in report.results}


# -- registry integration (REAL tools, deny-all ctx) ------------------------------------------

def test_real_registry_lints_without_executing(tmp_path):
    registry = build_registry(enable_sandbox=False, enable_browser=False)
    report = fuzz_registry(registry.values(), _deny_ctx(tmp_path),
                           exclude_dispatch=tuple(registry))   # lint-only sweep
    lint_rows = [r for r in report.results if r["case"] == "lint"]
    assert len(lint_rows) == len(registry)
    assert all(r["outcome"] in (LINT_OK, LINT_ISSUE) for r in lint_rows)


def test_real_jwt_tool_fuzzed_under_deny_all(tmp_path):
    report = fuzz_registry([JwtInspectTool()], _deny_ctx(tmp_path))
    # whatever the tool does with garbage, it must never CRASH
    assert not any(r["outcome"] == CRASH for r in report.results)
    assert report.decided > 0


def test_report_card_has_wilson_interval(tmp_path):
    report = fuzz_registry([_HonestTool(), _LyingTool()],
                           _deny_ctx(tmp_path))
    card = report.card()
    assert "Wilson 95% CI" in card
    assert "clean-reject rate" in card
    assert report.failures, "the lying tool must surface as a failure"
