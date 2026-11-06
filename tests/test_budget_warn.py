"""BudgetTracker W10 additions: warn-before-trip events, tool-call caps, telemetry."""

import pytest

from redteam.events import EventBus
from redteam.runtime import BudgetTracker, Halt


def _bus():
    bus = EventBus(run_id="budget-test")
    seen: list[dict] = []
    bus.subscribe(seen.append)
    return bus, seen


def test_warn_fires_once_at_fraction_of_token_cap():
    bus, seen = _bus()
    b = BudgetTracker(max_tokens=100, events=bus, warn_fraction=0.8)
    b.add_usage({"total_tokens": 85})
    b.check()
    warns = [e for e in seen if e["type"] == "budget.warn"]
    assert len(warns) == 1
    assert warns[0]["scope"] == "tokens"
    assert warns[0]["fraction"] == 0.85
    b.check()                      # idempotent: one warn per scope, ever
    assert len([e for e in seen if e["type"] == "budget.warn"]) == 1


def test_trip_emits_exceeded_then_halts():
    bus, seen = _bus()
    b = BudgetTracker(max_tokens=100, events=bus)
    b.add_usage({"total_tokens": 120})
    with pytest.raises(Halt):
        b.check()
    exceeded = [e for e in seen if e["type"] == "budget.exceeded"]
    assert len(exceeded) == 1
    assert exceeded[0]["scope"] == "tokens"
    assert exceeded[0]["used"] == 120


def test_tool_call_cap_warns_then_trips():
    bus, seen = _bus()
    b = BudgetTracker(max_tool_calls=3, events=bus)
    b.count_tool_call()            # 1/3 — no warn, no trip
    b.count_tool_call()            # 2/3 — no warn yet (0.67 < 0.8)
    assert seen == []
    with pytest.raises(Halt):
        b.count_tool_call()        # 3/3 — warn + exceeded + Halt
    types = [e["type"] for e in seen]
    assert types == ["budget.warn", "budget.exceeded"]


def test_tool_calls_surface_in_status():
    b = BudgetTracker(max_tool_calls=50)
    b.count_tool_call(7)
    st = b.status()
    assert st["tool_calls"] == 7
    assert st["max_tool_calls"] == 50


def test_no_event_bus_still_halts_cleanly():
    b = BudgetTracker(max_tool_calls=1)
    with pytest.raises(Halt):
        b.count_tool_call()


def test_legacy_signature_unchanged():
    """Old callers (max_seconds/max_tokens/kill_file only) behave exactly as before."""
    b = BudgetTracker(max_tokens=100)
    b.add_usage({"total_tokens": 99})
    b.check()                      # 99 < 100: no trip, and no warn at 0.99? warn fires...
    assert b.tokens == 99
    b.add_usage({"prompt_tokens": 5, "completion_tokens": 5})
    with pytest.raises(Halt):
        b.check()
    assert "tool_calls" in b.status()
