"""Pinning + drift alarms (W14): a backend swap trips a visible alarm."""

import json

import pytest

from redteam.events import EventBus
from redteam.pinning import PinDriftError, PinRegistry, fingerprint

ROUTER_CONFIG = {"model": "nvidia/nemotron-3-ultra-550b-a55b:free",
                 "backend": "openrouter", "role": "plan"}


def test_fingerprint_is_order_insensitive_and_stable():
    a = fingerprint({"a": 1, "b": [2, 3]})
    b = fingerprint({"b": [2, 3], "a": 1})
    assert a == b
    assert a != fingerprint({"a": 1, "b": [2, 4]})


def test_unchanged_config_produces_no_alarm():
    reg = PinRegistry()
    reg.pin("plan", model="nemotron", backend="openrouter", config=ROUTER_CONFIG)
    assert reg.check({"plan": ROUTER_CONFIG}) == []


def test_backend_swap_trips_a_changed_alarm():
    reg = PinRegistry()
    reg.pin("plan", model="nemotron", backend="openrouter", config=ROUTER_CONFIG)
    swapped = {**ROUTER_CONFIG, "model": "some-other-model:free"}
    alarms = reg.check({"plan": swapped})
    assert len(alarms) == 1
    assert alarms[0]["kind"] == "changed"
    assert alarms[0]["expected"] != alarms[0]["actual"]


def test_unpinned_live_key_is_itself_drift():
    reg = PinRegistry()
    reg.pin("plan", config=ROUTER_CONFIG)
    alarms = reg.check({"plan": ROUTER_CONFIG, "poc": ROUTER_CONFIG})
    kinds = {a["key"]: a["kind"] for a in alarms}
    assert kinds == {"poc": "unpinned"}


def test_emit_and_strict_mode(tmp_path):
    reg = PinRegistry()
    reg.pin("plan", config=ROUTER_CONFIG)
    live = {"plan": {**ROUTER_CONFIG, "backend": "ollama"}}

    bus = EventBus(run_id="pin-test")
    seen: list[dict] = []
    bus.subscribe(seen.append)

    alarms = reg.check_and_emit(live, events=bus, strict=False)
    assert len(alarms) == 1
    assert [e["type"] for e in seen] == ["pin.drift"]
    assert seen[0]["key"] == "plan"

    with pytest.raises(PinDriftError):
        reg.check_and_emit(live, events=None, strict=True)


def test_atomic_save_and_roundtrip(tmp_path):
    path = tmp_path / "pins.json"
    reg = PinRegistry(path=path)
    reg.pin("plan", model="nemotron", backend="openrouter", config=ROUTER_CONFIG)
    reg.save()
    loaded = PinRegistry.load(path)
    assert len(loaded) == 1
    assert loaded.check({"plan": ROUTER_CONFIG}) == []
    assert not loaded.corrupt


def test_corrupt_pins_file_fails_closed_visibly(tmp_path):
    path = tmp_path / "pins.json"
    path.write_text("{ this is not json", encoding="utf-8")
    reg = PinRegistry.load(path)
    assert reg.corrupt
    alarms = reg.check({})
    assert alarms and alarms[0]["kind"] == "registry_corrupt"
    # strict mode refuses to bless a blind registry
    with pytest.raises(PinDriftError):
        reg.check_and_emit({}, strict=True)


def test_missing_pins_file_is_no_pins_yet_not_corrupt(tmp_path):
    reg = PinRegistry.load(tmp_path / "absent.json")
    assert not reg.corrupt
    assert len(reg) == 0
