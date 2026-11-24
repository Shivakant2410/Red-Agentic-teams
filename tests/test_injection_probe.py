"""injection_probe — the intelligence-not-scanner gate. A parameter that reacts
to a boolean/arith differential is 'reactive' (with a check_spec); a dead param
is 'not_reactive' and gets ZERO exploit payloads. Diagnostic only, nothing
recorded."""
import json
import types

from redteam.tools import injprobe


def _ctx(fetch):
    """Minimal ToolContext: injection_probe only needs scope.check (no-op) and
    fetch_once (monkeypatched)."""
    return types.SimpleNamespace(
        scope=types.SimpleNamespace(check=lambda u: None),
        audit=types.SimpleNamespace(record=lambda *a, **k: None),
    )


def test_reactive_param_boolean_differential(monkeypatch):
    # A param that reaches a WHERE clause: TRUE tail ~ baseline, FALSE tail empty.
    def fake_fetch(ctx, req, tool="", session=""):
        url = req["url"]
        if "1'='2" in url or "%271%27%3D%272" in url:
            return (200, "no results found", 0.1, {})          # FALSE -> empty
        if "1'='1" in url or "%271%27%3D%271" in url:
            return (200, "row: Alice row: Bob row: Carol", 0.1, {})  # TRUE -> rows
        return (200, "row: Alice row: Bob row: Carol", 0.1, {})      # baseline -> rows
    monkeypatch.setattr(injprobe, "fetch_once", fake_fetch)

    out = json.loads(injprobe.InjectionProbeTool().run(
        _ctx(fake_fetch), url="https://t.test/search", params=["q"], reason="t"))
    v = out["verdicts"][0]
    assert v["verdict"] == "reactive"
    assert "check_spec" in v and v["check_spec"]["requests"]


def test_not_reactive_param_gets_no_exploit(monkeypatch):
    # A static param: every input returns the identical page -> not reactive.
    def fake_fetch(ctx, req, tool="", session=""):
        return (200, "<html>Welcome to the shop. Same page always.</html>", 0.1, {})
    monkeypatch.setattr(injprobe, "fetch_once", fake_fetch)

    out = json.loads(injprobe.InjectionProbeTool().run(
        _ctx(fake_fetch), url="https://t.test/page", params=["ref"], reason="t"))
    v = out["verdicts"][0]
    assert v["verdict"] == "not_reactive"
    assert "check_spec" not in v
    assert "move on" in v["evidence"][0].lower() or "do not" in v["evidence"][0].lower()


def test_error_signature_alone_is_inconclusive_not_reactive(monkeypatch):
    # A quote triggers a DB error but no boolean/arith differential: inconclusive,
    # NOT reactive — error text must not by itself earn a proof trial.
    def fake_fetch(ctx, req, tool="", session=""):
        url = req["url"]
        if url.endswith("%27") or url.endswith("'"):
            return (500, "You have an error in your SQL syntax near ''", 0.1, {})
        return (200, "static identical body", 0.1, {})  # no differential
    monkeypatch.setattr(injprobe, "fetch_once", fake_fetch)

    out = json.loads(injprobe.InjectionProbeTool().run(
        _ctx(fake_fetch), url="https://t.test/x", params=["id"], reason="t"))
    v = out["verdicts"][0]
    assert v["verdict"] == "inconclusive"
    assert "check_spec" not in v


def test_arithmetic_identity_reactive(monkeypatch):
    # value=7 == value=6+1 but != value=99  -> server evaluates the expression.
    def fake_fetch(ctx, req, tool="", session=""):
        url = req["url"]
        if url.endswith("=7") or url.endswith("=6%2B1") or url.endswith("=6+1"):
            return (200, "product #7 details widget", 0.1, {})
        if url.endswith("=99"):
            return (200, "product #99 totally different", 0.1, {})
        return (200, "baseline", 0.1, {})
    monkeypatch.setattr(injprobe, "fetch_once", fake_fetch)

    out = json.loads(injprobe.InjectionProbeTool().run(
        _ctx(fake_fetch), url="https://t.test/item", params=["pid"], reason="t"))
    v = out["verdicts"][0]
    assert v["verdict"] == "reactive"
    assert any("arithmetic" in e.lower() for e in v["evidence"])


def test_nothing_recorded_diagnostic_only(monkeypatch):
    recorded = []
    def fake_fetch(ctx, req, tool="", session=""):
        return (200, "same", 0.1, {})
    monkeypatch.setattr(injprobe, "fetch_once", fake_fetch)
    ctx = types.SimpleNamespace(
        scope=types.SimpleNamespace(check=lambda u: None),
        audit=types.SimpleNamespace(record=lambda *a, **k: recorded.append((a, k))))
    injprobe.InjectionProbeTool().run(ctx, url="https://t.test/x", params=["a"], reason="t")
    # only the summary audit line, never a finding/confirm record
    event_names = [args[0] for (args, kwargs) in recorded if args]
    assert event_names and all(e == "injection_probe" for e in event_names)
