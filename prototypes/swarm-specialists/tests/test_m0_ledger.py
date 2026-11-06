"""M0 test suite — the promoted HypothesisLedger spine.

Unit layer : ledger lifecycle + honest scoring, projection resolution paths
             (confirmed / tested / refuted / inconclusive / dvlba-shaped),
             grounding discipline, deferred-window projection from traffic.
E2E layer  : registry run writes hypothesis_ledger.json (spine ON by
             default), and the deterministic fallback (ledger off) produces
             no spine artifacts and identical findings.
"""
import json
import os
import subprocess
import sys
import time

import pytest
import requests

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)
from engine.ledger import HypothesisLedger                  # noqa: E402
from engine.projection import project_swarm, project_statefuzz  # noqa: E402
from swarm.registry_tool import run, _SPINE_AVAILABLE       # noqa: E402


def test_spine_available():
    assert _SPINE_AVAILABLE, "engine package must import from the tree root"


# ----------------------------------------------------------------- ledger --
def test_ledger_lifecycle_and_honesty():
    l = HypothesisLedger()
    a = l.propose("t", "h_async_toctou", "async settle re-check missing", 0.4,
                  plan="register marker, drain, read back",
                  derived_from=["F-1"])
    l.attach(a["id"], "probe", "marker registered", 3)
    l.resolve(a["id"], "confirmed", {"note": "balance moved"})
    b = l.propose("t", "h_x", "never dispatched", 0.5)
    l.resolve(b["id"], "inconclusive")
    c = l.propose("t", "h_y", "probe found nothing", 0.5)
    l.resolve(c["id"], "refuted")
    st = l.stats()
    assert st["total"] == 3
    assert st["by_status"] == {"confirmed": 1, "inconclusive": 1,
                               "refuted": 1}
    # refuted belief scores as high as a confirmed one — both are information
    assert l.score() == 2.0
    e = l.entries[0]
    assert e["derived_from"] == ["F-1"] and e["tests"][0]["requests_spent"] == 3


def test_ledger_deferred_window():
    l = HypothesisLedger()
    e = l.deferred("run", marker="1 window(s)", callback_path="/api/ev/1",
                   expectation={"delta": -30000})
    assert e["deferred"]["marker"] == "1 window(s)"
    l.resolve(e["id"], "confirmed", {"note": "I1 violation"})
    assert l.stats()["by_status"] == {"confirmed": 1}


def test_ledger_persistence(tmp_path):
    l = HypothesisLedger()
    e = l.propose("s", "t", "title", 0.5)
    l.resolve(e["id"], "confirmed-by-transcript", {"note": "n"})
    path = str(tmp_path / "hypothesis_ledger.json")
    doc = l.save(path)
    assert doc["stats"]["total"] == 1
    on_disk = json.load(open(path))
    assert on_disk["entries"][0]["status"] == "confirmed-by-transcript"


# ------------------------------------------------------------- projection --
def _hyp(fid, tag="h_state_guard", title="T", prior=0.5):
    # specialist-published facts use the SF-<SOURCE>-<seq> id scheme
    # (swarm/specialist.py FactLike) — the projection keys dispatch traces
    # on exactly these ids.
    return {"id": fid, "kind": "HYPOTHESIS", "source": "hypothesis",
            "payload": {"tag": tag, "title": title, "prior": prior,
                        "test_plan": "p"}, "tags": [], "derived_from": []}


def test_projection_resolution_paths():
    h = _hyp("SF-HYPOTHESIS-0001")
    finding = {"id": "SF-EXPLOIT-0002", "kind": "FINDING",
               "source": "exploit",
               "payload": {"finding": {"id": "FW-X", "title": "violation"},
                           "status": "verified"},
               "tags": [], "derived_from": ["SF-HYPOTHESIS-0001"]}
    obs = _hyp("SF-HYPOTHESIS-0003", tag="h_hidden_verbs", title="O")
    obs_child = {"id": "SF-EXPLOIT-0004", "kind": "OBSERVATION",
                 "source": "exploit", "payload": {"verbs": ["settle"]},
                 "tags": [], "derived_from": ["SF-HYPOTHESIS-0003"]}
    dead = _hyp("SF-HYPOTHESIS-0005", tag="h_quota_race", title="D")
    idor = _hyp("SF-HYPOTHESIS-0006", tag="h_idor", title="I")
    trace = [{"event": "dispatch", "fact": "SF-HYPOTHESIS-0005"}]
    l = HypothesisLedger()
    project_swarm(l, [h, finding, obs, obs_child, dead, idor], trace,
                  "run1", 100)
    by_tag = {e["tag"]: e["status"] for e in l.entries}
    assert by_tag["h_state_guard"] == "confirmed"
    assert by_tag["h_hidden_verbs"] == "tested"      # observation-only
    assert by_tag["h_quota_race"] == "refuted"       # dispatched, no violation
    assert by_tag["h_idor"] == "inconclusive"        # dvlba-shaped: honest miss
    # grounding: swarm-board entries carry their fact id
    assert l.entries[0]["derived_from"] == ["SF-HYPOTHESIS-0001"]


def test_projection_skip_statefuzz_is_inconclusive():
    h = _hyp("SF-HYPOTHESIS-0001", tag="h_fsm")
    ctrl = {"id": "SF-EXPLOIT-0002", "kind": "CONTROL", "source": "exploit",
            "payload": {"event": "skip-statefuzz", "reason": "shape"},
            "tags": [], "derived_from": ["SF-HYPOTHESIS-0001"]}
    l = HypothesisLedger()
    project_swarm(l, [h, ctrl], [], "run1", 10)
    assert l.entries[0]["status"] == "inconclusive"
    assert "skip" in l.entries[0]["evidence"][-1]["note"]


def test_projection_deferred_window_from_traffic(tmp_path):
    traffic = tmp_path / "traffic.jsonl"
    with open(traffic, "w") as fh:
        fh.write(json.dumps({"status": 202, "path": "/api/refunds/async",
                             "resp_body": {"event": "/api/events/7"}}) + "\n")
        fh.write(json.dumps({"tag": "event-poll", "path": "/api/events/7",
                             "status": 200}) + "\n")
    facts = [{"id": "F-1", "kind": "FINDING", "source": "exploit",
              "payload": {"finding": {"id": "SW-ASYNC", "title": "double"},
                          "status": "verified"},
              "tags": [], "derived_from": []}]
    l = HypothesisLedger()
    project_swarm(l, facts, [], "run1", 42, traffic_path=str(traffic),
                  deferred_hits=lambda fd_list: ["SW-ASYNC"]
                  if any(f["finding"]["id"] == "SW-ASYNC"
                         and f["status"] == "verified" for f in fd_list)
                  else [])
    win = [e for e in l.entries if e["tag"] == "deferred-window"]
    assert win and win[0]["status"] == "confirmed"
    assert "SW-ASYNC" in win[0]["evidence"][-1]["note"]
    assert win[0]["tests"][0]["requests_spent"] == 1   # the event-poll


def test_projection_statefuzz_doc():
    l = HypothesisLedger()
    doc = {"findings": [
        {"id": "SF-A", "title": "neg qty", "invariant": "I4",
         "endpoint": "POST /api/cart/items"},
        {"id": "SF-SKIP", "title": "skip note", "invariant": "-"}]}
    project_statefuzz(l, doc, 73)
    st = l.stats()
    assert st["by_status"] == {"confirmed": 2}   # spine entry + SF-A
    assert st["by_source"] == {"statefuzz-standalone": 2}


# ------------------------------------------------------------------- E2E --
def _spawn_shop(port):
    proc = subprocess.Popen([sys.executable, "target/app.py", "--port",
                             str(port)], cwd=HERE, stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL)
    base = "http://127.0.0.1:%d" % port
    for _ in range(60):
        try:
            if requests.get(base + "/health", timeout=0.5).status_code == 200:
                return proc, base
        except Exception:
            time.sleep(0.2)
    proc.terminate()
    pytest.fail("target did not start")


def test_registry_writes_hypothesis_ledger(tmp_path):
    if not _SPINE_AVAILABLE:
        pytest.skip("spine not importable")
    proc, base = _spawn_shop(8394)
    try:
        out = run({"base_url": base, "out_dir": str(tmp_path / "r1"),
                   "memory_dir": str(tmp_path / "mem"),
                   "approvals": "lab", "budget": 380,
                   "stop_file": str(tmp_path / "r1" / "STOP")})
        assert out["ok"] is True
        # spine artifact exists and reflects real resolutions
        path = str(tmp_path / "r1" / "hypothesis_ledger.json")
        assert os.path.exists(path), "spine artifact missing"
        doc = json.load(open(path))
        assert doc["stats"]["total"] > 0
        assert doc["stats"]["by_status"].get("confirmed", 0) >= 1
        assert doc["score"] > 0
        assert out["hypothesis_ledger"]["stats"]["total"] == \
            doc["stats"]["total"]
        # no regression: the swarm still delivers its dvlba baseline
        assert len(out["findings"]) >= 9
    finally:
        proc.terminate()


def test_registry_ledger_off_deterministic_fallback(tmp_path):
    if not _SPINE_AVAILABLE:
        pytest.skip("spine not importable")
    proc, base = _spawn_shop(8394)
    try:
        out = run({"base_url": base, "out_dir": str(tmp_path / "r2"),
                   "memory_dir": str(tmp_path / "mem2"),
                   "approvals": "lab", "budget": 380,
                   "ledger": False,
                   "stop_file": str(tmp_path / "r2" / "STOP")})
        assert out["ok"] is True
        assert out["hypothesis_ledger"] is None
        assert not os.path.exists(str(tmp_path / "r2"
                                      / "hypothesis_ledger.json"))
        assert len(out["findings"]) >= 9   # deterministic path unimpaired
    finally:
        proc.terminate()
