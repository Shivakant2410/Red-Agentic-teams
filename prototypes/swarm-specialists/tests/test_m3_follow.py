"""M3 test suite — follow-through, ambient oracles, live FSM, attack graph.

Unit layer : watcher attribution (adopt/settle), FSM induce (409-gating +
             walk + built-in replay), gated/replayable row derivation,
             terminal gate, attack-graph build (evidence states,
             next_actions ranking) and artifact save.
E2E layer  : the M3 exit in miniature — a REAL freightlane run through the
             registry finds GV-8 as FW-STATE-SKIP (verified, wallet-delta +
             409-gated sibling evidence), the ambient watcher publishes the
             unattributed open-vocab credit as an ESCALATION, the attack
             graph artifact exists with the settle edge, M2's findings all
             still verify, M1's markers stay >= 2, decoys stay clean.
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
from engine import fsm, attackgraph as ag                      # noqa: E402
from engine.watch import WalletWatcher                         # noqa: E402
from swarm.registry_tool import run, _SPINE_AVAILABLE          # noqa: E402

FREIGHTLANE = os.path.normpath(os.path.join(
    HERE, "..", "hard-lab", "freightlane"))


# --------------------------------------------------------------- watcher --
class _StubEx:
    """Scripted executor: path -> (status, body). Registers principals."""

    def __init__(self, script):
        self.script = script
        self.count = 0
        self.principals = {}

    def request(self, p, method, path, body=None, phase="t", tag="t"):
        self.count += 1
        status, body_out = self.script.get(path, (404, {}))
        return {"status": status, "resp_body": body_out, "path": path,
                "tag": tag}


class _P:
    def __init__(self, name):
        self.name = name


def test_watcher_attributed_vs_unexplained():
    ex = _StubEx({"/api/wallet": (200, {"balance_cents": 100})})
    events = []
    w = WalletWatcher(ex, {"readback": ["/api/wallet"]}, events=events)
    p = _P("u1")
    ex.principals["u1"] = p
    w.begin_act("h_open_vocab")
    assert w.adopt(p) is True                    # baseline = 100
    ex.script["/api/wallet"] = (200, {"balance_cents": 3100})
    # act produced NO finding -> the +3000 delta is unexplained
    unexplained = w.settle_act(produced_findings=[])
    assert len(unexplained) == 1
    assert unexplained[0]["delta"] == 3000
    assert unexplained[0]["attributed"] is False
    # next act DOES produce a finding -> attributed
    w.begin_act("h_cross_tenant")
    ex.script["/api/wallet"] = (200, {"balance_cents": 3200})
    assert w.settle_act(produced_findings=[{"kind": "FINDING"}]) == []
    assert events[-1]["attributed"] is True and events[-1]["delta"] == 100
    assert w.summary()["unexplained"] == 1


def test_watcher_adopt_cap_per_act():
    ex = _StubEx({"/api/wallet": (200, {"balance_cents": 5})})
    w = WalletWatcher(ex, {"readback": ["/api/wallet"]})
    w.begin_act("h_quota_race")
    taken = [w.adopt(_P("p%d" % i)) for i in range(6)]
    assert taken == [True, True, True, False, False, False]   # cap = 3


def test_watcher_no_readback_is_inert():
    ex = _StubEx({})
    w = WalletWatcher(ex, {"readback": []})
    w.begin_act("t")
    assert w.adopt(_P("x")) is False
    assert w.settle_act([]) == []


# ------------------------------------------------------------------- fsm --
def test_fsm_state_echo():
    assert fsm.state_echo({"status": "booked"}) == "booked"
    assert fsm.state_echo({"state": "settled"}) == "settled"
    assert fsm.state_echo({"amount": 3}) is None
    assert fsm.state_echo("junk") is None


def test_fsm_induce_walk_gating_and_replay():
    # scripted shipment-ish lifecycle: pickup advances, deliver is gated
    # from booked (409) then advances from picked_up; pickup re-answered
    # 409 at the new state = the built-in replay check.
    states = {"o1": "booked"}

    def state_body():
        return {"status": states["o1"]}

    class _FSMEx:
        count = 0
        principals = {}

        def request(self, p, method, path, body=None, phase="t", tag="t"):
            _FSMEx.count += 1
            if method == "GET":
                return {"status": 200, "resp_body": state_body(),
                        "path": path}
            verb = path.rsplit("/", 1)[-1]
            st = states["o1"]
            if verb == "pickup":
                if st == "booked":
                    states["o1"] = "picked_up"
                    return {"status": 200, "resp_body": {}, "path": path}
                return {"status": 409, "resp_body": {"error": "bad state"},
                        "path": path}
            if verb == "deliver":
                if st == "picked_up":
                    states["o1"] = "delivered"
                    return {"status": 200, "resp_body": {}, "path": path}
                return {"status": 409, "resp_body": {"error": "bad state"},
                        "path": path}
            if verb == "settle":
                # money verb: must NEVER be probed by the inducer
                raise AssertionError("inducer probed the money verb")
            return {"status": 404, "resp_body": {}, "path": path}

    ex = _FSMEx()
    g = {"param": "/api/things/{id}", "param_name": "id", "actions": []}
    table = fsm.induce(ex, "p", "things", g, "o1", known_verbs=set(),
                       discovered_verbs=["settle"])   # terminal: excluded
    verbs_walked = [r["verb"] for r in table["rows"]]
    assert "settle" not in verbs_walked
    assert table["state0"] == "booked"
    gated = fsm.gated_rows(table)
    assert {r["verb"] for r in gated} >= {"deliver", "pickup"}
    # pickup was answered 200 (booked->picked_up): the walk re-probed it
    # at picked_up and got 409 -> no replayable row
    assert fsm.replayable_rows(table) == {}
    assert table["probes"] <= 16


def test_fsm_replayable_rows_detection():
    table = {"rows": [
        {"verb": "advance", "state_before": "s1", "status": 200,
         "state_after": "s2", "gated": False},
        {"verb": "advance", "state_before": "s2", "status": 200,
         "state_after": "s3", "gated": False}]}
    assert set(fsm.replayable_rows(table)) == {"advance"}


# ---------------------------------------------------------- attack graph --
def test_attackgraph_build_and_next_actions():
    surface = {
        "endpoints": ["/api/wallet"], "readback": ["/api/wallet"],
        "resource_actions": {
            "shipments": {"create": "/api/shipments", "actions": [
                {"verb": "rerate", "path": "/api/shipments/{id}/rerate",
                 "method": "POST"},
                {"verb": "settle", "path": "/api/shipments/{id}/settle",
                 "method": "POST", "discovered": True}],
                "param": "/api/shipments/{id}", "param_name": "id"},
            "vouchers": {"create": "/api/vouchers", "actions": [
                {"verb": "release", "path": "/api/vouchers/{id}/release",
                 "method": "POST", "discovered": True}],
                "param": None, "param_name": None}},
        "discoveries": {
            "undocumented_verbs": [
                {"resource": "shipments", "verb": "settle", "status": 200},
                {"resource": "vouchers", "verb": "release", "status": 200}],
            "undocumented_resources": [{"noun": "vouchers",
                                        "path": "/api/vouchers"}],
            "verb_facts": [
                {"resource": "shipments", "verb": "settle", "status": 200,
                 "credited": True},
                {"resource": "vouchers", "verb": "release", "status": 200,
                 "credited": False}],
            "readback_added": [], "mined_fields": {}}}
    facts = [{"kind": "SURFACE", "payload": surface, "tags": []}]
    ambient = [{"name": "ov-1", "tag": "h_open_vocab", "delta": 3998,
                "attributed": False}]
    doc = ag.build(facts, ambient_events=ambient)
    sm = doc["surface_map"]
    vouchers = next(n for n in sm["nodes"] if n["id"] == "res:vouchers")
    assert vouchers["layer"] == "discovered"
    settle_edge = next(e for e in sm["edges"]
                       if e["verb"] == "settle")
    assert settle_edge["layer"] == "discovered"
    # credited verbs are money edges on the attack graph
    credit_edges = [e for e in doc["attack_graph"]["edges"]
                    if e["kind"] == "credit-verb"]
    assert any(e["resource"] == "shipments" and e["verb"] == "settle"
               for e in credit_edges)
    # next_actions ranks edges that still need an agent: untested probes or
    # credit-only terminal verbs (the GV-8 follow-through)
    nas = doc["next_actions"]
    assert nas and all(n["technique"] for n in nas)
    assert all(e["evidence"] in ("untested", "credit-only")
               for e in doc["attack_graph"]["edges"]
               if e["id"] in {n["edge"] for n in nas})
    # the credited settle verb carries the follow-through suggestion
    follow = [e for e in doc["attack_graph"]["edges"]
              if e["kind"] == "terminal-followup"]
    assert any(e["resource"] == "shipments" and e["verb"] == "settle"
               and e["technique"] == "h_state_skip" for e in follow)
    assert "e-credit-shipments-settle" in doc["money_paths"]
    tmp = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                       "..", "..", "..", "tmp-ag-test")
    try:
        path = ag.save(doc, tmp)
        assert os.path.exists(path)
    finally:
        import shutil
        shutil.rmtree(tmp, ignore_errors=True)


def test_attackgraph_terminal_suggestions():
    edges = [{"id": "e1", "from": "acct:any", "to": "goal:wallet-credit",
              "kind": "terminal-transition", "resource": "shipments",
              "verb": "settle", "requests": 4, "evidence": "untested",
              "technique": "h_state_skip", "path": "/x"}]
    nas = ag.next_actions(edges)
    assert len(nas) == 1 and nas[0]["technique"] == "h_state_skip"


# ------------------------------------------------------------------- E2E --
def _spawn(port):
    proc = subprocess.Popen([sys.executable, "target/app.py", "--port",
                             str(port)], cwd=FREIGHTLANE,
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL)
    base = "http://127.0.0.1:%d" % port
    for _ in range(60):
        try:
            if requests.get(base + "/health", timeout=0.5).status_code == 200:
                return proc, base
        except Exception:
            time.sleep(0.2)
    proc.terminate()
    pytest.fail("freightlane target did not start")


def test_freightlane_m3_exit_in_miniature(tmp_path):
    """THE M3 exit criteria, executed: GV-8 found as FW-STATE-SKIP with
    wallet-delta + gated-sibling evidence, the ambient watcher exposes the
    unattributed open-vocab credit, the attack graph artifact exists with
    the settle edge, and the M2/M1 baselines all still hold."""
    if not _SPINE_AVAILABLE:
        pytest.skip("spine not importable")
    proc, base = _spawn(8475)
    try:
        out = run({"base_url": base, "out_dir": str(tmp_path / "m3"),
                   "memory_dir": str(tmp_path / "m3mem"),
                   "approvals": "lab", "budget": 720,
                   "stop_file": str(tmp_path / "m3" / "STOP")})
        assert out["ok"] is True, out
        statuses = {f["id"]: f["status"] for f in out["findings"]}
        ids = set(statuses)

        # --- E1: GV-8 autonomous + verified -------------------------------
        assert statuses.get("FW-STATE-SKIP") == "verified", statuses
        full = json.load(open(str(tmp_path / "m3" / "findings.json")))
        by_id = {e["finding"]["id"]: e["finding"] for e in full["findings"]}
        ev = by_id["FW-STATE-SKIP"]["evidence"][0]
        assert ev["verb"] == "settle" and ev["resource"] == "shipments"
        assert ev["from_state"] == "booked"
        assert ev["wallet_delta"] and ev["wallet_delta"] > 0
        assert ev["gated_siblings"], "no 409-gated sibling evidence"
        assert ev["after_state"] == "settled"

        # --- E2: the ambient watcher saw the band-D leak -------------------
        ambient = full.get("ambient_watch") or {}
        assert ambient.get("events", 0) >= 1
        unexplained = [d for d in ambient.get("deltas", [])
                       if not d.get("attributed")]
        assert unexplained, "no unattributed ambient credit recorded"
        bb = json.load(open(str(tmp_path / "m3" / "blackboard.json")))
        esc = [f for f in bb if f["kind"] == "ESCALATION" and
               f["payload"].get("event") == "ambient-credit"]
        assert esc and esc[0]["derived_from"], "ambient ESCALATION ungrounded"

        # --- E3: the attack graph artifact exists and carries the edge ----
        graph = json.load(open(str(tmp_path / "m3" / "attack_surface.json")))
        assert "e-credit-shipments-settle" in graph["money_paths"]
        assert graph["next_actions"] is not None

        # --- E4: M2/M1 baselines all still hold ---------------------------
        for fid in ("FW-RELEASE-REPLAY", "FW-CREDIT-RACE",
                    "FW-DEPUTY-CREDIT", "FW-MASS-PRICE",
                    "FW-TOCTOU-SETTLE", "FW-SETTLED-CANCEL",
                    "FW-ROUND-DRIFT"):
            assert statuses.get(fid) == "verified", (fid, statuses)
        assert out["markers_registered"] >= 2
        assert not any("QUOTA-RACE" in i for i in ids)
        assert len(out["llm_seam_calls"]) == 0
    finally:
        proc.terminate()
