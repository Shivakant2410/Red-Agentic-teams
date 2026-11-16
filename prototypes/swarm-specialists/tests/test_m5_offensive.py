"""M5 offensive-core unit tests: pre-ex ladder, post-ex ladder, recon
derivation — the techniques are tested against FAKE environments so the
wire logic (status accounting, delta math, candidate provenance, verdict
rules) is exact, without a live target. Live-lab exit evidence lives in
run_m5.py + m5-results (pre-registered predictions P1..P5)."""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

from swarm import techniques_preex as PX            # noqa: E402
from swarm import techniques_postex as PXT          # noqa: E402
from swarm.specialists.recon import (               # noqa: E402
    _derive_candidates, _collect_field_keys, _ASSET_PATH_RE)

FREIGHTLANE_PATHS = ["/api/shipments", "/api/shipments/{shipment_id}",
                     "/api/shipments/{shipment_id}/rerate",
                     "/api/credits/claim", "/api/wallet"]

SHIPMENTS_SURFACE = {
    "resource_actions": {"shipments": {
        "create": "/api/shipments",
        "create_schema": {"weight_kg": {"type": "integer"},
                          "service": {"type": "string"}},
        "param": "/api/shipments/{shipment_id}",
        "param_name": "shipment_id",
        "actions": [
            {"verb": "read", "path": "/api/shipments/{shipment_id}",
             "method": "GET", "schema": {}, "kind": ""},
            {"verb": "rerate",
             "path": "/api/shipments/{shipment_id}/rerate",
             "method": "POST",
             "schema": {"weight_kg": {"type": "integer"}}, "kind": ""},
        ]}},
    "readback": ["/api/wallet"]}


class FakePrincipal:
    def __init__(self, name):
        self.name = name
        self.auth_headers = {}


class FakeExecutor:
    """Canned wire: settle pays +credit; GETs echo an owner-matched body."""

    def __init__(self, credit=500):
        self.count = 0
        self.credit = credit
        self.principals = {}
        self.balances = {}
        self.requests = []

    def request(self, principal, method, path, body=None, phase="",
                tag=""):
        self.count += 1
        name = getattr(principal, "name", str(principal))
        self.balances.setdefault(name, 1000)
        self.requests.append((name, method, path, body))
        if method == "POST" and path.endswith("/settle"):
            self.balances[name] += self.credit
            return {"status": 200,
                    "resp_body": {"status": "settled",
                                  "payout_cents": self.credit}}
        if method == "GET":
            oid = path.rstrip("/").split("/")[-1]
            return {"status": 200, "resp_body": {"order_id": oid,
                                                 "owner": "other"}}
        if method == "POST" and path.count("/") >= 3:
            return {"status": 200, "resp_body": {"applied_cents": -100}}
        return {"status": 200, "resp_body": {"ok": True}}


class FakeEnv:
    """Duck-typed swarm.techniques.Env for technique-level tests."""

    def __init__(self, surface, budget=400, credit=500):
        self.surface = surface
        self.budget = budget
        self.ex = FakeExecutor(credit)
        self.anon = FakePrincipal("anon")
        self.notes = {}
        self.cache = {}
        self.phase = "preex"
        self.artifacts = {}
        self._n = 0

    def remaining(self):
        return self.budget - self.ex.count

    def register(self, nick):
        self._n += 1
        p = FakePrincipal("%s-%d" % (nick, self._n))
        self.ex.principals[p.name] = p
        return p

    def create(self, p, g):
        self._n += 1
        oid = "OBJ-%d" % self._n
        return {"resp_body": {"shipment_id": oid}, "status": 201}

    def wallet(self, p):
        self.ex.balances.setdefault(p.name, 1000)
        return self.ex.balances[p.name]


# ------------------------------------------------------- recon derivation --
def test_derive_candidates_lifecycle_first():
    c = _derive_candidates(FREIGHTLANE_PATHS, cap=16)
    assert c[0].startswith("/api/shipments/{shipment_id}/"), \
        "lifecycle verbs on object paths outrank collection suffixes"
    assert "/api/shipments/recent" in c
    # documented paths are never re-probed
    for p in FREIGHTLANE_PATHS:
        assert p not in c
    assert len(c) <= 16


def test_derive_candidates_excludes_documented_and_verb_tails():
    paths = ["/api/shipments/{shipment_id}/settle", "/api/shipments"]
    c = _derive_candidates(paths, cap=32)
    assert "/api/shipments/{shipment_id}/settle/settle" not in c
    assert "/api/shipments/recent" in c


def test_asset_regex_extracts_endpoint_strings():
    raw = '<script src="/static/app.js"></script><a href="/api/v1/orders">x' \
          '</a><script>fetch("/api/internal/audit")</script>'
    hits = _ASSET_PATH_RE.findall(raw)
    assert "/api/v1/orders" in hits and "/api/internal/audit" in hits


def test_collect_field_keys_filters_plumbing():
    acc = set()
    _collect_field_keys({"resp_body": {"balance_cents": 5, "error": "x",
                                       "openapi": {"paths": 1}},
                         "kind": "OBSERVATION"}, acc)
    assert "balance_cents" in acc
    assert "error" not in acc and "openapi" not in acc


# ------------------------------------------------------------ pre-ex -------
def test_id_from_body_prefers_id_shaped_keys():
    assert PX._id_from_body({"shipment_id": "S1", "weight_kg": 2}) == "S1"
    assert PX._id_from_body({"weight_kg": 2}) is None
    assert PX._id_from_body("nope") is None


def test_object_map_feeds_authz_matrix_bola_hit():
    env = FakeEnv(SHIPMENTS_SURFACE)
    pay_map, oc_map = PX.px_object_map(env)
    assert oc_map == "success" and "shipments" in pay_map["object_map"]
    env.notes["px_object_map"] = pay_map      # the ladder contract (PX.run)
    pay_mx, oc_mx = PX.px_authz_matrix(env)
    assert oc_mx == "success"
    rows = pay_mx["authz_matrix"]
    assert rows and all(r["verdict"] in ("bola-evidence", "enforced",
                                         "inconclusive:200") for r in rows)
    bola = [r for r in rows if r["verdict"] == "bola-evidence"]
    assert bola, "the fake target has no ownership check -> BOLA evidence"
    assert pay_mx["bola_hits"] == len(bola)


def test_hypotheses_raised_from_matrix_and_params():
    hyp = PX.hypotheses_from({
        "authz_matrix": [{"verdict": "bola-evidence",
                          "path": "/api/shipments/SHP-1", "status": 200,
                          "attacker": "a", "victim_owner": "B"}],
        "hidden_params": [{"param": "rate_cents", "source":
                           "schema-observed"}]})
    tags = {h[0]: h for h in hyp}
    assert tags["h_cross_tenant"][1] == 0.85
    assert any("authz-matrix" in e for e in tags["h_cross_tenant"][2])
    assert tags["h_mass_assign"][1] == 0.75
    assert "rate_cents" in tags["h_mass_assign"][2][0]


def test_param_probe_is_differential_and_capped():
    env = FakeEnv(SHIPMENTS_SURFACE, budget=400)
    pay, oc = PX.px_param_probe(env)
    # the fake target answers every write identically -> honest failure,
    # and the candidate count stays within the hard cap
    assert oc in ("success", "failure")
    if pay:
        assert len(pay["hidden_params"]) <= 12


def test_preex_ladder_dead_arm_stop():
    env = FakeEnv(SHIPMENTS_SURFACE, budget=400)
    outcomes, payloads = PX.run(env, budget_cap=70)
    assert "px_object_map" in outcomes
    assert outcomes["px_object_map"] == "success"
    assert sum(o == "failure" for o in outcomes.values()) <= 2
    assert env.ex.count <= 70


# ----------------------------------------------------------- post-ex -------
SETTLE_FINDING = {"id": "FW-STATE-SKIP",
                  "endpoint": "POST /api/shipments/{id}/settle "
                              "(from booked)",
                  "invariant": "I2", "operators": [], "evidence": []}

MASS_FINDING = {"id": "FW-MASS-PRICE",
                "endpoint": "POST /api/shipments (mass-assign:price)",
                "invariant": "I4", "operators": ["PARTIAL", "NEGATIVE"],
                "evidence": [{"candidate_field": "rate_cents",
                              "injected": {"rate_cents": 1,
                                           "weight_kg": 2},
                              "negative_probe_credit": 50000}]}


def test_op_recovery_hidden_verb_keeps_template():
    op = PXT._op_from_finding(SETTLE_FINDING, SHIPMENTS_SURFACE)
    assert op == ("POST", "/api/shipments/{id}/settle", {}, None, None)


def test_op_recovery_negative_variant_for_amplification():
    op = PXT._op_from_finding(MASS_FINDING, SHIPMENTS_SURFACE)
    method, path, body, res, g = op
    assert method == "POST" and path == "/api/shipments"
    assert body["rate_cents"] == -50000, \
        "amplification replays the PROVEN worst case, not a reconstruction"


def test_op_recovery_documented_action_uses_template():
    fd = {"endpoint": "POST /api/shipments/{shipment_id}/rerate "
                      "(resize-cycle)",
          "evidence": [{"injected": {"weight_kg": 3}}]}
    op = PXT._op_from_finding(fd, SHIPMENTS_SURFACE)
    assert op[1] == "/api/shipments/{shipment_id}/rerate"
    assert op[2] == {"weight_kg": 3}


def test_amplify_measures_reach_and_delta():
    env = FakeEnv(SHIPMENTS_SURFACE, budget=400, credit=500)
    pay, oc = PXT.px_amplify(env, SETTLE_FINDING, env.surface)
    assert oc == "success"
    amp = pay["amplification"]
    assert amp["victims_reached"] == 3
    assert amp["aggregate_delta_cents"] == 1500
    assert all(r["delta_cents"] == 500 for r in amp["rows"])


def test_persist_replay_detects_repeatable_credit():
    env = FakeEnv(SHIPMENTS_SURFACE, budget=400, credit=500)
    pay, oc = PXT.px_persist_replay(env, SETTLE_FINDING, env.surface)
    assert oc == "success"
    per = pay["persistence"]
    assert per["repeatable"] is True
    assert all(d["delta_cents"] == 500 for d in per["replays"])


def test_scope_traverse_records_capability_footprint():
    env = FakeEnv(SHIPMENTS_SURFACE, budget=400)
    pay, oc = PXT.px_scope_traverse(env, env.register("pxs"),
                                    env.surface)
    assert oc == "success"
    cp = pay["capability_footprint"]
    assert cp["accessible"] == ["/api/wallet",
                                "/api/shipments/{shipment_id}"]
    assert cp["probed"] == 2


def test_postex_run_never_fires_without_findings():
    env = FakeEnv(SHIPMENTS_SURFACE, budget=400)
    outcomes, payloads = PXT.run(env, [])
    assert outcomes == {} and payloads == {}


# ------------------------------------------------------ traffic harvest ----
def test_traffic_keys_observed_vocabulary(tmp_path):
    tf = tmp_path / "traffic.jsonl"
    rows = [
        {"resp_body": {"balance_cents": 5, "error": "x",
                       "shipment_id": "S1", "rate_cents": 3998}},
        {"resp_body": {"shipments": [{"shipment_id": "S2",
                                      "picked_up_at": 1.0}]}},
        {"resp_body": "not-a-dict"},
    ]
    tf.write_text("\n".join(json.dumps(r) for r in rows))
    keys = PX.traffic_keys(str(tf))
    assert "rate_cents" in keys and "picked_up_at" in keys
    assert "error" not in keys
    assert PX.traffic_keys(str(tmp_path / "missing.jsonl")) == []
