"""M2 test suite — surface truth + open vocabulary (G2+G4).

Unit layer : template normalisation, echo field mining, id extraction,
             noun existence oracle, resource opening (object/error/async),
             verb facts with credit detection, surface merge (discovered
             actions are shape-identical to doc actions).
E2E layer  : the M2 exit in miniature — a REAL freightlane run through the
             registry discovers the undocumented voucher resource, the
             rebook/recent/settle/release/consume verbs, mines rate_cents
             from the create echo, and finds GV-1/GV-2/GV-3/GV-6 with
             fresh-principal verification — M1's markers still >= 2.
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
from engine import surface as sf                          # noqa: E402
from swarm.registry_tool import run, _SPINE_AVAILABLE     # noqa: E402

FREIGHTLANE = os.path.normpath(os.path.join(
    HERE, "..", "hard-lab", "freightlane"))


# ----------------------------------------------------------- primitives --
def test_normalize_templates():
    assert sf.normalize("/api/shipments/{shipment_id}/rerate") == \
        "/api/shipments/{id}/rerate"
    assert sf.normalize("/api/wallet") == "/api/wallet"     # literals kept
    assert sf.normalize(None) is None


def test_money_fields_echo_mining():
    # the freightlane create echo names its own price field (GV-3 evidence)
    schema = {"weight_kg": {"type": "integer"}, "service": {"type": "string"}}
    body = {"shipment_id": "SHP-x", "owner": "o", "weight_kg": 2,
            "service": "standard", "rate_cents": 3998, "status": "booked"}
    assert sf.money_fields(body, schema) == ["rate_cents"]
    # declared fields are never candidates (D-2 stays a decoy)
    assert "weight_kg" not in sf.money_fields(body, schema)
    assert sf.money_fields({"status": "ok"}, {}) == []
    assert sf.money_fields("junk", {}) == []


def test_extract_ids():
    body = {"shipments": [{"shipment_id": "SHP-abcdef1234", "owner": "x"},
                          {"shipment_id": "SHP-9876543210", "owner": "y"}],
            "balance_cents": 5}
    ids = sf.extract_ids(body)
    assert "SHP-abcdef1234" in ids and "SHP-9876543210" in ids
    assert sf.extract_ids({"error": "nope"}) == []


class _StubEx:
    """Scripted executor: path -> status (+optional body). Records calls."""

    def __init__(self, script):
        self.script = script
        self.count = 0

    def request(self, p, method, path, body=None, phase="t", tag="t"):
        self.count += 1
        status, body_out = self.script.get(path, (404, {}))
        return {"status": status, "resp_body": body_out, "path": path,
                "tag": tag}


def test_probe_nouns_existence_oracle():
    ex = _StubEx({"/api/vouchers": (405, {}),      # POST-only: EXISTS
                  "/api/payouts": (405, {}),       # seam noun: EXISTS
                  "/api/coupons": (404, {})})
    hits = sf.probe_nouns(ex, "p", ["/api/wallet", "/api/shipments"],
                          budget_guard=lambda: True)
    nouns = [h["noun"] for h in hits]
    assert "vouchers" in nouns and "payouts" in nouns
    assert "coupons" not in nouns                  # 404 = absent
    vouchers = next(h for h in hits if h["noun"] == "vouchers")
    assert vouchers["documented"] is False         # not in the doc endpoints


def test_open_resource_kinds():
    ex = _StubEx({
        "/api/vouchers": (201, {"voucher_id": "VCH-abc12345",
                                "face_cents": 30000}),
        "/api/payouts": (400, {"error": "amount_cents out of range"}),
        "/api/async1": (202, {"job_id": "J-1", "event": "/api/async1/J-1/e"}),
        "/api/nowhere": (404, {})})
    obj = sf.open_resource(ex, "p", "/api/vouchers")
    assert obj["kind"] == "object" and obj["body"]["face_cents"] == 30000
    err = sf.open_resource(ex, "p", "/api/payouts")
    assert err["kind"] == "error" and err["learned_field"] == "amount_cents"
    async_ = sf.open_resource(ex, "p", "/api/async1")
    assert async_["kind"] == "async"               # hands off to the driver
    assert sf.open_resource(ex, "p", "/api/nowhere")["kind"] == "absent"


def test_probe_verbs_credit_detection():
    ex = _StubEx({
        "/api/vouchers/V1/release": (200, {"credited_cents": 30000}),
        "/api/vouchers/V1/consume": (200, {"credited_cents": 30000}),
        "/api/vouchers/V1/settle": (404, {})})
    facts = sf.probe_verbs(ex, "p", "vouchers", "V1", set(),
                           vocab=("release", "consume", "settle"))
    by_verb = {f["verb"]: f for f in facts}
    assert by_verb["release"]["credited"] is True
    assert by_verb["consume"]["credited"] is True
    assert "settle" not in by_verb                 # 404 = verb absent


def test_merge_produces_uniform_actions_and_readback():
    surface = {"endpoints": ["/api/wallet"],
               "readback": ["/api/wallet"],
               "resource_actions": {"shipments": {
                   "create": "/api/shipments", "actions": [],
                   "param": "/api/shipments/{shipment_id}",
                   "param_name": "shipment_id"}}}
    disc = {
        "resources": [{"noun": "vouchers", "path": "/api/vouchers",
                       "status": 405, "documented": False,
                       "open_kind": "object", "open_status": 201,
                       "create_schema": {}, "object_id": "VCH-1"}],
        "actions": [{"resource": "shipments", "verb": "rebook",
                     "path": "/api/shipments/S1/rebook", "status": 200},
                    {"resource": "vouchers", "verb": "release",
                     "path": "/api/vouchers/V1/release", "status": 200}],
        "verb_facts": [{"resource": "shipments", "verb": "rebook",
                        "status": 200, "credited": True}],
        "single_use": [{"resource": "vouchers", "verb": "consume",
                        "first": 200, "second": 409, "single_use": True}],
        "readback": [{"path": "/api/shipments/recent", "resource":
                      "shipments", "sub": "recent", "body": {}}],
        "mined_fields": {"shipments": ["rate_cents"]},
        "doc_suspect": {}}
    merged = sf.merge(surface, disc)
    # discovered actions are shape-identical to doc actions + discovered flag
    a = next(x for x in
             merged["resource_actions"]["shipments"]["actions"]
             if x["verb"] == "rebook")
    assert a["method"] == "POST" and a["schema_unknown"] is True and \
        a["discovered"] is True
    assert merged["resource_actions"]["vouchers"]["create"] == "/api/vouchers"
    assert "/api/shipments/recent" in merged["readback"]        # GV-2 read
    assert merged["resource_actions"]["shipments"]["mined_fields"] == \
        ["rate_cents"]
    d = merged["discoveries"]
    assert {(v["resource"], v["verb"]) for v in d["undocumented_verbs"]} == \
        {("shipments", "rebook"), ("vouchers", "release")}
    assert d["undocumented_resources"] == [
        {"noun": "vouchers", "path": "/api/vouchers", "open_kind": "object",
         "open_status": 201}]
    assert d["single_use"][0]["single_use"] is True
    # purity: the input surface is untouched
    assert surface["resource_actions"]["shipments"]["actions"] == []
    assert surface["readback"] == ["/api/wallet"]


def test_merge_is_idempotent():
    surface = {"resource_actions": {}, "readback": []}
    disc = {"resources": [], "actions": [{"resource": "vouchers",
                                          "verb": "release",
                                          "path": "/api/vouchers/V1/release",
                                          "status": 200}],
            "verb_facts": [], "single_use": [],
            "readback": [{"path": "/api/x/recent", "resource": "x",
                          "sub": "recent", "body": {}}],
            "mined_fields": {}, "doc_suspect": {}}
    once = sf.merge(surface, disc)
    twice = sf.merge(once, disc)
    assert len(twice["resource_actions"]["vouchers"]["actions"]) == 1
    assert twice["readback"].count("/api/x/recent") == 1


def test_suspect_doc_scan(tmp_path):
    tp = tmp_path / "traffic.jsonl"
    rows = [{"tag": "create", "status": 400, "path": "/api/broken"},
            {"tag": "create", "status": 422, "path": "/api/broken"},
            {"tag": "create", "status": 400, "path": "/api/broken"},
            {"tag": "create", "status": 201, "path": "/api/shipments"}]
    with open(tp, "w") as fh:
        for r in rows:
            fh.write(json.dumps(r) + "\n")

    class _Ex:
        traffic_path = str(tp)

    assert sf.scan_traffic_suspect_docs(_Ex()) == {"/api/broken": 3}


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


def test_freightlane_m2_exit_in_miniature(tmp_path):
    """THE M2 exit criteria, executed: open vocabulary discovers the hidden
    voucher resource + >= 3 undocumented verbs, mines rate_cents from the
    echo, and GV-1/GV-2/GV-3/GV-6 are found AND re-verified with fresh
    principals. M1's markers stay >= 2; decoys stay clean."""
    if not _SPINE_AVAILABLE:
        pytest.skip("spine not importable")
    proc, base = _spawn(8473)
    try:
        out = run({"base_url": base, "out_dir": str(tmp_path / "m2"),
                   "memory_dir": str(tmp_path / "m2mem"),
                   "approvals": "lab", "budget": 620,
                   "stop_file": str(tmp_path / "m2" / "STOP")})
        assert out["ok"] is True, out
        findings = {f["id"]: f for f in out["findings"]}
        statuses = {f["id"]: f["status"] for f in out["findings"]}

        # --- the four band-C covert classes, verified --------------------
        assert statuses.get("FW-RELEASE-REPLAY") == "verified", findings
        assert statuses.get("FW-CREDIT-RACE") == "verified", findings
        assert statuses.get("FW-DEPUTY-CREDIT") == "verified", findings
        assert statuses.get("FW-MASS-PRICE") == "verified", findings

        # GV evidence specifics (grounded, not name-matched) — full form
        # lives in findings.json; the run summary carries id/status only
        full = json.load(open(str(tmp_path / "m2" / "findings.json")))
        by_id = {e["finding"]["id"]: e["finding"] for e in full["findings"]}
        ev = by_id["FW-MASS-PRICE"]["evidence"][0]
        assert ev["candidate_field"] == "rate_cents"
        assert ev["mined_from_echo"] is True
        assert ev["negative_probe_credit"] and ev["negative_probe_credit"] > 0
        race_ev = by_id["FW-CREDIT-RACE"]["evidence"][0]
        assert race_ev["winners"] >= 2 and race_ev["wallet_delta"] >= \
            2 * (race_ev["face_value"] or 0)

        # --- >= 3 undocumented verbs in the revised SURFACE fact ---------
        bb = json.load(open(str(tmp_path / "m2" / "blackboard.json")))
        revisions = [f for f in bb if f["kind"] == "SURFACE" and
                     "surface-update" in f.get("tags", [])]
        assert revisions, "no revised surface published"
        undoc = revisions[-1]["payload"]["discoveries"][
            "undocumented_verbs"]
        verbs = {(v["resource"], v["verb"]) for v in undoc}
        assert len(verbs) >= 3, verbs
        assert ("vouchers", "release") in verbs
        assert any(v == ("shipments", "rebook") for v in verbs), verbs
        # the discovery observation exists and is grounded
        obs = [f for f in bb if f["kind"] == "OBSERVATION" and
               "open-vocab" in f.get("tags", [])]
        assert obs and obs[0]["derived_from"]

        # --- readback added: the GV-2 leak path is a surface fact --------
        assert "/api/shipments/recent" in \
            revisions[-1]["payload"]["readback"]

        # --- M1 still holds: deferred-window violations + markers --------
        assert statuses.get("FW-TOCTOU-SETTLE") == "verified", findings
        assert statuses.get("FW-SETTLED-CANCEL") == "verified", findings
        assert out["markers_registered"] >= 2

        # --- decoys clean + deterministic --------------------------------
        assert not any("QUOTA-RACE" in i for i in findings)
        assert len(out["llm_seam_calls"]) == 0
    finally:
        proc.terminate()
