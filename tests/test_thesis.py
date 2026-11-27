"""The attack-thesis layer: deep, target-specific chained reasoning must
outrank generic scanner classes, and malformed input must degrade safely."""
from redteam.thesis import (AttackThesis, generate_theses, theses_briefing,
                            validate_thesis, extract_json_array)

_KEYS = {"https://m.test/orders/status", "https://m.test/wallet/balance"}


def _deep():
    return {
        "target_model": "C2C marketplace; buyer funds escrow, seller paid on delivery",
        "belief": "seller payout trusts a client-supplied delivered flag on the order",
        "rationale": ("the /orders/status POST accepts delivered=true from the client "
                      "with no carrier confirmation and the payout job reads that same "
                      "flag, so a seller can mark their own order delivered before "
                      "shipping which then triggers escrow release to themselves"),
        "invariant": "escrow releases only after delivery is confirmed server-side",
        "chain": ["own buyer+seller", "buyer funds escrow", "seller sets delivered=true",
                  "payout releases to seller without shipping"],
        "predicted_proof": "payout flips to released on my own order with no carrier event",
        "kill_condition": "server rejects delivered=true without a carrier token",
        "impact": "financial", "technique": "logic.workflow",
        "target": "https://m.test/orders/status",
    }


def _generic():
    return {
        "belief": "reflected XSS on the search parameter",
        "rationale": "q reflects unencoded",
        "invariant": "user input is encoded on output",
        "chain": [], "impact": "info", "target": "https://m.test/search",
    }


def test_deep_thesis_outranks_generic():
    deep = validate_thesis(_deep(), 1, _KEYS)
    generic = validate_thesis(_generic(), 2, _KEYS)
    assert deep is not None and generic is not None
    assert deep.score > generic.score
    # the deep one must be decisively preferred, not marginally
    assert deep.score > generic.score * 5
    assert deep.novelty > generic.novelty
    assert deep.impact == "financial"


def test_thesis_requires_belief_and_invariant():
    assert validate_thesis({"belief": "x"}, 1, set()) is None          # no invariant
    assert validate_thesis({"invariant": "y"}, 1, set()) is None        # no belief
    assert validate_thesis({}, 1, set()) is None


def test_unknown_impact_defaults_low():
    t = validate_thesis({"belief": "b", "invariant": "i", "impact": "bogus"}, 1, set())
    assert t is not None and t.impact == "info"


def test_extract_json_array_handles_fences_and_objects():
    arr = extract_json_array('```json\n[{"a":1},{"b":2}]\n```')
    assert arr == [{"a": 1}, {"b": 2}]
    one = extract_json_array('noise {"a":1} trailing')
    assert one == [{"a": 1}]
    assert extract_json_array("not json") is None


def test_generate_theses_ranks_and_renumbers():
    class _Msg:
        def __init__(self, c): self.message = {"content": c}

    class _Client:
        def chat(self, messages, tools=None, role=None):
            import json
            return _Msg(json.dumps([_generic(), _deep()]))  # generic first on input

    out = generate_theses(_Client(), lens="logic", evidence_digest="endpoints: ...",
                          evidence_keys=_KEYS, objective_text="test")
    assert len(out) == 2
    # ranked best-first regardless of input order, and ids renumbered
    assert out[0].id == "T01" and out[0].impact == "financial"
    assert out[0].score > out[1].score


def test_generate_theses_empty_on_client_failure():
    class _Boom:
        def chat(self, *a, **k): raise RuntimeError("no model")
    assert generate_theses(_Boom(), lens="exploit", evidence_digest="x") == []


def test_briefing_renders_chain_and_prove():
    t = validate_thesis(_deep(), 1, _KEYS)
    b = theses_briefing([t])
    assert "chain:" in b and "prove by:" in b and "drop if:" in b
    assert "falsifiable belief" in b.lower()


def test_generate_theses_prefers_compact_world_model_over_raw_digest():
    import json

    class _Msg:
        def __init__(self, content): self.message = {"content": content}

    class _Client:
        def __init__(self): self.messages = None
        def chat(self, messages, tools=None, role=None):
            self.messages = messages
            return _Msg(json.dumps([_deep()]))

    client = _Client()
    projection = {"schema_version": 1, "facts": [{
        "id": "app_component:orders", "kind": "app_component",
        "key": "https://m.test/orders/status", "epistemic_state": "observed",
        "evidence_ref_ids": ["traffic_seq:9"],
        "attributes": {"component_type": "http_endpoint", "layer": "application"},
    }]}
    out = generate_theses(
        client, lens="logic", evidence_digest="RAW-8KB-DUMP-MUST-NOT-BE-SENT",
        evidence_keys=_KEYS, objective_text="test",
        world_model_projection=projection,
    )
    prompt = client.messages[1]["content"]
    assert out and "TYPED WORLD MODEL" in prompt
    assert "traffic_seq:9" in prompt
    assert "RAW-8KB-DUMP-MUST-NOT-BE-SENT" not in prompt
