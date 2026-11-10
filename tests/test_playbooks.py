"""First-party technique playbooks (data/playbooks/ + find_techniques).

The corpus IS the product here: the linter (load_playbooks) doubles as the CI gate
so a malformed playbook can never ship, and the cross-check proves every playbook
names tools the agent can actually call (or documented future tools from the plan).
The tool's contract: offline, deterministic, full-body results, and a phase index
when nothing matches — the agent never needs the web for tradecraft.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from redteam.tools.playbooks import (
    DEFAULT_PLAYBOOK_ROOT,
    FindTechniquesTool,
    load_playbooks,
)

ROOT = DEFAULT_PLAYBOOK_ROOT

# Tools playbooks may reference that are PLANNED but not yet registered
# (docs/tool-integration-plan.md W1b/W3/R1). Everything else must be real.
FUTURE_TOOLS = {"host_probe", "port_scan", "oob_watch", "nxc_sweep", "adcs_inspect",
                "kerbrute_enum", "kerberoast"}


class _Audit:
    def record(self, *a, **k):
        pass


class _Ctx:
    def __init__(self, root=None):
        if root is not None:
            self.playbook_root = root
        self.audit = _Audit()


# -- corpus lint (CI gate) -----------------------------------------------------------

def test_corpus_loads_and_validates():
    playbooks = load_playbooks(ROOT)
    assert len(playbooks) >= 12
    ids = [p["id"] for p in playbooks]
    assert len(ids) == len(set(ids))


def test_corpus_covers_the_whole_kill_chain():
    playbooks = load_playbooks(ROOT)
    phases = {p["kill_chain"] for p in playbooks}
    assert {"recon", "surface", "enum", "exploit", "creds", "postex",
            "lateral", "report"} <= phases


def test_every_playbook_technique_is_concrete():
    for p in load_playbooks(ROOT):
        steps = p["technique"]
        assert len(steps) >= 120, f"{p['id']}: technique too thin"
        # Concrete means it names at least one platform tool in its steps or tools list.
        assert p.get("tools"), f"{p['id']}: no tools referenced"
        assert "verify_hint" in p and len(p["verify_hint"]) >= 40, \
            f"{p['id']}: missing verify hint"


def test_every_playbook_tool_is_real_or_documented_future():
    from redteam.tools import build_registry
    registry = set(build_registry(enable_sandbox=False, enable_browser=False))
    for p in load_playbooks(ROOT):
        for tool in p.get("tools", []):
            assert tool in registry or tool in FUTURE_TOOLS, \
                f"{p['id']} references unknown tool '{tool}'"


def test_linter_rejects_bad_corpus(tmp_path):
    bad = tmp_path / "broken.yaml"
    bad.write_text("id: not-enough\nname: x\nkill_chain: exploit\n", encoding="utf-8")
    with pytest.raises(ValueError, match="missing required field"):
        load_playbooks(tmp_path)

    empty = tmp_path / "sub"
    empty.mkdir()
    with pytest.raises(ValueError, match="no playbooks"):
        load_playbooks(empty)


# -- find_techniques tool ------------------------------------------------------------

def _run(**kwargs):
    return json.loads(FindTechniquesTool().run(ctx=_Ctx(), **kwargs))


def test_lookup_by_kill_chain_returns_full_body_offline():
    out = _run(kill_chain="exploit", surface="web")
    assert out["ok"]
    assert out["results"], "exploit/web must have playbooks"
    for r in out["results"]:
        assert r["steps"] and r["verify_hint"]          # full body, not a pointer
        assert r["risk_class"] in (0, 1, 2, 3, 4)
        assert "verify" in out["note"].lower()


def test_query_ranks_the_right_playbook_first():
    out = _run(kill_chain="exploit", query="template injection")
    assert out["results"][0]["id"] == "exploit-ssti-detection"

    out = _run(kill_chain="exploit", surface="web", query="idor authorization")
    assert out["results"][0]["id"] == "exploit-idor-authz-matrix"


def test_surface_filter_narrows_correctly():
    out = _run(kill_chain="creds", surface="ad")
    assert out["results"]
    assert all("ad" in r["surfaces"] for r in out["results"])
    assert {"creds-kerberoast-chain", "creds-adcs-esc-chain"} <= \
        {r["id"] for r in out["results"]}


def test_no_match_returns_corpus_index_not_silence():
    out = _run(kill_chain="recon", surface="k8s")
    assert out["ok"] and out["results"] == []
    assert out["corpus_index"]["exploit"] >= 5
    assert "do not search the web" in out["note"]


def test_invalid_phase_is_a_clean_error():
    out = _run(kill_chain="hiring")
    assert out["ok"] is False and "kill_chain" in out["error"]


def test_missing_corpus_is_a_clean_error():
    out = json.loads(FindTechniquesTool().run(
        ctx=_Ctx(root=Path("/nonexistent/playbooks")), kill_chain="enum"))
    assert out["ok"] is False and "missing" in out["error"]


def test_deterministic_order_and_limit_cap():
    a = _run(kill_chain="exploit", limit=8)
    b = _run(kill_chain="exploit", limit=8)
    assert [r["id"] for r in a["results"]] == [r["id"] for r in b["results"]]
    assert len(a["results"]) <= 8


def test_registry_includes_find_techniques():
    from redteam.tools import build_registry
    registry = build_registry(enable_sandbox=False, enable_browser=False)
    assert "find_techniques" in registry
    schema = registry["find_techniques"].schema()
    assert schema["input_schema"]["required"] == ["kill_chain"]
    assert schema["input_schema"]["properties"]["kill_chain"]["enum"] == \
        ["recon", "surface", "enum", "exploit", "creds", "postex", "lateral", "report"]
