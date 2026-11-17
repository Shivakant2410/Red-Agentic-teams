#!/usr/bin/env python
"""Controlled integration demonstration for the Unified Attack Intelligence Graph
(Builder 02 Phase E2, docs/adr-002-unified-intelligence-graph.md).

This is a LOCAL, DETERMINISTIC demonstration over controlled fixtures and
deterministic test doubles — no network activity, no real target, no LLM. It
exercises the full synchronization path on REAL persisted stores in a temp run
directory:

    1. a host/service is observed in AssetInventory (passive fingerprint)
    2. the synchronization bridge makes it visible in KnowledgeGraph
    3. an endpoint is associated with the appropriate host/service (KG edges)
    4. an AttackTree technique is associated with that endpoint (seed/sync)
    5. a finding is recorded through the existing finding pipeline (proof tool
       check_spec; pending_verification)
    6. the independent verifier determines its verdict from a deterministic
       double (HttpCheck over a canned fetch + mandated negative control)
    7. the graph projection represents the finding and its verification state
    8. demonstrated access is represented from AccessGraph evidence (creditor
       path with the structured finding reference)
    9. a FIXED retest causes the appropriate lifecycle invalidation
       (holding revoked, endpoint remediated — history preserved)
   10. the projection reflects the remediated/revoked state without erasing
       historical evidence

Run:  python scripts/demo_unified_intelligence.py
Exit code 0 = every step asserted. Output is a step-by-step trace.
"""

from __future__ import annotations

import json
import shutil
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from redteam.access import AccessGraph
from redteam.attack_tree import AttackTree
from redteam.findings import Finding, FindingStore
from redteam.inventory import AssetInventory
from redteam.knowledge import ENDPOINT, HOST, SERVICE, KnowledgeGraph
from redteam.graph_view import build_exploration_graph
from redteam.orchestrator import sync_inventory_into_graph
from redteam.retest import invalidate_after_fix  # noqa: F401 (used by retest_run internally)
from redteam.verify import verify, HttpCheck

STEP = 0


def step(n: int, title: str, detail: str = "") -> None:
    global STEP
    STEP = n
    print(f"\n[{n:02d}] {title}")
    if detail:
        print(f"     {detail}")


def main() -> int:
    run_dir = Path(tempfile.mkdtemp(prefix="demo-uig-"))
    print(f"run dir (controlled fixture, no network): {run_dir}")
    try:
        # -- real stores, exactly as run.py wires them -------------------------
        graph = KnowledgeGraph(run_dir / "graph.json")
        access = AccessGraph(run_dir / "access.json")
        tree = AttackTree(run_dir / "attack_tree.json")
        inventory = AssetInventory(run_dir / "inventory.json")
        store = FindingStore(run_dir / "findings.json")

        step(1, "AssetInventory observes a host/service (passive fingerprint)",
             "inventory.observe_http — the same passive path tools/http.py uses")
        inventory.observe_http("203.0.113.10", 443, "https", 200,
                               headers={"Server": "nginx"}, body="<title>Lab</title>",
                               source="http")
        assert inventory.summary()["services"] == 1

        step(2, "The synchronization bridge makes it visible in the KnowledgeGraph",
             "sync_inventory_into_graph — idempotent observe() merges")
        stats = sync_inventory_into_graph(inventory, graph)
        assert stats["bridged"] == 1, stats
        assert graph.nodes(HOST)[0].key == "203.0.113.10"
        svc = graph.nodes(SERVICE)[0]
        assert svc.key == "203.0.113.10:443" and svc.attrs["server"] == "nginx"

        step(3, "An endpoint is associated with the host/service (KG edges)",
             "recon's own observe(relate_to=...) path, as recon/passive.py does")
        ep = graph.observe(ENDPOINT, "https://203.0.113.10/admin", source="recon",
                           relate_to="service:203.0.113.10:443", relation="exposes")
        assert graph.neighbors("service:203.0.113.10:443", "exposes")[0].id == ep.id

        step(4, "An AttackTree technique is associated with that endpoint",
             "AttackTree.sync seeds entry techniques per discovered endpoint")
        tree.sync(graph=graph, findings=store.all())
        node = tree.node("access.control", "https://203.0.113.10/admin")
        assert node is not None and node.status == "todo"

        step(5, "A finding is recorded through the existing finding pipeline",
             "proof-shaped check_spec stored; agent self-check -> pending_verification")
        finding = Finding(title="Broken access control on /admin",
                          severity="high", target="https://203.0.113.10/admin",
                          summary="protected content without auth",
                          evidence="status 200 + marker", cwe="CWE-284",
                          confidence="pending_verification",
                          check_type="http",
                          check_spec={"request": {"method": "GET",
                                                  "url": "https://203.0.113.10/admin",
                                                  "headers": {}, "body": ""},
                                      "expect_status": 200})
        store.add(finding)
        assert store.pending()[0].confidence == "pending_verification"

        step(6, "The independent verifier determines the verdict",
             "HttpCheck rebuild + k-of-n over a deterministic double; no LLM")
        def good_fetch():
            return 200, "SECRET-DATA", 0.01
        result = verify(HttpCheck(fetch=good_fetch, expect_status=200,
                                  body_regex="SECRET-DATA"),
                        trials=5, need=4)
        assert result.verdict == "confirmed", result
        store.promote(finding.id, result.verdict, "; ".join(result.details[:2]))
        assert store.all()[0].confidence == "confirmed"
        # the orchestrator syncs the tree after every verify pass — same here
        tree.sync(graph=graph, findings=store.all())
        assert tree.node("access.control", "https://203.0.113.10/admin").status == "completed"

        step(7, "The graph projection represents the finding + verification state",
             "graph_view.build_exploration_graph — read-time only")
        view = build_exploration_graph(run_dir)
        paths = [p for p in view["attack_paths"] if p.get("findings")]
        assert paths and paths[0]["findings"][0]["confidence"] == "confirmed"
        ac = next(t for t in paths[0]["techniques"] if t["technique"] == "access.control")
        assert ac["status"] == "completed"  # tree synced on confirm

        step(8, "Demonstrated access is represented from AccessGraph evidence",
             "the creditor path: hold with source=verified_finding + structured ref")
        access.hold("resource", "admin", evidence=f"confirmed finding {finding.id}: "
                    "protected content", source="verified_finding",
                    attrs={"finding_id": finding.id})
        assert [n.key for n in access.held()] == ["admin"]

        step(9, "A FIXED retest causes the appropriate lifecycle invalidation",
             "deterministic retest double: 0 reproductions over a live transport")
        # The REAL production path: retest_run appends the retest_history entry
        # and gates invalidation on the FIXED verdict (never on
        # cannot_confirm/blocked). The deterministic double stands in for the
        # replayed HttpCheck so the demo stays offline.
        import redteam.retest as rt
        f = store.all()[0]
        original_retest_finding = rt.retest_finding

        def fake_retest(ff, ctx, **kw):
            return {"finding_id": ff.id, "verdict": "fixed",
                    "detail": "0/5 reproductions, all trials reached a live target",
                    "reproductions": 0, "trials": 5, "unreachable": 0, "title": ff.title}

        class _RetestCtx:
            audit = None
            events = None

        rt.retest_finding = fake_retest
        try:
            results = rt.retest_run(store, _RetestCtx(), finding_id=f.id,
                                    access=access, graph=graph)
        finally:
            rt.retest_finding = original_retest_finding   # always restore
        out = results[0]["invalidation"]
        assert out["revoked"] == [{"kind": "resource", "key": "admin"}], out
        assert out["remediated"] == [{"kind": ENDPOINT, "key": "https://203.0.113.10/admin"}]
        assert access.held() == []                      # no longer current
        assert access._nodes["resource:admin"].revoked is True

        step(10, "The projection reflects the remediated/revoked state — history intact",
             "revoked holding rendered with status; endpoint lifecycle=remediated;")
        view2 = build_exploration_graph(run_dir)
        p2 = [p for p in view2["attack_paths"] if p.get("findings")][0]
        assert p2["endpoint"]["lifecycle"] == "remediated"
        assert p2["findings"][0]["retest_last"]["verdict"] == "fixed"
        assert p2["access"][0]["status"] == "revoked"
        # historical evidence survives everywhere:
        assert access._nodes["resource:admin"].evidence.startswith("confirmed finding")
        assert store.all()[0].confidence == "confirmed"          # was real, stays on record
        assert store.all()[0].retest_history[-1]["verdict"] == "fixed"
        # the persisted files prove it on disk (actual persisted data, not memory)
        disk = json.loads((run_dir / "access.json").read_text())["nodes"][0]
        assert disk["held"] is False and disk["invalidation_reason"].startswith("retest fixed")
        disk_g = json.loads((run_dir / "graph.json").read_text())["nodes"]
        ep_row = next(r for r in disk_g if r["key"] == "https://203.0.113.10/admin")
        assert ep_row["lifecycle"]["status"] == "remediated"

        print("\nALL 10 STEPS ASSERTED — the unified intelligence graph path "
              "runs end-to-end on real persisted stores with deterministic doubles.")
        return 0
    finally:
        shutil.rmtree(run_dir, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
