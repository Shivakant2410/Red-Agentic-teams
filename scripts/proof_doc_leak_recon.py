"""Deterministic proof for the doc-leak recon fix — zero LLM tokens.

Boots lab/fetcher.py (benign profiles, default), runs the REAL passive recon
pipeline against it, and asserts the planted ops token (openapi description of
/api/import) now lands in BOTH the knowledge graph and state_briefing — the
agent-visible layer. Pre-fix, ladder-3 agents died at hop 1 because recon
stripped descriptions.
"""
import subprocess
import sys
import time

import requests

sys.path.insert(0, "src")        # agentic_setup layer
sys.path.insert(0, ".")          # redteam package at repo root

from redteam.config import Engagement
from redteam.knowledge import KnowledgeGraph
from redteam.planner import state_briefing
from redteam.recon import run_deterministic_recon  # the same entry the run pipeline uses
from redteam.scope import ScopeGuard

APP_PORT, INT_PORT = 8971, 8970
BASE = f"http://127.0.0.1:{APP_PORT}"

proc = subprocess.Popen(
    [sys.executable, "lab/fetcher.py", str(APP_PORT), str(INT_PORT)],
    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
try:
    for _ in range(50):
        try:
            requests.get(BASE, timeout=1)
            break
        except requests.RequestException:
            time.sleep(0.2)

    # 1. Pre-fix behavior check: the doc IS on the wire (this is what the agent could GET).
    doc = requests.get(f"{BASE}/openapi.json", timeout=5).json()
    wire = doc["paths"]["/api/import"]["post"]["description"]
    assert "tok-ops-551f" in wire, "fixture plant missing"
    print(f"[wire]     openapi /api/import description carries: ...{wire[-40:]}")

    # 2. Real engagement RoE + the REAL recon entry (passive + attack-tree seeding).
    import datetime as dt
    eng = Engagement(
        name="doc-leak-proof", client="c", authorized_by="a", ticket="t",
        starts=dt.date.today() - dt.timedelta(days=1),
        ends=dt.date.today() + dt.timedelta(days=1),
        allowed_hosts=("127.0.0.1",), excluded_hosts=(),
        allowed_ports=(APP_PORT,), allowed_schemes=("http",),
        max_requests_per_second=5.0, max_total_requests=200,
        allow_private_ranges=True, require_approval_for=(), raw={},
    )
    assert ScopeGuard(eng).check(BASE), "RoE must allow the fixture"
    graph = KnowledgeGraph()
    summary = run_deterministic_recon(eng, graph, audit=None)
    print(f"[recon]    {summary}")

    # 3. The pass/fail line the live-fire runs failed: token in the agent briefing.
    brief = state_briefing(graph)
    node = next(n for n in graph.nodes("endpoint") if n.key.endswith("/api/import"))
    assert "tok-ops-551f" in node.attrs["doc"], "token did not reach the graph"
    assert "tok-ops-551f" in brief, "token did not reach the agent-visible briefing"
    print("[graph]    endpoint attrs doc -> tok-ops-551f present")
    print("[briefing] agent-visible state_briefing section:")
    for line in brief.splitlines():
        if "tok-ops" in line or "DOC NOTES" in line:
            print(f"           {line.strip()}")
    print("PROOF OK: hop-1 doc-leak is now visible through the deterministic recon layer.")
finally:
    proc.terminate()
