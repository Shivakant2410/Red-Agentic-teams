"""search_peer_traces: the swarm's read side must attribute, exclude and cap honestly.

Failure modes these tests exist to kill:

1. Attribution — a worker's search must return ONLY sibling traces (self-exclusion
   via the dispatch-published identity), and every hit must name who made it.
   Without the unique per-worker names (exploit-w0/w1), "peer" is meaningless.
2. Precision — an AND-of-keywords query; non-trace event types (findings, phase
   markers) must never surface, no matter how loudly they contain the keywords:
   formal state is already visible to the agent; process traces are the point.
3. Honesty — no bus / no sink / zero hits must degrade to informative strings,
   never exceptions and never fabricated context. Caps and ordering (most recent
   first) keep a flood of sibling traffic from drowning the caller's context.
4. Wiring — the tool exists in the registry, and agent._dispatch actually
   publishes the caller's identity around every tool call (that is what makes
   self-exclusion structural rather than advisory).
"""

from __future__ import annotations

from datetime import date

from test_artex_features import _Audit, _ctx

from redteam.agent import RedTeamAgent
from redteam.config import Engagement
from redteam.events import EventBus
from redteam.findings import FindingStore
from redteam.ratelimit import RateLimiter
from redteam.scope import ScopeGuard
from redteam.tools import ToolContext, build_registry, current_agent
from redteam.tools.peer_traces import SearchPeerTracesTool


def _eng() -> Engagement:
    return Engagement(
        name="t", client="c", authorized_by="a", ticket="ref",
        starts=date.today(), ends=date.today(),
        allowed_hosts=("127.0.0.1",), excluded_hosts=(), allowed_ports=(80,),
        allowed_schemes=("http",), max_requests_per_second=1000.0,
        max_total_requests=100, allow_private_ranges=True, require_approval_for=(),
    )


def _tool_ctx(tmp_path, bus) -> ToolContext:
    ctx = _ctx(tmp_path, eng=_eng(), limiter=RateLimiter(1000.0, max_total=100))
    ctx.events = bus
    return ctx


def _seed_swarm_log(bus):
    """Two workers' interleaved process + a formal event that must stay invisible."""
    # w0 (will be "self" in the tests below) probes the admin panel and fails oddly
    bus.emit("tool.call", role="exploit-w0", tool="http_probe",
             args='{"url": "http://t/admin", "method": "GET"}')
    bus.emit("tool.result", role="exploit-w0", tool="http_probe", ok=False,
             preview="status 403 — forbidden, body mentions WAF block id 7734")
    # w1 hits the same endpoint family and sees something juicy
    bus.emit("tool.call", role="exploit-w1", tool="http_probe",
             args='{"url": "http://t/admin/users", "method": "GET"}')
    bus.emit("tool.result", role="exploit-w1", tool="http_probe", ok=True,
             preview="200 OK — user list fragment mentions debug=1 parameter")
    # a claim: w2 is NOW working on the auth bypass hypothesis
    bus.emit("swarm.claim", role="orchestrator", worker=2, round=0,
             technique="auth_bypass", target="http://t/admin")
    # formal events must NEVER be searchable: they are already first-class state
    bus.emit("finding.recorded", role="exploit-w0", title="admin 403 anomaly",
             preview="admin 403 anomaly recorded as a finding")


def test_peer_hits_exclude_the_caller_and_carry_attribution(tmp_path):
    bus = _bus = EventBus("run-test", sink_path=tmp_path / "events.jsonl")
    _seed_swarm_log(bus)
    ctx = _tool_ctx(tmp_path, bus)
    tool = SearchPeerTracesTool()
    token = current_agent.set("exploit-w0")
    try:
        out = tool.run(ctx, query="admin")
        out_frag = tool.run(ctx, query="fragment")
    finally:
        current_agent.reset(token)
    # self excluded, sibling kept, claim line (orchestrator) kept
    assert "exploit-w1" in out and "exploit-w0" not in out
    assert "auth_bypass" in out                  # live claim surfaces too
    assert "debug=1" in out_frag                 # w1's observation is visible
    assert "WAF block id 7734" not in out_frag   # w0's own trace is not


def test_include_own_flips_exclusion(tmp_path):
    bus = EventBus("run-test", sink_path=tmp_path / "events.jsonl")
    _seed_swarm_log(bus)
    ctx = _tool_ctx(tmp_path, bus)
    token = current_agent.set("exploit-w0")
    try:
        out = SearchPeerTracesTool().run(ctx, query="admin", include_own=True)
    finally:
        current_agent.reset(token)
    assert "exploit-w0" in out and "exploit-w1" in out


def test_multi_term_query_is_conjunction(tmp_path):
    bus = EventBus("run-test", sink_path=tmp_path / "events.jsonl")
    _seed_swarm_log(bus)
    ctx = _tool_ctx(tmp_path, bus)
    token = current_agent.set("exploit-w0")
    try:
        both = SearchPeerTracesTool().run(ctx, query="user list fragment")
        miss = SearchPeerTracesTool().run(ctx, query="debug waf")
    finally:
        current_agent.reset(token)
    assert "debug=1" in both                     # all terms present in one trace
    assert "No matching peer observation" in miss  # terms split across roles/lines


def test_formal_state_never_leaks_through(tmp_path):
    bus = EventBus("run-test", sink_path=tmp_path / "events.jsonl")
    _seed_swarm_log(bus)
    ctx = _tool_ctx(tmp_path, bus)
    token = current_agent.set("exploit-w2")
    try:
        out = SearchPeerTracesTool().run(ctx, query="anomaly")
    finally:
        current_agent.reset(token)
    # 'finding.recorded' carried the word — a trace search must not return it
    assert "No matching peer observation" in out


def test_no_bus_and_no_sink_degrade_honestly(tmp_path):
    tool = SearchPeerTracesTool()

    ctx_no_bus = _tool_ctx(tmp_path, None)
    ctx_no_bus.events = None
    assert "no telemetry bus" in tool.run(ctx_no_bus, query="x").lower()

    bus_mem = EventBus("run-test")               # no sink file configured
    ctx_mem = _tool_ctx(tmp_path, bus_mem)
    assert "no event log" in tool.run(ctx_mem, query="x").lower()

    bus_empty = EventBus("run-test", sink_path=tmp_path / "empty.jsonl")
    ctx_empty = _tool_ctx(tmp_path, bus_empty)
    out = tool.run(ctx_empty, query="anything")
    assert "0 hit" in out and "No matching" in out


def test_most_recent_first_and_cap(tmp_path):
    bus = EventBus("run-test", sink_path=tmp_path / "events.jsonl")
    for i in range(12):  # seqs 1..12, roles cycle w0/w1/w2
        bus.emit("tool.result", role=f"exploit-w{i % 3}", tool="http_probe", ok=True,
                 preview=f"cycle {i} on /admin")
    ctx = _tool_ctx(tmp_path, bus)
    token = current_agent.set("exploit-w0")      # own = seqs 1,4,7,10 -> 8 peer hits
    try:
        out = SearchPeerTracesTool().run(ctx, query="cycle", limit=4)
    finally:
        current_agent.reset(token)
    assert "8 hit(s)" in out                     # honest total, own excluded
    assert "#12" in out and "#11" in out and "#9" in out and "#8" in out
    assert "#4" not in out and "#7" not in out   # own traces excluded
    assert "#1 " not in out                      # oldest is both own and capped out
    # most-recent-first ordering across the shown lines
    assert out.index("#12") < out.index("#11") < out.index("#9") < out.index("#8")


def test_empty_query_rejected(tmp_path):
    ctx = _tool_ctx(tmp_path, EventBus("run-test", sink_path=tmp_path / "e.jsonl"))
    assert "ERROR" in SearchPeerTracesTool().run(ctx, query="   ")


def test_registered_and_reachable_from_profiles():
    registry = build_registry(enable_sandbox=False, enable_browser=False)
    assert "search_peer_traces" in registry
    from redteam.orchestrator import EXPLOIT, RECON, VERIFY
    assert "search_peer_traces" in EXPLOIT.tool_names
    assert "search_peer_traces" in RECON.tool_names
    # VERIFY is deliberately blind to peer traces: independence means re-deriving
    # the proof from stored replay material, not from the proposer's process.
    assert "search_peer_traces" not in VERIFY.tool_names


def test_dispatch_publishes_caller_identity(tmp_path):
    seen = {}

    class Probe:
        name = "identity_probe"

        def schema(self):
            return {"name": self.name}

        def run(self, ctx, **kw):
            seen["agent"] = current_agent.get()
            return "ok"

    class NullClient:  # _dispatch never talks to the LLM
        def chat(self, *a, **k):  # pragma: no cover - must not be reached
            raise AssertionError("dispatch must not call the model")

    agent = RedTeamAgent(_eng(), {"identity_probe": Probe()},
                         _tool_ctx(tmp_path, None), NullClient(),
                         max_steps=2, agent_name="exploit-w1")
    agent._dispatch("identity_probe", {})
    assert seen["agent"] == "exploit-w1"
    # and it does NOT leak after the dispatch returns
    assert current_agent.get() == ""
