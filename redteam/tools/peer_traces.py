"""search_peer_traces — worker-to-worker process-level information exchange.

Ported from ARTEX's engine (the Baidu "Agent+" winner): in a parallel exploit
swarm, the most valuable observation of a run — an odd error body, a hidden
parameter, a 403 that differed from the others — usually appears inside ONE
worker's process and dies there, because it never became a formal fact and the
worker moved on to its own hypothesis. ARTEX solves this with
`search_all_worker_traces(q)`: any worker can keyword-search the OTHER workers'
execution traces and stand on observations that never got written up.

Our equivalent: the event bus already records every `tool.call` / `tool.result`
of every specialist (that is what the dashboard replays). This tool is the
READ side for the swarm — a bounded, role-aware grep over peer process
activity. A worker stuck on a target can ask "has anything like this been seen
before?" and get the actual wire observations of its siblings, each attributed
to the specialist that made them.

Discipline:

- READ-ONLY over the run's own event log. Nothing here touches the network, so
  it costs no rate budget and can never widen scope — the only RoE-safe tool
  call there is.
- Self-exclusion by default: a worker searching its own traces would mostly
  re-find what it already knows (its own context carries it). `include_own`
  flips that deliberately.
- Attribution is structural: every hit carries the `role` that emitted it, and
  the swarm gives each worker a unique role (`exploit-w0`, `exploit-w1`, ...)
  so "peer" means a specific sibling hypothesis, not an anonymous cloud.
- Compact output: previews are truncated and hits are capped — a worker that
  floods its context with a sibling's raw traffic defeats the point of the
  swarm's division of labor. Most recent hits come first, because in a live
  engagement the freshest observation is usually the most relevant one.
- Deliberately NOT given to the VERIFY specialist: independence there means
  re-deriving the proof from stored replay material, not from whatever the
  proposing agent happened to observe. Peer traces are for workers planning
  the next hypothesis, never for the court that judges the last one.
- Never records findings, never promotes anything: an observation recovered
  here is a LEAD. If it matters, the worker proves it through the normal
  pipeline like any other hypothesis.
"""

from __future__ import annotations

import json
from pathlib import Path

from ..events import read_events
from . import ToolContext, current_agent

# Event types that constitute "process" (as opposed to formal state). swarm.claim
# is included so a worker can also ask "who is working on X right now?" — claims
# carry technique + target + worker id.
_TRACE_TYPES = ("tool.call", "tool.result", "swarm.claim")

# Fields worth grepping per type. Everything else in the event is bookkeeping.
_FIELDS = ("args", "preview", "tool", "technique", "target", "worker", "ok")

_PREVIEW = 160  # chars of args/preview shown per hit — enough to recognize, not to flood


class SearchPeerTracesTool:
    name = "search_peer_traces"

    def schema(self) -> dict:
        return {
            "name": self.name,
            "description": (
                "Search OTHER specialists' process traces (their raw tool calls and "
                "result previews from this run) for observations that never became a "
                "finding — an error body, a hidden parameter, a response oddity a "
                "sibling worker saw and moved past. Use it when your hypothesis needs "
                "context you don't have: 'has anything on this endpoint/token/error "
                "already been observed?'. Each hit names the specialist that made it "
                "(e.g. exploit-w1) so you can reason about who saw what. Read-only, "
                "no rate budget. A hit is a LEAD: prove it yourself through the "
                "normal pipeline; nothing here is evidence."
            ),
            "input_schema": {
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "Space-separated keywords; ALL must appear in a "
                                       "trace line for it to match (case-insensitive).",
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Max hits returned (most recent first). Default 8.",
                    },
                    "include_own": {
                        "type": "boolean",
                        "description": "Include your own traces too. Default false.",
                    },
                },
                "required": ["query"],
            },
            "strict": True,
        }

    def run(self, ctx: ToolContext, query: str, limit: int = 8,
            include_own: bool = False) -> str:
        bus = ctx.events
        if bus is None:
            return ("No telemetry bus in this run (legacy single-agent mode) — "
                    "there are no peer traces to search.")
        path = bus.sink_path
        if path is None:
            return "This run has no event log on disk — nothing to search yet."
        events = read_events(path, after=0)
        own = "" if include_own else (current_agent.get("") or "")
        terms = [t for t in str(query).lower().split() if t]
        if not terms:
            return "ERROR: empty query — give at least one keyword."

        hits: list[dict] = []
        scanned = 0
        for ev in events:
            if ev.get("type") not in _TRACE_TYPES:
                continue
            scanned += 1
            if own and ev.get("role") == own:
                continue
            blob = " ".join(str(ev.get(k, "")) for k in _FIELDS).lower()
            if all(t in blob for t in terms):
                hits.append(ev)

        total = len(hits)
        shown = hits[-max(1, min(limit, 25)):][::-1]  # cap + most-recent-first
        lines = [f"peer traces: {total} hit(s) for {query!r} (scanned {scanned} trace events)"]
        if not shown:
            lines.append("No matching peer observation. Siblings may simply not have "
                         "looked here yet — that is information too.")
        for ev in shown:
            ts = (ev.get("ts") or "")[11:19]  # HH:MM:SS — a trace line, not a calendar
            what = ev.get("type", "")
            if what == "swarm.claim":
                body = (f"claimed {ev.get('technique')} on {ev.get('target')}")
            elif what == "tool.call":
                body = f"{ev.get('tool')} args={str(ev.get('args', ''))[:_PREVIEW]}"
            else:
                ok = "ok" if ev.get("ok") else "FAIL"
                body = f"{ev.get('tool')} [{ok}] {str(ev.get('preview', ''))[:_PREVIEW]}"
            lines.append(f"#{ev.get('seq')} {ts} {ev.get('role', '?'):>10} {body}")
        lines.append("Hits are leads from sibling workers' processes — verify through "
                     "the proof pipeline before treating any as fact.")
        return "\n".join(lines)
