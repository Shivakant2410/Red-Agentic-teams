#!/usr/bin/env python3
"""Loop-observability trace for Builder 04 campaigns.

Turns a run directory into the observable autonomous loop:

  Observe -> Hypothesize -> Prioritize -> Execute -> Evaluate evidence
           -> Verify -> Replan (or stop)

Output: loop_trace.md + loop_trace.json next to the run artifacts.
"""
from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]


def _jsonl(path: Path) -> list[dict]:
    rows = []
    if path.exists():
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if line:
                try:
                    rows.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
    return rows


def trace_run(run_dir: Path) -> dict:
    journal = _jsonl(run_dir / "mission_journal.jsonl")
    # this codebase records the event bus into the hash-chained audit log
    # (events.jsonl is not written by execute_run); audit rows carry the same
    # type/fields either as {"event": ...} or {"type": ...}
    events = []
    for row in _jsonl(run_dir / "audit.log.jsonl"):
        row = dict(row)
        if "type" not in row and "event" in row:
            row["type"] = row["event"]
        events.append(row)

    tasks: dict[str, dict] = {}
    mission_meta: dict = {}
    for row in journal:
        t = row.get("type", "")
        ts = row.get("ts", "")
        task_id = row.get("task_id") or ""
        payload = row.get("payload") or {}
        if t == "MISSION_CREATED":
            mission_meta = payload.get("mission") or {}
        elif t == "TASK_CREATED":
            td = payload.get("task") or {}
            tasks[task_id] = {"task_id": task_id, "title": td.get("title", ""),
                              "role": td.get("role", ""), "technique": td.get("technique", ""),
                              "target": td.get("target", ""), "created": ts,
                              "attempts": td.get("attempts", 0),
                              "max_attempts": td.get("max_attempts", 1),
                              "status": td.get("status", ""), "evidence": [],
                              "result": "", "error": "", "history": []}
        elif task_id and task_id in tasks:
            td = tasks[task_id]
            td["history"].append({"ts": ts, "type": t,
                                  "payload": {k: v for k, v in payload.items()
                                              if k in ("from_status", "to_status", "owner",
                                                       "result", "error", "evidence", "reason")}})
            if t in ("TASK_SUCCEEDED", "TASK_FAILED", "TASK_BLOCKED", "TASK_EXHAUSTED"):
                td["status"] = {"TASK_SUCCEEDED": "succeeded", "TASK_FAILED": "failed",
                                "TASK_BLOCKED": "blocked",
                                "TASK_EXHAUSTED": "exhausted"}[t]
                td["result"] = str(payload.get("result", ""))[:300]
                td["error"] = str(payload.get("error", ""))[:300]
            elif t == "TASK_EVIDENCE":
                td["evidence"].append(payload)
            elif t == "RESULT_REJECTED":
                td["history"][-1]["rejected"] = True
            elif t == "TASK_REARMED":
                td["status"] = "rearmed"

    hypotheses = []
    for row in _jsonl(run_dir / "research_journal.jsonl"):
        h = row.get("payload") or row
        hypotheses.append({"ts": row.get("ts", ""), "type": row.get("type", ""),
                           "text": str(h)[:200]})

    tool_calls: Counter = Counter()
    verify_passes = []
    verdicts = []
    llm_selected = []
    denied = []
    for row in events:
        t = row.get("type", "")
        if t == "tool.call":
            tool_calls[row.get("tool", "?")] += 1
        elif t == "verify_pass.start":
            verify_passes.append({"ts": row.get("ts", ""), "findings": row.get("pending", "")})
        elif t in ("finding.confirmed", "finding.verdict", "independent_verify.result"):
            verdicts.append({"ts": row.get("ts", ""), "id": row.get("id", row.get("finding", "")),
                             "verdict": row.get("verdict", row.get("verdicts", "")),
                             "type": t})
        elif t == "llm.selected":
            llm_selected.append({"provider": row.get("provider", ""),
                                 "model": row.get("model", "")})
        if t in ("tool.denied",) or t.endswith(".blocked"):
            denied.append({"ts": row.get("ts", ""), "type": t,
                           "tool": row.get("tool", ""), "detail": str(row)[:200]})

    tree = {}
    tree_path = run_dir / "attack_tree.json"
    if tree_path.exists():
        try:
            raw = json.loads(tree_path.read_text())
            nodes = raw.get("nodes") if isinstance(raw, dict) else raw
            states = Counter(n.get("status", "?") for n in (nodes or [])
                             if isinstance(n, dict))
            tree = {"node_states": dict(states),
                    "nodes": [{"technique": n.get("technique"), "target": n.get("target"),
                               "status": n.get("status"), "bucket": n.get("bucket", "")}
                              for n in (nodes or []) if isinstance(n, dict)][:40]}
        except json.JSONDecodeError:
            tree = {"error": "attack_tree.json unreadable"}

    manifest = {}
    if (run_dir / "manifest.json").exists():
        manifest = json.loads((run_dir / "manifest.json").read_text())
    mission = {}
    if (run_dir / "mission.json").exists():
        mission = json.loads((run_dir / "mission.json").read_text())

    return {
        "mission": {k: mission_meta.get(k) for k in
                    ("mission_id", "objective", "status", "halt_reason", "driver")},
        "mission_final": {k: mission.get(k) for k in
                          ("status", "stop_reason", "halt_reason", "outcome", "rounds")},
        "manifest": {k: manifest.get(k) for k in
                     ("status", "halt_reason", "steps", "tokens", "findings")},
        "llm": llm_selected[:2],
        "tasks": list(tasks.values()),
        "hypotheses_events": hypotheses[:40],
        "tool_census": dict(tool_calls),
        "verify_passes": verify_passes,
        "independent_verdicts": verdicts,
        "denials": denied[:20],
        "denials_count": len(denied),
        "attack_tree": tree,
    }


def render(trace: dict) -> str:
    lines = ["# Loop trace", ""]
    m = trace.get("mission") or {}
    f = trace.get("mission_final") or {}
    lines += [f"- mission: `{m.get('mission_id', '')}` status={m.get('status', '')} "
              f"final={f.get('status', '')} stop={f.get('stop_reason', '') or f.get('halt_reason', '')}",
              f"- objective: {m.get('objective', '')}",
              f"- llm: {trace.get('llm')}", ""]
    lines += ["## Task timeline", "",
              "| # | role | technique | target | status | attempts | result/error |",
              "|---|------|-----------|--------|--------|----------|--------------|"]
    for i, t in enumerate(trace.get("tasks") or [], 1):
        tail = (t.get("result") or t.get("error") or "")[:90].replace("|", "/")
        lines.append(f"| {i} | {t.get('role', '')} | {t.get('technique', '')} | "
                     f"{(t.get('target') or '')[:40]} | {t.get('status', '')} | "
                     f"{t.get('attempts', 0)}/{t.get('max_attempts', 1)} | {tail} |")
    lines += ["", "## Tool census", "", "```json",
              json.dumps(trace.get("tool_census"), indent=1), "```", "",
              f"Out-of-scope denials audited: **{trace.get('denials_count', 0)}**", ""]
    lines += ["## Independent verdicts", ""]
    if trace.get("independent_verdicts"):
        for v in trace["independent_verdicts"]:
            lines.append(f"- {v['ts'][:19]} {v['id']} -> {v['verdict']} ({v['type']})")
    else:
        lines.append("- none recorded")
    lines += ["", "## Attack tree (final)", "", "```json",
              json.dumps(trace.get("attack_tree", {}).get("node_states"), indent=1), "```"]
    return "\n".join(lines)


def main() -> int:
    run_dir = Path(sys.argv[1])
    trace = trace_run(run_dir)
    (run_dir / "loop_trace.json").write_text(json.dumps(trace, indent=2, default=str))
    md = render(trace)
    (run_dir / "loop_trace.md").write_text(md, encoding="utf-8")
    print(md)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
