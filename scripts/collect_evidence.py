#!/usr/bin/env python3
"""Compile real-model campaign evidence into a committed markdown document.

Reads ONLY run artifacts under runs/campaigns/ (campaign_meta.json,
manifest.json, mission.json, campaign_score.json, traffic.jsonl,
audit.log.jsonl, mission_journal.jsonl) — the same honesty rules as the
independent scorer: verdicts come from artifacts, never from agent narration.

Usage:
  python3 scripts/collect_evidence.py <run_dir> [<run_dir> ...] > out.md
"""
from __future__ import annotations

import datetime as _dt
import json
import sys
from collections import Counter
from pathlib import Path


def _jsonl(path: Path) -> list[dict]:
    if not path.exists():
        return []
    rows = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if line:
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                pass
    return rows


def _json(path: Path) -> dict:
    if not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def _mission_inner(run_dir: Path) -> dict:
    rec = _json(run_dir / "mission.json")
    inner = rec.get("mission")
    return inner if isinstance(inner, dict) else rec


def section(run_dir: Path) -> str:
    meta = _json(run_dir / "campaign_meta.json")
    manifest = _json(run_dir / "manifest.json")
    score = _json(run_dir / "campaign_score.json")
    inner = _mission_inner(run_dir)
    traffic = _jsonl(run_dir / "traffic.jsonl")
    audit = _jsonl(run_dir / "audit.log.jsonl")
    journal = _jsonl(run_dir / "mission_journal.jsonl")

    lines: list[str] = []
    rid = meta.get("run_id", run_dir.name)
    lines.append(f"### `{rid}`")
    lines.append("")
    prov = ", ".join(meta.get("providers", [])) or "n/a"
    lines.append(f"- **Scenario/driver:** {meta.get('scenario')} / {meta.get('driver')}"
                 f" · **providers:** {prov}")
    lines.append(f"- **Commit under test:** `{meta.get('commit')}`"
                 f" · **started:** {meta.get('started')}")
    lines.append(f"- **Budget config:** wall {meta.get('budget_seconds')}s,"
                 f" LLM tokens ≤ {meta.get('max_llm_tokens')},"
                 f" RoE requests ≤ 4000 @ 50 rps")
    used = manifest.get("tokens")
    steps = manifest.get("steps")
    lines.append(f"- **Budget usage:** {used if used is not None else '?'} LLM tokens,"
                 f" {len(traffic)} recorded lab requests, manifest steps {steps}")
    stop = (score.get("mission_stop_reason")
            or inner.get("stop_reason") or inner.get("halt_reason")
            or manifest.get("halt_reason") or "(none recorded)")
    lines.append(f"- **Stop reason:** `{stop}`"
                 f" · **run status:** `{manifest.get('status')}`"
                 f" · **mission status:** `{inner.get('status') or score.get('mission_status')}`")
    verdict = score.get("verdict", "(scorer did not run)")
    lines.append(f"- **Independent verifier (campaign_scorer.py, artifacts-only):**"
                 f" **{verdict}**")
    if score.get("ground_truth"):
        gt = ", ".join(f"`{k}`={'HIT' if v else 'MISS'}"
                       for k, v in score["ground_truth"].items())
        lines.append(f"  - ground truth: {gt}")
    integ = score.get("integrity") or {}
    if integ:
        lines.append(f"  - finding pipeline: confirmed={integ.get('confirmed_findings')},"
                     f" confirmed_with_independent_verdict={integ.get('confirmed_with_independent_verdict')},"
                     f" pending_never_counted_confirmed={integ.get('pending_never_counted_confirmed')},"
                     f" tool_denials_audited={integ.get('tool_denials_audited')}"
                     + (f", canary_hits={score['canary_hits']}"
                        if score.get("canary_hits") is not None else ""))

    # Attack traces: real wire evidence only.
    lines.append("")
    if traffic:
        paths = Counter(str(e.get("url") or e.get("path")) for e in traffic)
        lines.append(f"- **Attack traces (traffic.jsonl, {len(traffic)} requests):**"
                     f" top URLs {dict(list(paths.items())[:4])}")
        interesting = [e for e in traffic
                       if any(s in str(e.get("req_body", "")).upper()
                              + str(e.get("url", "")).upper()
                              for s in ("UNION", "%27", "'1'='1", "SELECT", "8909"))
                       or e.get("status") in (500, 200)]
        for e in (interesting or traffic)[:5]:
            body = str(e.get("req_body") or "").replace("\n", " ")[:80]
            lines.append(f"  - `{e.get('method')} {e.get('url')}` ->"
                         f" {e.get('status')} ({e.get('tool') or 'no tool recorded'})"
                         + (f" · body: `{body}`" if body else ""))
    else:
        lines.append("- **Attack traces:** none — no lab request was ever recorded"
                     " (see stop reason; a narration-only run produces no wire evidence)")
    denied = [e for e in audit
              if str(e.get("event", "")).startswith(("tool.denied", "probe.denied"))]
    if denied:
        lines.append(f"- **Scope enforcement on the wire:** {len(denied)} audited"
                     f" tool denial(s), e.g."
                     f" `{str(denied[0].get('url') or denied[0].get('detail'))[:70]}`")

    # Mission journal task timeline (actors only, no narration).
    if journal:
        actors = Counter(str(e.get("actor")) for e in journal)
        lines.append(f"- **Mission journal:** {len(journal)} journaled events,"
                     f" actors {dict(actors)}")
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    runs = [Path(a) for a in sys.argv[1:]]
    now = _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    out = []
    out.append("# Builder 04 — real-model campaign evidence (2026-11-18)\n")
    out.append("Every claim below is read from run artifacts by the ARTIFACTS-ONLY "
               "independent scorer (`scripts/campaign_scorer.py`) and this "
               "collector; agent narration is never evidence. Stop reasons, "
               "budget usage and traces are reported even when they are "
               "unflattering (rate-limited providers, narration-only runs, "
               "budget exhaustion).\n")
    out.append(f"Compiled: {now}\n")
    for run in runs:
        out.append(section(run))
    sys.stdout.write("\n".join(out))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
