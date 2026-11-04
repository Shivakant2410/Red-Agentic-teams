"""Markdown report for an llmred campaign.

The shape follows what the teardown found buyers actually need (Pillar's "ask
for the command that ran, not the text the model produced"): every number is a
rate with an interval, every objective carries its OWASP 2026 mapping, and the
evidence pointer is the hash-addressed campaign.jsonl — the transcript of every
attempt lives next to the report, addressable by the sha256 in the audit log.
"""

from __future__ import annotations

from .regression import LABEL_TARGET_CHANGED


def _fmt_asr(cell: dict) -> str:
    asr = cell.get("asr")
    if asr is None:
        return "— (undecided)"
    lo, hi = cell.get("ci95", [None, None])
    return f"{asr:.2f} [{lo:.2f}, {hi:.2f}]" if lo is not None else f"{asr:.2f}"


def render_markdown(summary: dict, diff_rows: list[dict] | None = None) -> str:
    tgt = summary.get("target", {})
    verdicts = summary.get("verdicts", {})
    lines: list[str] = []
    ap = lines.append

    ap(f"# LLM red-team campaign — {tgt.get('name', 'unnamed target')}")
    ap("")
    ap(f"- Target: `{tgt.get('kind')}`"
       + (f" model `{tgt.get('model')}`" if tgt.get("model") else "")
       + f" (fingerprint `{tgt.get('fingerprint')}`)")
    ap(f"- Authorization: {summary.get('authorized_by')} (ticket {summary.get('ticket')})")
    ap(f"- Attempts: {summary.get('attempts')} / budget {summary.get('budget')}"
       f" · HTTP requests used: {summary.get('requests_used')}")
    if summary.get("halt_reason"):
        ap(f"- **Halted early:** {summary['halt_reason']}")
    ap("- Verdicts: "
       + ", ".join(f"{k} {v}" for k, v in verdicts.items()))
    ap("- ASR convention: successes/decided (undetermined and errors reported "
       "separately, never laundered); intervals are Wilson 95%.")
    ap("")

    ap("## Objectives")
    ap("")
    ap("| Objective | OWASP (2026) | ASR [CI95] | attempts | undet. | errors | worst strategy |")
    ap("|---|---|---|---|---|---|---|")
    for oid, cell in (summary.get("objectives") or {}).items():
        strat_cells = cell.get("strategies") or {}
        worst, worst_rate = "—", -1.0
        for sid, s in strat_cells.items():
            if s["decided"] and s["successes"] / s["decided"] > worst_rate:
                worst, worst_rate = sid, s["successes"] / s["decided"]
        worst_txt = f"`{worst}` ({worst_rate:.2f})" if worst != "—" else "—"
        ap(f"| {oid} | {cell.get('owasp')} | {_fmt_asr(cell)} | {cell.get('attempts')} "
           f"| {cell.get('undetermined')} | {cell.get('error')} | {worst_txt} |")
    ap("")

    owasp = summary.get("owasp") or {}
    if owasp:
        ap("## OWASP LLM Top 10 (2026) rollup")
        ap("")
        ap("| Class | successes / decided |")
        ap("|---|---|")
        for code in sorted(owasp):
            agg = owasp[code]
            ap(f"| {code} | {agg['successes']} / {agg['decided']} |")
        ap("")

    skipped = summary.get("skipped") or []
    if skipped:
        ap("## Skipped combinations (loud, per PyRIT scenario convention)")
        ap("")
        for s in skipped:
            ap(f"- `{s['objective']}` × `{s['strategy']}`: {s['reason']}")
        ap("")

    if diff_rows is not None:
        ap("## Posture vs previous summary")
        ap("")
        if any(r.get("label") == LABEL_TARGET_CHANGED for r in diff_rows):
            ap("- **target-changed**: the compared summaries are for different "
               "fingerprints; no posture comparison is valid.")
        else:
            ap("| Objective | Label | prev ASR | cur ASR | delta |")
            ap("|---|---|---|---|---|")
            for r in diff_rows:
                ap(f"| {r['objective']} | **{r['label']}** | {r.get('prev_asr')} "
                   f"| {r.get('cur_asr')} | {r.get('delta', '—')} |")
        ap("")

    ap("## Evidence")
    ap("")
    ap("- `campaign.jsonl` — one JSON line per attempt: full bounded transcript, "
       "canary, verdict, reason, and `transcript_sha256` (the audit log's "
       "`transcript_sha256` values address these lines).")
    ap("- `summary.json` — machine-readable version of this report (schema "
       "`llmred.summary.v1`); feed it to the next run's regression diff.")
    ap("- `llmred_bandit.json` — the Thompson-sampling evidence that decides "
       "where the NEXT campaign's budget goes.")
    ap("")
    return "\n".join(lines)
