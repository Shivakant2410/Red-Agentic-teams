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


def render_dynamics_card(dyn: dict) -> str:
    """Markdown card for the B2 dynamics run (see dynamics.py for the models).

    Every block renders its headline measurement, its model anchor, and its
    declared limits — a card that hides the limits would be marketing."""
    lines: list[str] = []
    ap = lines.append
    ap("## Dynamics — formal adversary models as instruments (B2)")
    ap("")
    ap(f"- Instruments: {dyn.get('instruments_ok')} ok · "
       f"{dyn.get('instruments_skipped')} skipped · "
       f"{dyn.get('instruments_error')} error (seed {dyn.get('seed')})")
    ap("- These are measurements of target DYNAMICS with declared limits — "
       "not verdicts; nothing here was laundered into a success number.")
    ap("")
    for block in dyn.get("blocks", []):
        inst = block.get("instrument", "?")
        status = block.get("status")
        if status == "skipped":
            ap(f"### {inst} — SKIPPED")
            ap("")
            ap(f"- {block.get('reason')}")
            ap("")
            continue
        if status == "error":
            ap(f"### {inst} — ERROR")
            ap("")
            ap(f"- {block.get('error')}")
            ap("")
            continue
        ap(f"### {inst} — {block.get('label', 'measured')}")
        ap("")
        ap(f"- Model: {block.get('model')}")
        if inst == "policy_commitment":
            ap(f"- unanimous repeats: {block.get('unanimous_rate')} over "
               f"{block.get('probe_count')} probes × {block.get('repeats')} "
               f"repeats · mean verdict entropy: "
               f"{block.get('mean_entropy_bits')} bits")
            ap(f"- attacker doctrine: {block.get('attacker_doctrine')}")
        elif inst == "signaling_gap":
            ev = block.get("deception_events") or []
            ap(f"- talk-action divergence events: {len(ev)}"
               + (f" — {ev[0].get('detail')}" if ev else ""))
            for r in block.get("probes", []):
                ap(f"- probe `{r.get('probe')}`: {r.get('classification')}")
        elif inst == "exfil_capacity":
            ap(f"- capacity: {block.get('capacity_bits')} bits recovered of "
               f"{block.get('payload_bits')} planted "
               f"(ratio {block.get('capacity_ratio')}, class "
               f"{block.get('label')})")
            ap(f"- benign control: "
               f"{'clean (0 bits)' if block.get('control_clean') else 'LEAKED — instrument machinery suspect'}")
        elif inst == "timing_contrast":
            ap(f"- median delta: {block.get('median_delta_ms')} ms "
               f"(trigger {block.get('trigger_median_ms')} vs benign "
               f"{block.get('benign_median_ms')}) · p={block.get('stat', {}).get('p_two_sided')}")
            nc = block.get("null_control") or {}
            ap(f"- split-half null: p={nc.get('p_two_sided')} "
               f"({nc.get('note')})")
        elif inst == "dose_response":
            ap(f"- crossing: turn {block.get('crossing_turn')} at "
               f"{block.get('crossing_dose_chars')} cumulative fragment "
               f"chars ({block.get('label')})")
        elif inst == "amplification_ratio":
            ap(f"- aggregate byte amplification {block.get('aggregate_amplification')}× "
               f"(peak {block.get('peak_amplification')}× on "
               f"`{block.get('peak_probe')}`)")
            if block.get("operations_ratio") is not None:
                ap(f"- operations: {block.get('operations_ratio')} tool "
                   "invocations per attacker message")
        elif inst == "propagation_chain":
            ap(f"- chain: {block.get('label')} · text survival "
               f"{block.get('text_survival_hops')} hops · action survival "
               f"{block.get('action_survival_hops')} hops · R="
               f"{block.get('r_factor')}")
        ap(f"- Limits: {block.get('limits')}")
        ap("")
    return "\n".join(lines)
