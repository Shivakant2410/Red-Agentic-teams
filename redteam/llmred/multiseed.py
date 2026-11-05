"""Multi-seed reliability — pass^k for defenses, pooling for ASRs (recs 6-7).

A single campaign is one draw of the bandit's exploration: an objective that
survived seed 3 may fold at seed 4. tau-bench's lesson applies to defense too —
pass^1 flatters, pass^8 collapses (their agents: <25% at k=8). This runner
executes the SAME campaign configuration under k independent seeds and reports
what a single run cannot:

  defense pass^k   P(the objective stays clean in ALL k runs) — bootstrap
                   estimate with a Wilson interval (stats.pass_hat_k). This is
                   the number a release gate should read; pass^1 is the demo.
  attack any^k     P(at least one of k runs leaks) = 1 - pass^k — the same coin,
                   the attacker's side. Reported alongside, never instead.
  pooled ASR       per-seed Beta(1,1) posteriors combined by precision weighting
                   (stats.beta_pool / pooled_cells) — pooling WITHOUT pretending
                   k campaigns are one homogeneous binomial sample.
  retry null       stats.resampling_null over each objective's per-attempt
                   verdict stream (null_k consecutive attempts = one "session"):
                   does success cluster beyond luck + patience? The raw-retry
                   inflation guard, applied to our own harness.

Undecided seeds (no decided attempts for an objective) are EXCLUDED from pass^k
and flagged in `undecided_seeds` — ambiguity is not defense evidence (the same
honesty contract as campaign.py: undetermined is never laundered into blocked).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Callable

from ..stats import pass_hat_k, pooled_cells, beta_pool, resampling_null
from .campaign import Campaign, CampaignConfig

CFG_FACTORY = Callable[[int], CampaignConfig]


def _attempt_stream(out_dir: Path) -> list[bool]:
    """Per-attempt 'leaked' booleans from one campaign's evidence file."""
    path = out_dir / "campaign.jsonl"
    if not path.exists():
        return []
    out: list[bool] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        rec = json.loads(line)
        out.append(rec.get("verdict") == "leaked")
    return out


def run_multiseed(cfg_factory: CFG_FACTORY, seeds: list[int],
                  null_k: int = 3) -> dict:
    """Run k seeds; aggregate per-objective reliability. cfg_factory(seed) must
    return a config whose out_dir is unique per seed (evidence separation)."""
    if len(seeds) < 2:
        raise ValueError("multiseed needs >= 2 seeds; a single run is Campaign.run")
    summaries: dict[int, dict] = {}
    for seed in seeds:
        cfg = cfg_factory(seed)
        summaries[seed] = Campaign(cfg).run()

    objective_ids = sorted({oid for s in summaries.values()
                            for oid in s["objectives"]})
    objectives_out: dict[str, dict] = {}
    for oid in objective_ids:
        clean: list[bool] = []       # decided-and-zero-leaks per seed
        decided_flags: list[bool] = []
        undecided_seeds: list[int] = []
        cells: list[dict] = []
        stream: list[bool] = []
        for seed in seeds:
            st = summaries[seed]["objectives"].get(oid)
            if st is None:
                undecided_seeds.append(seed)     # bandit never reached it
                continue
            decided = st["decided"]
            successes = st["successes"]
            stream.extend([True] * successes +
                          [False] * (decided - successes))
            if decided > 0:
                cells.append(beta_pool(successes, decided))
                decided_flags.append(True)
                clean.append(successes == 0)
            else:
                undecided_seeds.append(seed)

        pk = pass_hat_k(clean, len(clean)) if clean else {
            "pass_k": None, "lo95": None, "hi95": None, "groups": 0}
        objectives_out[oid] = {
            "seeds": len(seeds),
            "decided_seeds": sum(decided_flags),
            "undecided_seeds": undecided_seeds,
            "leaking_seeds": sum(1 for c in clean if not c),
            "defense_pass_k": pk["pass_k"],
            "pass_k_ci95": [pk["lo95"], pk["hi95"]],
            "attack_any_k": (round(1.0 - pk["pass_k"], 4)
                             if pk["pass_k"] is not None else None),
            "pooled_asr": pooled_cells(cells),
            "retry_null": resampling_null(stream, null_k),
        }

    out = {
        "schema": "llmred.multiseed.v1",
        "seeds": list(seeds),
        "null_k": null_k,
        "attempts_total": sum(s["attempts"] for s in summaries.values()),
        "objectives": objectives_out,
    }

    first_cfg = cfg_factory(seeds[0])          # factory is cheap; out_dir is stable
    parent = Path(first_cfg.out_dir).parent if first_cfg.out_dir else None
    if parent and parent.exists():
        (parent / "multiseed.json").write_text(
            json.dumps(out, indent=2, ensure_ascii=False), encoding="utf-8")
    return out


def render_multiseed_card(result: dict) -> str:
    """Markdown cell card for the multiseed block."""
    lines = ["### multiseed reliability", "",
             f"seeds: {result['seeds']} | attempts total: {result['attempts_total']}",
             "",
             "| objective | pass^k | 95% CI | any^k | pooled ASR | undecided |",
             "| --- | --- | --- | --- | --- | --- |"]
    for oid, st in result["objectives"].items():
        pk = st["defense_pass_k"]
        lo, hi = st["pass_k_ci95"]
        pooled = st["pooled_asr"]
        any_k = st["attack_any_k"]
        lines.append(
            f"| {oid} | "
            f"{'n/a' if pk is None else f'{pk:.3f}'} "
            f"| {'n/a' if lo is None else f'{lo:.3f}-{hi:.3f}'} "
            f"| {'n/a' if any_k is None else f'{any_k:.3f}'} "
            f"| {pooled['mean']:.3f}±{pooled['sd']:.3f} "
            f"| {len(st['undecided_seeds'])} |")
    return "\n".join(lines)
