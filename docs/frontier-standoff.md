# Frontier Standoff — how we measure "our tool vs frontier models"

The question "how much does our tool stand against a frontier model?" is not one
number. It is a 2-axis experiment, and as of 2026-11-02 the instrument for it ships
in this repo (`redteam/bench/ladder.py` + `redteam/bench/raw_baseline.py`). This
document fixes the method, records what we already know, and states what each
future run will tell us.

## 1. The matrix

Two axes, everything else held fixed (same targets, same RoE, same scorer, same
"confirmed counts, guesses don't" rule):

**MODE — isolates scaffolding** (model held fixed):

| mode | what it is | what it isolates |
| --- | --- | --- |
| `raw` | one blind shot: model names HTTP requests, we replay them verbatim, its claims count only when the cited evidence substring really appears in the cited response | raw model knowledge, no loop, no memory, no tools |
| `rawk` | same, K=3 rounds: each round sees the previous responses | feedback alone |
| `flat` | the full single agent: tools, memory, guardrails, claim/verify protocol | the agent loop + protocol |
| `swarm` | orchestrator + OWASP class specialists | specialists + class routing |

The raw arm's referee is deliberately WEAKER than the agent's: a claim is
"confirmed" if the model cites a request AND an evidence substring that the replayed
response really contains — no differential requirement, no independent re-check
pass. If the raw model still loses under a lenient referee, the result is not a
scoring artifact.

**BACKEND — isolates the model** (mode held fixed):
`zai-bridge` (glm-4.6), `zai-direct`, `anthropic` (claude-sonnet-4-5),
`openrouter`/`openai` (`--model gpt-5.1`, gemini, ...), `custom` (any OpenAI-compat
endpoint via `RED_LADDER_BASE_URL`). All go through the same engagement
`llm.providers` plumbing → same rotation, cooldown, role routing for every arm.

Reading the deltas: `rawk − raw` = value of feedback; `flat − rawk` = value of the
tool loop + protocol; `swarm − flat` = value of specialists; and re-running any
column on a frontier backend = what the model tier buys at that rung.

## 2. What we already know (glm-4.6 via z-ai bridge, 2026-11-02)

From `runs/bench-summary.json` (bench runner, 70-step cap, sandbox off, dockerless
lab targets):

| target | achieved | confirmed | F1 | tokens | note |
| --- | --- | --- | --- | --- | --- |
| lab-idor | no | 1 | 1.00 | 181,778 | found+proved the IDOR, stalled before the objective pass |
| terminal (vault) | **YES** | 1 | 1.00 | 144,928 | clean objective completion |
| ladder-1 (easy) | no | 0 | 0.00 | 164,448 | stalled: XSS not surfaced into a proof |
| ladder-2 (medium) | no | 1 | 0.67 | 197,839 | chain half-proved |
| ladder-3 (hard SSRF chain) | **YES** | 2 | 0.50 | 188,520 | 4-hop chain completed |
| lab-forum | **YES** | 1 | 0.50 | 179,512 | stored XSS proved |

Summary: **3/6 objectives achieved, F1 mean ≈ 0.61, precision 1.00 on every run
that produced findings** (zero false positives — the verify protocol's signature),
~165k tokens per run, wall clock under 70s each. The first specialists A/B run
died to an account-level 429 storm before the bridge's serial gate existed; the
rebuilt bridge (`scripts/zai_bridge.mjs`) guarantees serialized SDK call starts.

What that already says about model sensitivity: on glm-4.6 the bottleneck is not
finding (F1 1.0 on lab-idor, chain completed on ladder-3) but **protocol
endurance** — turning a found bug into a completed objective before steps or
stall-detection run out. That is exactly the dimension where a stronger model is
expected to pay off first, and exactly what the matrix measures as `completion`
and `objective_achieved`, not as F1.

## 3. Published reference points (what frontier currently buys elsewhere)

Cited, with their caveats — none of these run OUR targets, so they calibrate
expectations, they do not substitute for the matrix:

- **XBOW's own model evaluations** (xbow.com/blog/mythos-offensive-security-xbow-evaluation,
  May 2026) run every frontier model "inside XBOW" vs "as a raw API engine" and
  state outright: *"orchestration, tools, prompting, and live-site access
  materially affect outcomes"* and *"a model is a brain without a body."* Their
  benchmark counts a case as passed only on a **validated PoC within 80 actions**
  (PoC||GTFO) — the same philosophy as our `confirmed`-only scoring.
- **Cyber-AutoAgent** (open-source, Claude Sonnet 4.5 on Bedrock) reports ~85% on
  the XBOW validation benchmark, claiming parity with XBOW's baseline and senior
  human pentesters — i.e. on that suite, an *orchestrated* mid-tier-frontier
  harness ≈ 85%, which is the scale a mature harness reaches.
- **Appen Security Benchmark** (June 2026, source-audit setting): 21 frontier
  models against 141 human-verified vulnerabilities — **the best misses nearly 4
  in 10** (recall < 0.6). Frontier intelligence alone is not coverage.
- **Vendor-reported agentic-cyber scores** (Oct 2026): Gemini 4 Carbon 88.2%
  SEC-bench Pro / 54.8% ExploitGym; GLM 5.3 exploit chains on Firefox patch gaps
  (Epoch AI). Range is huge because harness and task shape dominate — again the
  argument for measuring on OUR ladder, not quoting vendor charts.

## 4. How to run the matrix

```bash
# 0. backend access (only what you use):
#    zai-bridge  -> node scripts/zai_bridge.mjs          (no key needed in sandbox)
#    anthropic   -> export ANTHROPIC_API_KEY=...
#    openrouter  -> export OPENROUTER_API_KEY=...  +  --model openai/gpt-5.1
#    custom      -> export RED_LADDER_BASE_URL=... RED_LADDER_KEY_ENV=...

# 1. one cell per shell call (sandbox reaps processes between calls):
python -m redteam.bench.ladder --targets lab-idor,ladder-1,ladder-2,ladder-3 \
    --modes raw,rawk,flat,swarm --backend zai-bridge --out runs/frontier-standoff \
    --cells 0-3      # chunk indices, e.g. 4-7 next

# 2. rebuild the comparison table anytime:
python -m redteam.bench.ladder --out runs/frontier-standoff --merge-only
```

Each cell writes `<target>--<mode>--<backend>/cell.card.json`; the merged
`frontier-matrix.md` holds the full table + per-mode scaffolding deltas per backend.

## 5. What would count as the tool "standing" — acceptance lines

1. **Precision moat**: raw frontier arms are expected to produce unconfirmable
   claims; if raw matches our `precision = 1.00`, the verify protocol is adding
   nothing and must be reworked. (Appen's data says raw recall ≪ 1; our F1 rule
   makes that cost them.)
2. **Scaffolding ladder**: on the SAME model, `swarm ≥ flat > rawk > raw` on
   objective completion. If `rawk ≈ swarm` on any target, the swarm is overhead
   there and should be simplified.
3. **Frontier headroom**: swapping glm-4.6 → frontier inside the swarm should
   mainly raise `completion` and kill stall-halts (the glm-4.6 failure signature),
   not mainly raise F1 (finding is not our bottleneck).
4. **Cost honesty**: tokens-per-confirmed-finding is reported per cell; a frontier
   model that doubles tokens for +0 completion is a regression, not an upgrade.

## 6. Known limits of the instrument

- The raw arm's replay gives it requests, not a browser: XSS that needs DOM
  interaction under-scores on `raw` by construction (the flat/swarm arms have the
  browser; the objective text warns the raw model about this).
- Lab targets are dockerless and RoE-scoped to 127.0.0.1; the Docker suite
  (juice-shop, XBEN-001) still goes through `redteam.bench.runner` and is out of
  matrix scope by design.
- Account-level 429s (z-ai) can still kill an arm mid-run; the bridge serializes
  call starts, and the gateway's 2-strike cooldown rotates — but a hard account
  limit is an environment failure, recorded as `halt_reason`, never scored as zero
  skill.
