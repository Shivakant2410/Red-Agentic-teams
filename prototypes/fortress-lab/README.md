# fortress-lab — the hardest-to-find local lab + full evaluation

Phase D of the statefuzz / swarm program: a **deliberately brutal target**
and the honest score matrix of every harness we built, run against it over
real HTTP.

## The lab: `helios-billing` (`target/app.py`)

A SaaS billing API — subscriptions, seats, proration, invoices, payouts,
promo credits. Domain shifted away from dvlba-shop so **every dvlba-shaped
constant (SKUs, WELCOME10, ONCE-9K4T, cart/checkout endpoints) lands on a
404**. Money is integer cents; all 10 bugs are deterministic and
wallet-observable. Difficulty design — each seed defeats single-request
scanners:

| seed | tier | class | bug | why it is hard to find |
|------|------|-------|-----|------------------------|
| F1 | HARD | I5 | promo quota check-then-act (35 ms) | per-account quota defeats single-identity races; needs 8 synchronized principals |
| F2 | HARD | I4 | asymmetric proration rounding (credit ceil / charge floor) | +1 cent per cycle, invisible per event; needs N repeated cycles |
| F3 | BRUTAL | I2 | resize accepted on a CANCELED subscription | only reachable after a lawful walk to a terminal state |
| F4 | BRUTAL | I1/I4 | payout debits at async settle with no re-check | TOCTOU across a 0.6 s worker; balance must be drained inside the window |
| F5 | MEDIUM | I3 | global audit leaks every tenant's object ids | harmless-looking readback; an enabler, not a payoff |
| F6 | BRUTAL | I3 | seat resize has no ownership check, credits the CALLER | **unexploitable without F5** — needs a leaked victim id |
| F7 | HARD | I4 | mass assignment: client `unit_cents` overrides pricing | field appears in NO schema; needs differential probing |
| F8 | HARD | I2/I4 | mass assignment: `plan` field upgrades without repricing | unit captured before the plan overwrite; needs readback + delta comparison |
| F9 | BRUTAL | I1 | cancel dedupe keyed by `(subscription, reason)` | identical replay is correctly 409 — only a mutated field re-credits |
| F10 | BRUTAL | I1 | cancel of a SETTLED payout refunds the balance | state must settle first (hidden `release` endpoint accelerates) |

`/api/payouts/{pid}/release` exists but is in **no openapi document** —
discoverable only by verb-wordlist probing on the resource.

Ground truth: `target/seeds.py` (evaluation only). `target/poc.py` proves
each seed with a standalone exploit — **12/12 tests green** (`tests/`).

## The evaluation (`run_fortress.py`)

Three phases, each on a fresh server instance; ground truth loaded only
AFTER all runs (`run_fortress.py` consults `seeds.py` at scoring time):

```
Phase B baseline  statefuzz_run as shipped (dvlba-shaped probes)
                  -> 0/10 seeds, 73 requests, every probe a 404
Swarm run 1       specialist swarm v0.2, fresh memory
                  -> 10/10 seeds, 329 requests, 34 rounds
Swarm run 2       same memory namespaces, fresh server
                  -> 10/10 seeds, 322 requests (no capability loss)
```

All 10 findings carried `verified` stamps from independent re-execution with
fresh principals — except FW-QUOTA-RACE, honestly downgraded to
`verified-by-transcript` (the race consumes the artifact). The access
specialist escalated the F5→F6 chain (leak grants "knowledge of any
subscription identifier" → confused-deputy credit) as a critical ESCALATION.

Run:
```
python run_fortress.py            # full evaluation
python target/poc.py --port 8407  # ground-truth PoCs only
python baseline_statefuzz.py      # Phase B gap, isolated
python run_swarm_fortress.py --run 1
```

## What the swarm v0.2 upgrade added (all target-agnostic)

The unmodified Phase B tool scores 0/10 — its probes ARE dvlba constants.
The swarm upgrade generalizes instead of hardcoding:

- `swarm/specialists/surface_mapper.py` v2 — parses the served openapi into a
  **resource/action graph** (creates, param verbs, non-param verb paths,
  body schemas). Deals with alphabetically-sorted JSON keys by *schema
  richness ordering*, never by target names.
- `swarm/techniques.py` (new) — 8 generic techniques derived from the graph:
  hidden-verb wordlist probe, terminal-state guard, mass-assignment
  differentials, cross-tenant leak→deputy, async TOCTOU, cancel-after-settle,
  rounding-drift cycling, multi-principal quota race (`executor.race_multi`,
  last-byte sync across distinct identities).
- `swarm/specialists/hypothesis.py` — surface-gated generic rules
  (cheap probes first, so a tight budget starves expensive ones last).
- `swarm/specialists/verify.py` — generic findings re-verified by re-running
  the SAME technique library with fresh principals.
- `exploit._t_fsm` — surface-compat gate: the dvlba-shaped statefuzz spawn is
  skipped honestly on unfamiliar lifecycles (budget preserved, gap logged).
- Engagement-brief artifacts (`ctx["artifacts"]`, e.g. `promo_code`) —
  a real red team receives known campaign tokens; behavior is still proven
  by execution.

## Honest engineering log (found by executing against this lab)

The first swarm run scored **4/10**. Each miss was a real defect, fixed and
re-proven — this is the log:

1. `_resource_graph` dropped verb paths without a path parameter
   (`/api/promo/claim`, `/api/credits/transfer`) → quota-race and TOCTOU
   hypotheses never fired. Fixed: third shape branch in the graph parser.
2. Flask serves openapi keys **alphabetically sorted**, so dict-order
   candidate selection picked `payouts` over `subscriptions` (and probed
   `/api/login` as a "create"). Fixed: schema-richness ordering + universal
   auth-vocabulary exclusion.
3. The rounding-drift cycle used the schema minimum (delta 9 seats);
   `9×49900×13/30` divides **exactly** — no drift. Fixed: minimal delta
   (v_up − 1), where the rounding remainder lives.
4. Phase B crashed with `TypeError` on an unfamiliar surface (None fields
   into arithmetic oracles). Fixed with fail-quiet guards in
   `invariants.py` + probe bails in both shipped copies (all 25 Phase B
   tests still green).

## Notes

- The LLM seam runs its deterministic fallback in this sandbox
  (`llm_backend=None`): every hypothesis above came from the surface-gated
  rule engine, not from a language model. Wiring a real backend stays a
  one-line seam (`LLMSeam(backend=...)`).
- Scope: loopback / TEST-NET-1 only (fail-closed guard in both harnesses).
- Suites: fortress 12 · statefuzz 25 · swarm 13 — all green after the
  upgrade.
