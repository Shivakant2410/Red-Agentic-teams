# Hard Lab — Research Before Code (Phase D)

**Mission.** Build a local lab that is *most hard to find* for our specific
engines (statefuzz FSM/invariant fuzzer + 7-specialist swarm), wire both into
the HypothesisLedger ("hypothetical engine") so every hypothesis gets a
propose → test → resolve lifecycle, and report the found/missed matrix
honestly — including false positives against decoys.

**Discipline.** Research first, code second. Every design decision below
cites a verified source or an executed prior result from Phases B/C.
Honesty flags: [F] verified by opening the source · [H] high confidence,
multiple converging signals · [U] unverified assumption, used with care.

---

## R1. What "hard" means for THESE engines (not generic difficulty)

Prior runs established the engine's strengths and blind spots:

| Prior result | Evidence | Implication for lab design |
| --- | --- | --- |
| dvlba-shop: 8/8 seed classes found, 87 requests | Phase B `results/findings.json` | Seeds cannot be single-request, breadcrumb-annotated flaws |
| Swarm: 9 dedup findings, 3 chains, 2nd run cheaper via memory | Phase C run1/run2 | Lab must not be solved by run-1 memory alone; state must differ per principal |
| Recon insight "openapi outperforms blind probing" | `results/memory/recon.json` | The lab must break the openapi dependency — that dependency is THE load-bearing weakness |
| Swarm `_t_fsm` honestly skips statefuzz when no checkout flow | `swarm/specialists/exploit.py` | FSM spawn path must be exercised by a *stateful* surface shape, or the gap must be reported honestly |
| Techniques are shape-gated (claim/cancel/transfer verbs, 202 async, integer money fields) | `swarm/techniques.py` gates | Seed shapes must legitimately match those gates — no target-name hacks |
| HypothesisLedger deferred oracle exists but only dvlba's async refund exercises it | `statefuzz/oracle.py` | Lab needs effects unassertable at mutation time (async settle windows) |

The last two rows drive the central design tension: the technique library is
*target-agnostic but disclosure-hungry* (it reasons over an openapi-derived
resource graph). A lab with zero machine-readable surface would starve the
hypothesis engine entirely (recon fails → no SURFACE fact → zero hypotheses →
zero tests). That would measure only "no openapi ⇒ blind", which we already
know from memory insights. The hard question is the middle tier.

## R2. Verified sources

1. **[F] Kettle, "Smashing the State Machine: The True Potential of Web Race
   Conditions"** — Black Hat USA 2023 / DEF CON 31, PortSwigger Research.
   https://portswigger.net/research/smashing-the-state-machine
   Contributions adopted:
   - *"with race conditions, everything is multi-step"* — the hardest class is
     hidden multi-step sequences with temporary sub-states, NOT single-endpoint
     limit overruns. Our seed set is dominated by multi-step state-machine flaws.
   - Methodology: (1) predict potential collisions, (2) probe for clues,
     (3) prove the concept. Step 2 justifies the lab's *clue trail* (route
     index + error contracts + audit trail) — hardness must come from the
     state machine, not from hiding the door entirely.
   - Last-byte sync is the established HTTP/1.1 race primitive — already
     implemented in our executor (`race`, `race_multi`).
2. **[F] Kettle, "The single-packet attack"** (2023).
   https://portswigger.net/research/the-single-packet-attack-making-remote-race-conditions-local
   — network jitter is what hides races remotely; over loopback jitter ≈ 0,
   so our lab must simulate the *application-side* window (worker latency,
   check-then-act gaps) rather than rely on network jitter. [U] loopback races
   are near-deterministic; we widen windows deliberately and note this as a
   validity threat (R5).
3. **[F] PortSwigger Web Security Academy — Race conditions topic.**
   https://portswigger.net/web-security/race-conditions
   — "race window" definition; TOCTOU taxonomy; limit-overrun vs hidden
   multi-endpoint sequences; the Academy's hard labs are built from the BH
   USA 2023 research. Seed taxonomy anchored here.
4. **[F] Hypothesis `RuleBasedStateMachine`** docs.
   https://hypothesis.readthedocs.io/en/latest/stateful.html
   — stateful testing = rules (actions) + invariants, sequences generated
   against a model. Our FSM walk + I1–I5 metamorphic oracles mirror this.
   Hardness lever: make the *model incomplete* — state transitions observable
   only through side effects (wallet deltas, async event polls), never
   declared in a schema.
5. **[F] Barr et al., "The Oracle Problem in Software Testing: A Survey"**
   (IEEE TSE 2015). https://www.computer.org/csdl/journal/ts/2015/05/06963470/13rRUx0geBw
   — when no direct oracle exists, metamorphic relations are the fallback.
   Our HypothesisLedger IS a deferred metamorphic oracle (wallet-delta vs
   expectation after callback resolution). The lab must include effects that
   are unassertable at mutation time to exercise it: async settlement.
6. **[F] Cybench** (Stanford CRFM 2024, arXiv:2408.08926).
   https://cybench.github.io · https://crfm.stanford.edu/2024/08/19/cybench.html
   — difficulty grounded in human first-solve time (FST 2 min … 24 h 54 min);
   without subtask guidance, agents of the era solved only tasks humans did
   in ≤ 11 min. We adopt FST-style grounding: each seed carries an estimated
   human-solve profile (steps + discovery key) so "hard" is argued, not felt.
7. **[F] OWASP API Security Top 10 (2023).**
   https://owasp.org/API-Security/editions/2023/en/0x11-t10
   — seed taxonomy mapped to API1 BOLA, API3 BOPLA, API5 BFLA, API6
   Unrestricted Access to Sensitive Business Flows, API4 Unrestricted Resource
   Consumption.
8. **[F] MAST — "Why Do Multi-Agent LLM Systems Fail?"** (Cemri et al. 2025,
   arXiv:2503.13657). https://arxiv.org/abs/2503.13657
   — decoys exist to provoke the MAST *verification* failure class on purpose:
   a swarm that reports decoys as findings demonstrates that failure mode
   measurably. Decoys are instrumentation, not decoration.

## R3. The HypothesisLedger connection ("hypothetical engine")

Phase B's ledger was a single-purpose deferred oracle (async refund window).
Phase D generalizes it into the connective spine (`engine/ledger.py`):

- **propose(source, tag, title, prior, plan)** — every HYPOTHESIS fact the
  swarm publishes, every statefuzz deferred window, every runner-level probe
  becomes a ledger entry with provenance.
- **test / attach_evidence** — exploit dispatches attach request counts and
  derived finding ids.
- **resolve(status, evidence)** — statuses are honest:
  `confirmed` (independent re-verified), `confirmed-by-transcript` (race
  artifact consumed), `refuted` (independent re-execution found no
  violation), `inconclusive` (never tested — budget, stall, or no surface).
- The final artifact `hypothesis_ledger.json` shows the full lifecycle, so
  the report can state not just "what was found" but "what was believed,
  tested, and what the evidence did to the belief."

## R4. Design decisions (each: decision → mechanism → falsifiable test)

- **D1 Domain: `meridian-vault`** — prepaid escrow vaults, payouts, transfers,
  promo vouchers. Chosen because its verbs (claim/cancel/transfer/resize),
  202-async settlement and integer money fields legitimately match the
  technique library's shape gates. Test: every seed is reachable by at least
  one GENERIC_RULES hypothesis without target-specific code.
- **D2 Disclosure tier: no `openapi.json`; thin `/api` route index** —
  resource+verb disclosure with NO schemas, NO parameter names, NO state
  machine. Required fields leak via 422 error contracts (realistic for
  validation-heavy APIs). This is Kettle step-2 "probe for clues" made
  concrete, and it forces a target-agnostic engine upgrade (U3: learn
  schemas from error contracts) instead of target-specific hacks.
- **D3 Hidden verbs**: `settle` (payouts) and `retry` (payouts) exist but are
  absent from the route index; discoverable only by verb wordlist probing
  (`h_hidden_verbs`). `retry` is a **decoy** — it is genuinely safe (only
  resumes failed payouts, no credit).
- **D4 Seeds S1–S8** (ground truth in `GROUND_TRUTH.md`, kept outside the
  target app):
  - S1 global quota race on voucher claim (I5, distinct principals)
  - S2 settle-after-cancel: payout cancel credits balance while the external
    wire stands (I1, 3-step, requires hidden verb)
  - S3 async TOCTOU: settle debits without balance re-check (I4, deferred
    window + transfer drain)
  - S4 asymmetric rounding drift on vault resize cycles (I4, aggregate-only)
  - S5 cancel dedupe keyed by reason string (I1, REPLAY)
  - S6 terminal-state reopen: resize on a canceled vault re-credits (I2, SKIP)
  - S7 cross-tenant audit leak → confused-deputy refund (I3→I1, 2 findings)
  - S8 account existence oracle (403 vs 404, LOW — severity discipline test)
- **D5 Decoys D1–D4**: sample `/.env` (harmless placeholders), safe `retry`
  verb, correctly-validated negative transfer, correctly-enforced account
  read (403). False positives against these are counted in the report.
- **D6 Deferred windows are real**: payouts settle on a worker thread after
  0.4–0.9 s with an event poll path; balance effect is unassertable at
  create time → must flow through the ledger's deferred hypothesis.
- **D7 Fresh principal per probe** (Phase B lesson: cross-probe state
  pollution burned the refund probe) — enforced by technique library already;
  the lab never relies on probe ordering.
- **D8 Engine upgrades (target-agnostic, each marked `# hard-lab upgrade`)**:
  - **U1 recon**: `fetch_index` (GET /, parse hint comments/scripts) and
    `fetch_route_index` (GET /api) techniques — Kettle step-2 tradecraft.
  - **U2 surface**: build the resource graph from the route index (no openapi
    needed); read paths land in the readback bucket for balance discovery.
  - **U3 techniques**: schema-from-errors — when schemas are empty, POST the
    lawful-shape body, parse the 422 error contract for required fields and
    types, hydrate, retry once. Applied in Env.create and the six runners
    that gate on non-empty schemas.
- **D9 Two runs (fresh memory, then same memory)** mirrors the Phase C
  protocol so "gets better over time" is measured on the hard lab too.

## R5. Honest threats to validity

1. Loopback races are near-jitter-free → windows widened app-side (worker
   latency, 2 ms check-then-act gap); wins are easier than production.
2. Seed shapes were chosen to intersect the technique library's gates
   (necessarily — unfindable-by-design seeds would only prove blindness).
   Difficulty therefore lives in multi-step discovery, not exotic shapes.
3. The decoys are simple; passing them is necessary, not sufficient,
   evidence of false-positive discipline.
4. The scorer matches findings to seeds by invariant + endpoint + mechanism
   keywords; borderline S8 (existence oracle) is scored LOW either way.

## R6. Acceptance criteria

- A1: every seed S1–S8 is independently reproducible by a scripted curl-level
  probe (`tests/test_hardlab.py` green) — the lab is valid before the engines
  run.
- A2: every decoy D1–D4 is *not* reproducible as a violation.
- A3: engines run inside loopback-only scope guard with STOP file and budget;
  all traffic recorded with provenance.
- A4: report shows found/missed per seed, false positives per decoy, the full
  hypothesis ledger lifecycle, request counts, and the run1→run2 delta.
