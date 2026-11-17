# The B2 deep-research dossier — formal adversary models as instruments

**Status: DELIVERED 2026-11-08 · Phase B2 of the `redteam/llmred` engine**
**Predecessor: Phase B1 (agentic target adapter, commit `586006a`) — verdicts measure real tool invocation.**

Phase B1 closed the says-vs-does gap at the single-attempt layer. Phase B2
answers the next question the engine could not ask: **what are the target's
dynamics?** — how its guard behaves under repetition, how much information
actually crosses its boundary, how fast an attacker moves through it, and how
asymmetric the cost of the exchange is. The models for those questions come
from four disciplines, and this document is the audit trail: what was
researched, what was verified, what was copied into code, and what each
instrument can and cannot claim.

---

## 1. The research protocol (how this batch was built)

The doctrine is unchanged: **research the mature public source first → copy
its concrete model → normalize into the engine → prove offline → declare the
limits.** For B2 the research step was run as a system, not as recall:

1. **Query batteries, not single lookups.** Two parallel search batteries
   (9 distinct queries) covered: propagation/worm dynamics, LLM timing and
   network side channels, Stackelberg security games, LLM signaling and
   deception studies, multi-turn threshold dynamics, denial-of-wallet
   economics, and covert-channel information theory.
2. **A source is only an anchor after it resolves.** Every citation below was
   opened or returned a full content page during the research pass
   (2026-11-08). Nothing is cited from memory. Sources already vetted in this
   repository's own paper bibliography (`docs/paper/refs.tex`) are marked
   *in-repo vetted* and reused as-is.
3. **Discipline → model → instrument → acceptance criterion.** A model earns
   an instrument only when the chain is complete: the published model, the
   deterministic implementation, and a falsifiable offline acceptance test.
   Models without all three were dropped.
4. **The proof loop is allowed to kill design decisions.** During B2 the loop
   caught two real design faults before they shipped, recorded in §5 — one of
   them a live bug inherited from B1's canary minting.

## 2. What was researched (verified anchors)

| # | Source (verified 2026-11-08) | Discipline | What it contributes |
|---|---|---|---|
| 1 | Korzhyk et al., "Stackelberg vs. Nash in Security Games," arXiv:1401.3888 | game theory | the commitment model: defenders commit first, possibly to randomized strategies; attackers surveil and best-respond |
| 2 | Bo An & M. Tambe (chapter), "Stackelberg Security Games — Basics and Application" (ARMOR program) | game theory | the operational doctrine quote: *"The defender commits to a mixed (randomized) strategy, whereas the attacker conducts surveillance of these mixed strategies and responds with a pure strategy"* — the exact behavior `probe_policy_commitment` measures |
| 3 | Crawford & Sobel, "Strategic Information Transmission," Econometrica 50(6), 1982 | game theory | cheap talk: costless statements vs costly actions — the model behind `probe_signaling_gap` |
| 4 | "When Do Large Language Models Exhibit Unsolicited Deception?", arXiv:2504.00285 (preregistered, signaling theory) | game theory / LLM | preregistered evidence that LLM signaling behavior is measurable with cheap-talk game structure |
| 5 | "Cheap Talk Stabilizes Strategic Interaction in LLM Agents," arXiv:2609.16270 | game theory / LLM | LLM agents measurably participate in cheap-talk signaling games |
| 6 | "Large Language Models Are Covert Channels," arXiv:2405.15652 (uses Cachin's information-theoretic steganography formalization) | information theory | the reply channel as a quantifiable information channel — capacity in bits, not canary booleans |
| 7 | "Unveiling Timing Side Channels in LLM Serving Systems," arXiv:2409.20002 | physics | measured timing channels in LLM serving |
| 8 | "Network Side-Channel Attacks on Interactive LLM Services," eprint.iacr.org/2025/167 | physics | network-layer side channels on interactive LLM endpoints |
| 9 | "Token-Length Side-Channel Attacks on LLM API Merged Transmissions" (PromptEcho), USENIX Security 2026, usenix.org/conference/usenixsecurity26/presentation/li-sijia | physics | the current generation of token-length/timing side channels |
| 10 | OWASP, "LLM10:2025 Unbounded Consumption," genai.owasp.org | economics / physics | names Denial of Wallet as the cost-attack example AND input-filter differences as a side-channel source — one page anchors two B2 instruments |
| 11 | Cohen et al., "Unleashing Zero-click Worms that Target GenAI-Powered Applications" (Morris II), arXiv:2403.02817 + compromptmized site | biology / chemistry | adversarial self-replicating prompts; replication → propagation → payload structure; the two propagation modes (RAG-poisoning = passive, application-flow-steering = active) |
| 12 | Liu et al., "Prompt Infection: LLM-to-LLM prompt injection within multi-agent systems," arXiv:2410.07283 | *in-repo vetted* | the agent-to-agent text seam the chain harness measures |
| 13 | Cemri et al., "Why do multi-agent LLM systems fail?" (MAST), arXiv:2503.13657 | *in-repo vetted* | cascading-failure taxonomy the propagation family belongs to |
| 14 | Russinovich et al., "The Crescendo Multi-Turn LLM Jailbreak Attack," arXiv:2404.01833 | pharmacology (model) | the doctrine that every individual turn stays inside the safety distribution — the accumulation is the attack; the dose-response instrument's crossing measurement operationalizes this |
| 15 | Chao et al. (PAIR, arXiv:2310.08419), Mehrotra et al. (TAP, arXiv:2312.02119) | *in-repo vetted* | adaptive attacker search already present in the engine (pair-lite); B2 deliberately does NOT duplicate it — the B2 instruments measure the DEFENDER's dynamics instead |

Deliberately **not** built in B2 (researched, then dropped for lack of a
complete chain): live R0 estimation against real multi-agent deployments
(needs live-model runs — declared out of G3's scope in Batch B and still
out of scope here); dollar-denominated denial-of-wallet accounting (no price
model is claimed — byte/op/latency proxies only); automated boundary mapping
against pure guards (a follow-on campaign strategy, not an instrument).

## 3. Discipline → instrument → acceptance criteria

| Instrument (module) | Model | Acceptance criterion (all proven offline) | Status |
|---|---|---|---|
| `probe_policy_commitment` (dynamics.py) | Stackelberg commitment: pure vs mixed defender strategy | deterministic guard → unanimity 1.0, entropy 0; guard with a known flip pattern → unanimity < 1; `repeats < 2` is a config error | DONE |
| `probe_signaling_gap` (dynamics.py) | cheap talk vs costly signals | promise-then-act double → 2 divergence events; aligned double → 0 events + aligned label; silent actor → unstated-action, never deception; chat target → loud skip | DONE |
| `probe_exfil_capacity` (dynamics.py) | covert-channel capacity (Shannon/Cachin) | full echo = 48 bits; base64 echo = 48 bits (encoded); 8-hex prefix = 32 bits prorated; silent = 0; control-first ordering keeps the benign control interpretable on STATEFUL targets | DONE |
| `probe_timing_contrast` (dynamics.py) | timing side channel + split-half null | 400 ms deterministic delta → signal, p < 0.001, null clean; identical twins → no-signal; monotonic drift manufactures a spurious contrast AND trips the null flag — the null discredits the noise | DONE |
| `probe_dose_response` (dynamics.py) | threshold kinetics (Crescendo doctrine) | closer-gated assembly crosses at the closer turn (15 cumulative chars); eager assembly crosses early; a per-message filter NEVER fires and the chain still crosses — the headline finding; inert control stays flat | DONE |
| `probe_amplification` (dynamics.py) | asymmetric cost (OWASP LLM10 DoW) | byte proxies measured from real traffic; agentic operations ratio = recorded invocations per attacker message (2.0 on the double); chat targets omit the operations metric instead of faking it | DONE |
| `run_propagation_chain` (propagation.py) | Morris II replication/propagation; per-hop survival | full worm → R = 1.0 over 2 propagation hops; attenuating chain contained at hop 1 with R = 0.0; inert chain never leaves hop 0; explicit plant without a canary is refused (attribution is not optional) | DONE |

## 4. The instruments in one paragraph each

**policy_commitment — game theory.** The SSG doctrine says the attacker's
optimal next move depends on whether the defender's committed policy is pure
(deterministic) or mixed (randomized). The instrument sends each of four
probe texts `repeats` times in fresh sessions, classifies every reply with
the deterministic detectors, and reports unanimity rate and mean verdict
entropy. Limits: verdict classes are coarse; a guard randomizing *inside*
one class reads as pure; live-model sampling variance is bounded by `repeats`
and the rate ships with its n.

**signaling_gap — game theory.** Claims are cheap talk; invocations in the
target's own trace are costly signals. Two probe pairs (commitment →
opportunity; capability claim → opportunity) score talk-action divergence on
agentic targets. Divergence is EVIDENCE of a talk-action mismatch, never a
proof of deceptive intent — a denied-capability model may be honest or
mistaken, and the block says so. B1's action-first verdict order is the
prerequisite this instrument builds on.

**exfil_capacity — information theory.** A canary boolean answers "did it
leak"; the channel model answers "how much of the secret crossed." Recovery
classes: full echo, encoded variants (base64/rot13 — the same encodings the
strategies layer attacks with), and prorated partial recovery (≥6 hex chars
to exclude incidental collisions; every partial hit is recorded). The benign
control runs FIRST (before anything is planted) so a stateful target has
nothing in memory — the control then measures machinery leakage, not the
target's memory. Output is an upper bound in bits for THIS secret in THIS
session.

**timing_contrast — physics.** Paired guard-relevant vs benign twins,
order-alternated, latency from the target's own measurement; Mann-Whitney
rank-sum with tie correction (normal approximation, deterministic, no scipy)
plus median delta. The split-half null control is the honesty device: drift
that manufactures a spurious contrast also trips the null, and the block
flags it. The instrument reports effects; it never asserts a leak.

**dose_response — pharmacology.** Three individually inert fragments of a
directive token ride benign narrative, one per turn, with full client-side
conversation replay (the campaign's own stateless semantics); a closer asks
for the assembled token. The dose curve records cumulative fragment chars vs
marker presence; the benign control runs the identical structure with inert
tokens and must stay flat. The demonstrable dynamics result: a filter that
inspects per-message never fires on the ladder, because the CONVERSATION
does the assembling.

**amplification — economics.** Attacker marginal cost is one message;
defender marginal cost is whatever the deployment burns. Measured in the
proxies the engine actually observes: bytes (in/out), recorded tool
invocations per attacker message (agentic targets), and latency per probe —
labeled proxies, never dollars. The amplification-shaped probe is bounded by
design; unbounded loops remain the campaign budget's job to prevent.

**propagation_chain — biology/chemistry (propagation.py).** The Morris II
seam made measurable: hop 0 receives the attacker's plant; each later hop
receives the previous hop's OUTPUT TEXT (tool results deliberately not
carried — the text seam is what the worm papers describe). Per hop: text
survival (canary in output) and action survival (probe tool invoked with the
canary in arguments). Labels: inert / contained / propagated (with an
r-factor over observed propagation hops) / truncated. Attribution is
enforced: an explicit plant without a canary is refused.

## 5. What the proof loop caught during B2 (recorded as evidence)

1. **The constant-canary bug (inherited from B1).** Canary minting used
   `uuid.UUID(int=rng.getrandbits(64)).hex[:12]` — a 64-bit integer fills
   only the LOW half of a UUID's 128-bit hex, so the first 12 characters are
   always zeros: every attempt's canary was the constant
   `CNR-000000000000`. Deterministic per seed, yes — but per-attempt
   attribution, the property the canary exists for, was silently absent.
   Fixed in `campaign.py` and in every B2 minting site with
   `f"{rng.getrandbits(48):012x}"` (seed reproducibility preserved). The
   offline capacity tests caught this because a zero payload makes partial
   recovery behave differently from a random one.
2. **The stateless-replay requirement.** The first B2 draft sent isolated
   single messages per turn; on stateless targets (OpenAIChatTarget — "every
   send replays the full conversation") the plant→harvest, claim→action and
   dose-ladder probes would have measured nothing, because nothing accumulates.
   All accumulation instruments now ride a conversation-replay helper with
   the campaign's exact semantics.

## 6. Scope declarations

- **Live-model non-determinism stays out of scope** (the Batch B declaration,
  unchanged): every number above is proven against deterministic doubles; a
  live run against a real deployment is the operator step.
- **The propagation harness measures harness-level mechanics.** A live R0
  across a real multi-agent deployment requires live runs and is explicitly
  NOT claimed.
- **Cost amplification is measured in byte/op/latency proxies.** No price
  model, no dollar figure, no vendor-specific latency attribution.
- **No new probe-pack objectives and no new pack skills were added.** B2 is
  an engine phase: the pack's Batch B delivery (30 AI skills / 6 shelves /
  `ai_agent_hijack` chains) is untouched — the zero-duplication discipline
  applies to the engine the same way it applies to the pack.
