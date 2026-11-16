# RESEARCH-M5 — the offensive core (recon → surface map → pre-ex → post-ex)

Written BEFORE any M5 code, per the standing mandate: no component enters this
engine without (a) web-verified evidence someone actually uses it, (b) a
competitor对照, (c) research-paper lineage, (d) a four-lens review
(AI-security-engineer / security-engineer / mathematician / researcher), and
(e) an adopt/reject verdict. M4's direction (policy gates, boundary papers —
CaMeL/MAST) is ARCHIVED for this milestone: the user's call is correct — a red
teamer is bought for recon, surface mapping and exploitation, not for
guardrails. M4's code stays (it is fail-safe plumbing, already green), but M5
spends zero further budget on governance.

**STATUS (2026-11-07): EXECUTED AND PROVEN.** Pre-registered predictions
§5 P1–P5: **5/5 HIT** on the live labs (freightlane + dvlba). Exit evidence
and the honesty scorecard: `M5-PROOF.md`; machine-readable:
`m5-results/M5-SUMMARY.json` (pass: true). Unit suite 81/81.

## 1. What the competitors actually do (web-verified 2026-11-07)

### XBOW (commercial leader — xbow.com)
Their product is organized as FOUR cards, and three of the four are offense:
- **Attack Surface**: "Upload API specifications … XBOW's discovery agent knows
  exactly what to map. XBOW still does its own discovery on top of what you
  provide." A team uploaded an OpenAPI spec (148 endpoints); XBOW "parsed it,
  mapped the full attack surface, and started the assessment already knowing
  every route. No crawling required." Another uploaded raw route files; XBOW
  "extracted 81 endpoints from those route definitions."
- **Priorities**: feeds "the coordinator, the persistent orchestration engine
  that directs testing" — the operator says which areas matter.
- **Attack Strategy**: "provides context to XBOW's attack agents, the
  short-lived, focused workers that execute actual exploits." Documented use:
  escalate a path traversal to RCE; **variant analysis** — "hidden endpoints
  following the same pattern that hadn't been tested yet."
- **Validation**: canary tokens so a finding is provable, not claimed.
De Moor's own description of the loop: "reconnaissance, attack-surface
discovery, prioritization, and repeated exploitation attempts."
→ **Adopt**: surface-first architecture with discovery-on-top of declared docs;
prioritization as a first-class artifact; variant amplification of verified
primitives (XBOW's own "found one, now find similar" play).
→ **Reject**: their assessment-guidance UX layer (operator product, not agent).

### PentestGPT (Deng et al., USENIX Security 2024, Distinguished Artifact)
Reasoning / Tool / Parsing trio over a context pool; phases recon → enum →
exploit → post-ex/persistence. Core empirical finding: LLMs are fine at
sub-tasks (run a tool, read output, propose next step) but "encounter
difficulties maintaining an overall testing context" — the +228.6% over
GPT-3.5 comes from scaffolding the context, not from model intelligence.
→ **Adopt**: the phase decomposition as first-class specialist states; their
failure mode is exactly why our blackboard/ledger carries the context instead
of the model.
→ **Reject**: their single-context Reasoning module (we keep the swarm).

### HackingBuddyGPT (ipa-lab)
Narrow round-based loops ("try an action → read the output → reason → decide
next step"); strongest where wins come from small clues (sudo perms, writable
scripts, exposed credentials). Community consensus (PentestGPT vs hB GPT
comparisons): PentestGPT = the reasoning layer across a full engagement;
hB GPT = focused technique loops.
→ **Adopt**: clue-driven narrow loops — our pre-ex matrix is exactly "small
clues, deterministically harvested".
→ **Reject**: one-agent round loop (contradicts the swarm evidence M1–M4).

### MITRE CALDERA (+ Atomic Red Team)
The automation standard for adversary emulation: an **ability** = one ATT&CK
technique with preconditions, commands, parsers, and **relationships**
("uses", "grants"); **planners** order abilities into operations; adversary
profiles are chains of abilities. Facts/relationship/rule store drives
decision-making, not an LLM.
→ **Adopt**: technique-as-operator — every M5 technique declares
preconditions (what must be on the surface graph), effects (what facts it
publishes), and cost (request cap) so the existing attack-graph planner can
rank them. ATT&CK-style verb labeling on post-ex (credential/session/lateral
analogues at the web tier).
→ **Reject**: implant/C2 machinery (we are a web-app/API engine).

### BOLABuster (blog, Aug 2024) + LLM-BOLA framework literature (2024–25)
Automated BOLA detection = enumerate objects per account → attempt
cross-account access → judge. The LLM-enhanced papers add test generation on
top of that same matrix skeleton.
→ **Adopt**: the matrix skeleton, implemented DETERMINISTICALLY — a matrix of
observed status codes needs no model, is reproducible, and feeds our
hypothesis priors. The LLM seam stays where M3/M4 proved it (tie-breaks only).

## 2. Research-paper lineage

- **Manadhata & Wing, "An Attack Surface Metric" (CMU, 2008+, ~1000 cites)** —
  the canonical formalization: a system's attack surface is the subset of its
  resources usable by an attacker — entry points, exit points, channels,
  untrusted data items; measured as damage potential × effort.
  **M5 adaptation (documented deviation)**: per-resource score =
  (mutating verbs ×3 + read verbs ×1 + param-object ×2 + unauthenticated ×4)
  ÷ request cost. Weights are ordinal (mutation > read, unauth > auth), not
  calibrated — claimed only as a PRIORITY ORDER, never as a probability.
- **Sarraute, "Automated Attack Planning" (arXiv:1307.7808)** — attack model
  in PDDL; probabilistic planning by p(success) and cost; **POMDP framing
  "intelligently mixes scanning actions with actual exploits"**. This is the
  theoretical license for M5's core claim: recon and pre-ex actions are not a
  phase prefix, they are cheap information-gathering actions that compete with
  exploits in one utility ranking. Obes et al. 2010 ("Attack Planning in the
  Real World") is the practical predecessor; Chen et al. 2024 survey confirms
  "the planner over the graph, not the scanner, is the differentiator."
  **Adopt the utility ordering; reject the full PDDL planner** — our graph is
  flat (source→edge→goal), a planner would be ceremony; `attackgraph.next_actions`
  already ranks cost-ordered untested edges.
- **BloodHound / SpecterOps + Elmiger et al., IJISS 2024 ("Start thinking in
  graphs")** — attack paths as graph theory; impact = what is REACHABLE from a
  node, counted, not asserted. **Adopt**: post-ex amplification counts
  reachable victims and aggregates measured deltas — "one IDOR" vs "N accounts
  readable" is a reachability count.
- **Arjun (hidden HTTP parameter discovery) + LinkFinder-style JS endpoint
  extraction + Intigriti's 2025 enumeration guide** — the living bug-bounty
  tradecraft: differential-response parameter mining with target-derived
  wordlists; endpoint strings harvested from JS/assets. **Adopt both**,
  target-agnostic: candidates are harvested from the target's own schemas and
  response bodies first, generic wordlist second.
- **OWASP API Top-10 (BOLA/BOPLA = #1 and #3)** — the authz matrix is testing
  the single most common API failure class, not an exotic extra.

## 3. Four-lens review (before code)

- **AI-security engineer**: does pre-ex evidence actually change downstream
  behavior? Yes and measurably so: hypotheses derived from an observed 200
  cross-principal read carry evidence + raised prior, so the exploit specialist
  stops spending its budget discovering what recon already knew (Sarraute's
  scan-vs-exploit utility mix). The bandit learns which recon/pre-ex arms pay
  per shape — dead arms are skipped next run (E1 machinery, unchanged).
- **Security engineer**: is this real pentest work? Yes: content discovery,
  JS mining, authz matrix, param mining, post-ex amplification and replay are
  the standard PTES/WSTG/bug-bounty ladder. Every technique ships with a
  negative control: the matrix records the DENIALS too (403/404), and the
  differential probes ship a baseline request. Nothing is a finding by
  assertion — pre-ex publishes EVIDENCE and HYPOTHESES; only the existing
  verify pipeline can confirm.
- **Mathematician**: three objective functions, each tied to a decision:
  (1) surface priority = ordinal damage-potential/effort (decides target
  queue order); (2) pre-ex utility = expected-information × remaining-budget
  gate (decides run/skip); (3) amplification = reachability count with
  measured per-victim delta (decides impact line in the report). No algorithm
  without a decision it serves; no learned weights without a bandit behind them.
- **Researcher**: every technique has lineage (§1–2) and a pre-registered
  prediction (§5) scored at exit — the M3/M4 honesty protocol continues.

## 4. Verdict table

| Technique | Who uses it | Paper lineage | Verdict |
|---|---|---|---|
| surface priority queue | XBOW Priorities card | Manadhata & Wing 2008 | ADOPT (adapted) |
| declared-doc ingestion + discovery-on-top | XBOW Attack Surface card | — (product docs) | ALREADY IN (M2); M5 keeps |
| JS/asset endpoint mining | LinkFinder/ffuf tradecraft | bug-bounty practice | ADOPT |
| target-derived content discovery | Intigriti guide 2025 | bug-bounty practice | ADOPT (generic list demoted to fallback) |
| hidden-param differential mining | Arjun | bug-bounty practice | ADOPT (target-derived candidates) |
| per-principal object map + authz matrix | BOLABuster; OWASP API#1 | 2024 BOLA automation | ADOPT (deterministic) |
| evidence-raised hypothesis priors | Sarraute POMDP mixing | arXiv:1307.7808 | ADOPT |
| technique-as-operator (pre/effects/cost) | CALDERA abilities | ATT&CK | ADOPT |
| post-ex amplification (reachability) | XBOW variant analysis | BloodHound/Elmiger 2024 | ADOPT |
| persistence/replay of verified primitives | PentestGPT post-ex phase | ATT&CK persistence analog | ADOPT (lab-legal verbs only) |
| PDDL planner dependency | Sarraute/Obes | 2010–13 | REJECT (flat graph; planner exists) |
| full LLM-driven recon/exploration | hB GPT single loop | — | REJECT (E6: LLM tie-breaks only) |
| more policy/boundary machinery | M4 direction (CaMeL/MAST) | arXiv 2503.* | REJECT for M5 (archived, kept as plumbing) |

## 5. Pre-registered predictions (scored in run_m5.py, honestly)

- **P1** — freightlane run1 publishes an authz-matrix OBSERVATION whose
  evidence raises ≥1 h_cross_tenant-class hypothesis to evidence-derived
  (derived_from the matrix fact), and that hypothesis still verifies.
- **P2** — recon discovers ≥1 endpoint NOT in the generic PROBE_PATHS list and
  NOT in the served openapi/route index (asset-mining or derived-probe origin,
  tagged with its source).
- **P3** — pre-ex costs ≤ 70 requests on freightlane; total run1 ≤ 1.35× M4's
  616-request baseline (≤ 832) at budget 900.
- **P4** — post-ex publishes ≥1 amplification ESCALATION with a measured
  aggregate delta across ≥2 victim objects on a verified finding.
- **P5** — non-regression: GV-1..8 verified run1+run2, decoy FPs 0, dvlba
  B1..B8 with 0 unmatched, deterministic path llm_seam_calls == 0,
  markers ≥ 2, schema identity holds.
