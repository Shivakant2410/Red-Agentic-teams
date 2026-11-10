# PI Integration Catalog — open-source assets we can integrate (2026-11)

Companion to `PI_GAP_RESEARCH.md`. Answers: which open-source tools, corpora,
and algorithm code can plug the G1-G11 gaps into `redteam/pi/`, under this
repo's contracts. Every asset was verified to exist as of 2026-11-11; licenses
marked ⚠ must be re-checked in the pinned commit at vendor time.

## Integration discipline (why we don't `pip install` red-team frameworks)

The pi package has four hard contracts (`redteam/pi/__init__.py:1-18`):
additive-only, oracle/technique abstractions import nothing from llmred,
offline-deterministic fixtures, and the registry stays small and inspectable
(`techniques.py:22-25` — "the product's technique vocabulary, not a scraped
dump"). Field evidence reinforces this: model-reliant scoring breaks under
adaptive attackers (arXiv 2604.23887), so our deterministic oracles must never
be replaced by a framework's LLM-judge. Therefore everything enters in exactly
four patterns:

- **A — vendor payloads**: copy selected payloads/templates into
  `techniques.py` with `provenance` strings carrying upstream repo + commit
  SHA + license. No runtime dependency.
- **B — port algorithms**: re-implement the deterministic core of an attack
  generator inside `runner.py`/`techniques.py`, with an explicit
  divergence note where we replace their LLM components with our oracle
  feedback. Seeded → reproducible.
- **C — live-lane libraries**: libraries that need network/model keys (PyRIT)
  are wired into operator-run scripts only, never the fixture bench.
- **D — defense semantics**: hardened-app defense configs gain `IOPolicy`
  flags whose semantics mirror published defenses (CaMeL, Progent, FIDES,
  Spotlighting) — honestly labeled "modeled defense", since we test our
  fixture, not their code.

**Never integrate**: model-based detectors as oracles; any framework's
third-party scoring API inside `bench.py`; network-requiring code in the
fixture path; unlicensed or unverified-license code.

## Asset catalog

### Attack corpora → Pattern A

| Asset | What it gives | License | Gap |
|---|---|---|---|
| **AgentDojo** — `ethz-spylab/agentdojo` (+ NIST fork `usnistgov/agentdojo-inspect`) | Task suites with proven injection task templates (important-instrument, diversion, direct); MIT verified via LICENSE file; NIST maintains an Inspect fork — the strongest adoption signal | MIT ✅ | G9, B-family payloads |
| **ASB (Agent Security Bench)** — `agiresearch/ASB` | ICLR 2025; 10 scenarios, 400+ tools, 10 PI attacks + **memory-poisoning attack dataset** + **Plan-of-Thought backdoor** + 4 mixed attacks + 11 defenses; active (last commit Sep 2026); `data/`, `memory_db/`, `memory_defense/` directories are directly vendorable | MIT ✅ | G1 (memory payloads), G9 (scenario taxonomy), C/E-family (PoT backdoor cross-maps to our PlanFlip family) |
| **InjecAgent** — `uiuc-kang-lab/InjecAgent` | 1,054 indirect-injection cases, 17 user tools, 62 attacker tools, direct-harm vs data-exfiltration intentions | ⚠ verify | B-family payload batch, G9 |
| **WASP** — `facebookresearch/wasp` (NeurIPS 2025) | Official web-agent injection benchmark: end-to-end delivery vectors (visible content, DOM, popups); the paper's "partial success" semantics match our stage ladder | ⚠ verify | G6 (delivery-vector payloads), B-family |
| **invariant mcp-injection-experiments** — `invariantlabs-ai/mcp-injection-experiments` | Working poisoned-MCP-server examples: tool poisoning, cross-server shadowing, rug pull — the canonical G3 payload seeds | ⚠ verify | G3 |
| **promptfoo ascii-smuggling plugin** — `promptfoo/promptfoo` `site/docs/red-team/plugins/ascii-smuggling.md` | Unicode Tags (U+E0000) implementation semantics: visible innocent text + hidden instruction; MIT kept after the OpenAI acquisition (Mar 2026) | MIT ✅ | G4 (A6 extension) |
| **GitInject** — arXiv 2606.09935 (Jun 2026) | Prompt injection in live GitHub workflows (CI/CD channel: PR bodies, action outputs) — new trusted-backend delivery scenario | ⚠ code release | E-family scenario seed |

### Attack algorithms → Pattern B

| Asset | What it gives | License | Gap |
|---|---|---|---|
| **TurboFuzzLLM** — `amazon-science/turbofuzzllm` (NAACL 2025) | Mutation-based template fuzzing, upgraded from GPTFuzzer; black-box; our G2 mutator-operator set. Divergence note: their LLM-judge feedback → our deterministic oracle feedback | ⚠ verify | G2 |
| **GPTFuzzer** — `sherdencooper/gptfuzz` (official) | The canonical 9 mutation templates; already in our provenance — now as algorithm, not just payload source | ⚠ verify | G2 |
| **AgentPoison** — `AI-secure/AgentPoison` (NeurIPS 2024, official) | Memory/RAG backdoor protocol: plant → trigger-retrieve → act. Their trigger optimization is embedding-gradient based (not offline-deterministic) — we port the *protocol* with a deterministic canary-token trigger and cite their numbers (ASR ≥80%, poison rate <0.1%, benign degradation ≤1%) as provenance | ⚠ verify | G1 |
| **CaMeL artifact** — `google-research/camel-prompt-injection` | Official research artifact: capability/provenance interpreter + their task-specific adaptive attack-generation methodology (the strongest published adaptive protocol) | ⚠ verify | G2 methodology, D-pattern semantics |
| **Progent** — `sunblaze-ucb/progent` | Privilege-control policy DSL; IPI 41.2%→2.2% on AgentDojo; their paper ships its own adaptive-attack analysis — the template for our `defense_spec_visible` mode | ⚠ verify | D-pattern `tool_guard` semantics, G2 |
| **FIDES** — `microsoft/fides` (+ PFI `compsec-snu/pfi`, agent-ifc `K20tg/agent-ifc`) | Information-flow-control artifact: confidentiality/integrity labels tracked to the tool boundary — deterministic by design, matches our oracle layer | ⚠ verify | D-pattern `output_filter` semantics |

### Defense semantics → Pattern D (modeled as `IOPolicy` flags)

- `memory_write_approval` — OWASP LLM01:2026 prevention + CaMeL/FIDES flow
  labels on memory writes (G1 hardened variant).
- `tool_desc_pinning` — Progent privilege control + MCP-Scan semantics:
  tool descriptions hash-pinned between approval and call; rug-pull detection
  (G3 hardened variant).
- `ifc_labels` — FIDES/agent-ifc label propagation on output filtering
  (canary-tagged sources may not reach untainted sinks) (G6 hardened variant).
- Spotlighting already exists as a flag (`app_target.py:42-50,580-581`) — add
  its *encoding* variant per the 2403.14720 paper when G4 lands.

### Scenario/protocol anchors (no code needed)

| Asset | Use | Gap |
|---|---|---|
| **MemHarmBench** (arXiv 2611.01700) | Victim-centric cross-session protocol; **no code released** (checked 2026-11-11) → validates building our own scenario | G1 |
| **XSPI** (arXiv 2606.04425) | Lifecycle vocabulary (persist → activate) for our two-phase technique naming/anchoring | G1, G11 |
| **OWASP AI Testing Guide AITG-APP-01** (`OWASP/www-project-ai-testing-guide`) | Official prompt-injection test checklist → cross-walk in bench coverage audit | G9, G10 |
| **PIAtlas / PICorpus** (arXiv 2610.24999) | When PICorpus download lands: `piatlas_class` mapping source | G9 |
| **Awesome-Agent-Security** — `ucsb-mlsec/Awesome-Agent-Security` | Standing meta-index for future vendor batches | all |

### Live-lane only → Pattern C

- **PyRIT** — `microsoft/PyRIT` (MIT ✅; Azure/PyRIT archived): Crescendo/TAP
  multi-turn orchestrators and multimodal converters for the operator-run
  live-model lane documented in `pi/__init__.py:15-18`. Covers G7 (multimodal
  converters) and G11 (Crescendo semantics as multi-turn technique seed).

### Track, don't integrate (framework lock-in, no unique payload value)

garak (NVIDIA, Apache-2.0, 120+ probes — probe text only), DeepTeam (Apache-2.0,
agentic attack names), NVIDIA SkillSpector, Tencent AI-Infra-Guard,
invariant MCP-Scan (operator-side scanner worth running *against our own
skills/tool descriptions* as hygiene, outside the fixture path).

## File-level integration map

| Gap | Assets | Moves |
|---|---|---|
| G1 | ASB memory_db + AgentPoison protocol + MemHarmBench protocol | `app_target.py`: memory store + `IOPolicy.memory_write_approval`; `techniques.py`: PI.B6 two-phase memory technique (provenance: AgentPoison@SHA, ASB@SHA); `runner.py`: two-visit protocol |
| G2 | TurboFuzzLLM + GPTFuzzer mutators + Progent adaptive analysis + CaMeL attack-gen | `runner.py`: `adaptive` mode with seeded deterministic mutator operators + `defense_spec_visible`; divergence note (oracle feedback replaces LLM judge) |
| G3 | mcp-injection-experiments + MCP-Scan semantics | `techniques.py`: `tool_description` channel + rug-pull variant; `app_target.py`: `IOPolicy.tool_desc_pinning` |
| G4 | promptfoo ascii-smuggling semantics | `techniques.py`: A6 gains tag/zero-width templates; `oracles.py`: `canary_hits` decodes U+E0000 |
| G5 | (self-built — impossibility-result test) | runner controls: instruction-bearing benign doc + `legit_instruction_compliance` metric |
| G6 | WASP delivery vectors + FIDES labels | typed RELAYED evidence enum; fixture outbound-request recorder; `IOPolicy.ifc_labels` |
| G7 | PyRIT converters (live lane) | skip records gain `evidence` + `live_lane` pointers; operator script |
| G8 | OWASP 2026 + AITG-APP-01 | dual-pin anchors; per-technique scenario mapping |
| G9 | PIAtlas + ASB scenarios + AITG-APP-01 | `piatlas_class` field + coverage-audit cross-walk |
| G10 | (self-built) | bench `honesty` block + held-out payload split |
| G11 | PyRIT Crescendo + ASB mixed attacks + XSPI vocabulary | family E two-turn technique; thread protocol shared with G1 |

## Vendor hygiene protocol (per batch)

1. Pin upstream commit SHA; record license in the technique `provenance`
   string; ⚠ items get license verification **before** vendoring.
2. Extract only the payloads a gap needs — the registry stays small and
   inspectable (`techniques.py:22-25`).
3. Every vendored payload gets a test proving canary propagation and oracle
   matchability (the A6 contract: detection sees through the same encodings).
4. Algorithm ports carry a divergence note naming what we replaced (their
   LLM judge → our deterministic oracle feedback).
5. Pattern C libraries never appear in fixture-bench imports; they live in
   operator scripts under `scripts/`.

## Verified-source appendix

Repos opened/confirmed 2026-11-11: ethz-spylab/agentdojo (MIT), agiresearch/ASB
(MIT, active Sep 2026), uiuc-kang-lab/InjecAgent, facebookresearch/wasp,
invariantlabs-ai/mcp-injection-experiments + MCP-Scan blog, promptfoo
(MIT, ascii-smuggling plugin docs), amazon-science/turbofuzzllm,
sherdencooper/gptfuzz, AI-secure/AgentPoison, sunblaze-ucb/progent,
microsoft/fides, google-research/camel-prompt-injection, microsoft/PyRIT (MIT),
compsec-snu/pfi, K20tg/agent-ifc, usnistgov/agentdojo-inspect, ucsb-mlsec/
Awesome-Agent-Security, OWASP AITG-APP-01. Papers: WASP 2504.18575, Progent
2504.11703, GitInject 2606.09935, MemHarmBench 2611.01700, XSPI 2606.04425,
PIAtlas 2610.24999, CaMeL 2503.18813.
