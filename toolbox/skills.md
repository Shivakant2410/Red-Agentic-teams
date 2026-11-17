# Skills & hands — what runs without a binary

The sandbox gives the agent BINARIES. The engine's own reasoning primitives
need none of them — they are first-party Python and keep working even with a
bare image. This page maps that layer so the toolbox is understood as an
ADD-ON to real capabilities, not the capability itself.

## Skills (proven proofs, replayable)

`redteam/skills.py` — `SkillLibrary`:

- `capture(name, description, requests, conditions, ...)` — after a proof
  survives verification, the exact HTTP sequence is captured as a SKILL:
  parameterized requests + the preconditions that made them work
- `recall(query=, cwe=, k=)` — retrieval by text/CWE for the planner
- `apply_skill` (tool) — re-runs a PROVEN proof instead of designing a new
  one; used on retests and expanded-scope follow-ups

Skills are the engine's memory of what WORKED on this target class. They
reference no binaries — a skill replay is pure HTTP through the same
rate-limited, scope-checked fetch path.

## Technique templates

`FindAttackTemplatesTool` / `ApplyTemplateTool` (over the attack-tree corpus,
`redteam/attack_tree.py`): research-backed bet templates (CWE-tagged signal
combinations) the planner can instantiate. Again: knowledge, not binaries.

## First-party tools (no binary required)

| Tool | What it does |
|---|---|
| `http_probe` | cheap session-aware LOOKING; never touches the finding pipeline |
| `authenticate` / `set_session` | hold identities; register operator-handed static tokens |
| `try_credential` | bounded credential checks |
| `jwt_inspect` | deterministic offline JWT analysis (alg/claims/kid) |
| `xss_reflect_probe` | maps marker reflections to sink contexts, emits a READY check_spec |
| `graphql_inspect` | deterministic 4-request introspection checklist |
| `verify_vulnerability` | the general agent-designed proof primitive |
| `verify_workflow_abuse` | business-logic proofs (ordered sequences, single-run + control) |
| `confirm_finding` / `prove_privilege` / `extract_secrets` | proof pipeline steps |
| `verify_finding_independently` | the ONLY path to "confirmed" — runs from a separate context |
| `surface_scan` | fills the asset inventory from the RoE allowlist itself (never widens scope) |
| `spa_recon` | walks a login-gated SPA with bootstrap mocks (ARTEX api-recon port) |
| `crosscheck` | second-signal triangulation for tool claims |
| `record_finding` / `record_access` / `claim_objective` | bookkeeping under approval |
| `kali_exec` | the sandbox shell — needs the image, not a specific binary |
| `tool_provision` | the on-requirement toolbox entry (see top-level README) |

## How the layers connect

```
planner bets (≥2 independent signals)
        │
        ├─ first-party probes ──── no binary, always available
        ├─ LEAD generators ─────── nmap/httpx/ffuf/katana/arjun/nuclei (toolbox/*.md)
        └─ kali_exec ───────────── any binary in the image (catalog-only tools)
        │
        ▼
verify → confirm → capture as SKILL → replay via apply_skill
```

Doctrine: a missing binary degrades a LEAD SOURCE, never the proof pipeline.
Findings only enter through first-party verification — that is why the matrix
(15 TP / 1 FP / 0 FN) is stable whether or not the toolbox is installed.
