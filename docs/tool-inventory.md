# Tool inventory — what we added, phase by phase, and what each output is allowed to be believed for

House rule this document enforces: **a tool's direct output is never believed on its
own.** Every claim gets a *second method* (crosscheck), every finding gets an
*independent replay + negative control* (verify_finding_independently), and only
k-of-n reproduction that a benign control does NOT match becomes "confirmed". A tool
agreeing with itself is not verification.

Legend: **[NEW]** = added in this engagement (phases D0–D2); nothing-marked = shipped
before (do not rebuild, see `tool-integration-plan.md` §1). `cN` = OPSEC cost tag.

## Phase 0 — Recon / asset inventory (what is there?)

| Tool | Backend | Output & trust route |
| --- | --- | --- |
| `surface_scan` | RoE allowlist itself | ENDPOINT/HOST nodes from the allowlist — operator ground truth, **exempt** from crosscheck by definition (it cannot widen scope) |
| `host_probe` **[NEW]** | httpx (W1b) | Status/title/tech/IP per ONE in-scope URL → ENDPOINT+TECHNOLOGY nodes; lead. Crosscheck: first-party GET (`crosscheck_lead`) |
| `port_scan` **[NEW]** | nmap `-sV --version-light -oX -` (W1b) | HOST+SERVICE nodes for ONE allowed host, RoE-port fail-closed; web services get ENDPOINT stubs. Crosscheck: raw first-party TCP connect |
| `spa_recon` | first-party walk (ARTEX port) | Login-gated SPA's runtime API routes. Crosscheck: first-party GET |

## Phase 1 — Discovery / surface expansion (where can we go?)

| Tool | Backend | Output & trust route |
| --- | --- | --- |
| `content_discovery` **[NEW]** | ffuf `-json` (W1) | Hidden paths → ENDPOINT leads. Crosscheck: first-party GET (404/410 contradicts) |
| `crawl` **[NEW]** | katana `-jsonl -fs rdn` (W1) | JS-aware crawl, domain-field-scoped → ENDPOINT leads. Crosscheck: first-party GET |
| `param_discovery` **[NEW]** | arjun `-oJ` (W1) | Hidden-parameter candidates → lead payloads (never graph nodes). Crosscheck: first-party WITH/without differential |

## Phase 2 — Inspect / vulnerability checklists (what looks wrong?)

All leads; none record findings. Binary-backed (nuclei) → crosschecked first-party;
first-party inspectors → crosschecked with FRESH inputs (a new marker, a differential
pair) — replaying an inspector's own marker only proves it agrees with itself.

| Tool | Backend | Output & trust route |
| --- | --- | --- |
| `jwt_inspect` | offline deterministic parse | Algorithm/claim flaws in a held token. **Exempt**: offline math; verification is the proof that USES the token |
| `nuclei_scan` | nuclei JSON | Template matches as leads. Crosscheck: first-party re-fetch must contain the extracted marker |
| `xss_reflect_probe` **[NEW]** | first-party HTTP (W2) | Reflection MAP: param → sink class, specials survival; live sinks emit a READY check_spec for `verify_vulnerability`. Crosscheck: fresh-marker reflection in the same param |
| `graphql_inspect` **[NEW]** | first-party HTTP (W2) | 4-request deterministic checklist (introspection, query-over-GET, field suggestions, batching), both outcomes + verify_hint. No cheap second method → crosscheck says **unverifiable** (never believed by default); proof budget decides |
| `crosscheck_lead` **[NEW]** | first-party HTTP / raw socket | The second-method engine itself: corroborated / contradicted / unverifiable per lead; unknown (tool, claim) fails closed. Never findings |

## Phase 3 — Prove (spend budget only on surviving leads)

| Tool | Role |
| --- | --- |
| `confirm_finding` | Single/differential HTTP proofs, k-of-n |
| `verify_vulnerability` | General agent-designed proof primitive (k-of-n + negative control) |
| `verify_workflow_abuse` **[NEW]** (C1-hardened, `tools/logic.py`) | Business-logic proofs: ordered sequences, one-shot semantics, fresh-identifier controls |
| `apply_skill`, `find_attack_templates`, `apply_template` | Re-run PROVEN proofs; research the corpus instead of inventing |
| `http_probe`, `authenticate`, `set_session` | Session-aware exploration/identity — explicitly NOT proof |

## Phase 4 — Independent verdict (nobody grades their own exam)

| Tool | Role |
| --- | --- |
| `verify_finding_independently` | Rebuilds the stored check_spec from scratch, re-runs k-of-n, MANDATES a negative control; the ONLY tool that may say "confirmed". Structural independence: called from the VERIFY specialist context |
| `search_peer_traces` **[NEW]** | Read sibling specialists' raw traces for observations that never became findings — a second source that costs no budget |
| `find_techniques` **[NEW]** | Offline ATT&CK-style technique cards (`data/playbooks/`) — look techniques up, don't hallucinate them |

## Phase 5 — Post-exploitation (prove the boundary moved)

| Tool | Role |
| --- | --- |
| `extract_secrets` | Harvest secret-shaped material; labels, never values, into findings |
| `try_credential` | Use recovered material as a NEW principal, scope-guarded |
| `prove_privilege` | Prove the privilege boundary moved (feeds access graph + killchain) |
| `record_access`, `claim_objective` | Track what we hold and what winning means |

## Cross-cutting planes

- `kali_exec` (sandbox), `browser_*` (5 tools), `record_finding`, `request_approval`,
  `local_exec` (opt-in, `RED_LOCAL_EXEC=1`, never default).
- **State machines** (`docs/state-machines.md`, Phase D1): 11 lifecycles now explicit;
  introspect via `GET /api/state-machines` / `python -m redteam.states --json`.

## The trust ladder (one sentence per rung)

1. A tool lead is a *claim*, not an observation.
2. `crosscheck_lead` re-derives the claim by a structurally different method — sandbox
   binary claims get first-party checks; first-party inspector claims get fresh inputs.
3. Corroborated ≠ confirmed: it only earns proof budget.
4. The proof pipeline (k-of-n + negative control) turns a corroborated lead into a
   pending finding.
5. `verify_finding_independently` — a separate context, the stored spec, a mandated
   control — is the only path to "confirmed".
6. Anything else stays a lead forever, no matter how confident the tool sounded.
