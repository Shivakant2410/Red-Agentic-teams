# ARTEX — binding findings to wire truth + human-assisted auth

Thesis (as shipped): **every finding is bound to CA-traced proxy traffic and
a verbatim decoded response quote, and the human-assisted browser extension
carries 2FA/SSO/captcha steps that Playwright-only auth cannot honestly do.**

## The chain

```
human operator's browser (+ ARTEX Session Bridge extension)
  │  completes 2FA / SSO / captcha themselves
  ├─ POST /api/traffic/ingest {run_id, rows, sessions}
  │     ├─ rows  → traffic.jsonl  source=extension   (scope-labeled: in-scope /
  │     │          denied / scope-unverified — evidence only, never forwarded)
  │     └─ sessions → <run>/ingest/sessions.jsonl    (fail-closed without a
  │                frozen scope.json; auth-header-filtered; audit trail)
  │
RECON/ACCESS specialist → ingest_sessions tool
  │  registers the session (set_session discipline: values never echoed,
  │  audit names only, foothold source=extension_ingest)
  │
agent probes (http_probe / browser / crosscheck / confirm)
  │  every exchange through EvidenceProxy (:8788, run CA, scope+budget)
  │  → traffic.jsonl rows carry VERBATIM DECODED bodies
  │    (accept-encoding rewritten to identity; gzip/deflate/br decoded for
  │     evidence when a server compresses anyway, annotated
  │     X-Evidence-Decoded-From)
  │
confirm_finding / record_finding / verify_finding_independently
  └─ Finding.evidence_refs = [{"kind":"traffic","seq":N,...}]
     + "[ARTEX quote — traffic seq N, METHOD url -> status]" verbatim line
     → the report reader opens the exact wire exchange the proof ran against
```

## Piece by piece

### 1. Recording proxy on :8788 (redteam/proxy.py)

`EvidenceProxy` now defaults to a **stable listener on :8788** so operator
tooling and the extension story stay predictable; when the port is taken it
falls back to an OS-assigned one and says so (`proxy_status.fallback_note`,
audit `proxy.start.fallback_note`). One run-scoped CA per run
(`<run>/proxy-ca/ca.crt+key`) — generated at start, dead at run end; MITM
decrypts compliant clients, rejects-pinned fail loudly, passthrough never
claims decrypted content. Every proxied tool exchange — including the
sandbox's `bash`-driven curl/ffuf traffic routed via `HTTP(S)_PROXY` — is
recorded with masked credential headers and (new) **decoded gzip/deflate/brotli
bodies** so evidence is never "a gzipped body nobody can read".

### 2. Verbatim quote binding (redteam/quotes.py + findings)

`Finding.evidence_refs` (new field) holds
`{"kind": "traffic", "seq": N, "url", "status", "source", "ts"}` refs;
`quote_evidence()` joins a request to the most recent matching traffic row and
extracts a size-bounded **verbatim decoded response quote** appended to the
finding's evidence text. Wired into:

- `confirm_finding` — quote of the payload request at record time;
- `record_finding` — optional `traffic_seq` input (cite the exact row) or
  URL match;
- `verify_finding_independently` — the re-check's own exchange is bound at
  `promote()` time, so a confirmed verdict cites the wire it actually ran
  against.

Honest absence: no matching row → no refs, no fabricated quotes. Duplicates
merge without losing provenance (refs accumulate on merge/promote).

### 3. Human-assisted auth loop (extension/ + POST /api/traffic/ingest + ingest_sessions)

- `extension/` — Chrome/Edge MV3 ("ARTEX Session Bridge"): bounded
  request/response-header ring, cookie capture for the active site, two
  actions (Share session / Flush traffic) posting to the control plane.
  MV3 cannot read response bodies without the debugger API — documented;
  the agent's own probes cover bodies.
- `POST /api/traffic/ingest` — rows are **evidence only** (never forwarded);
  the run's **frozen scope.json** labels them honestly (accepted / denied
  "out of run scope" / scope-unverified); **sessions fail closed** without a
  frozen scope; every batch is appended to `<run>/ingest/audit.jsonl`.
- `ingest_sessions` — agent-side pickup: lists pending sessions (header NAMES
  only), registers with `set_session` discipline (values held, never echoed;
  masked ack), foothold recorded with honest source `extension_ingest`
  (a session alone never satisfies an objective criterion), consumed ids
  tracked so repeat calls are idempotent. Registered for RECON and ACCESS.

## Security posture

- Scope: every agent-side exchange (fetch path, browser route guard, proxy
  dial, replay) is ScopeGuard-checked; ingest rows are LABELED by scope, and
  only credentials the operator explicitly shares enter the run — through a
  fail-closed gate.
- Secrets: header masking at the recorder; credential-shaped metadata
  withheld; session values stored in the run dir only, never echoed into
  transcripts/audit/reports; the ingest audit carries names, not values.
- The control plane must stay loopback-only — it accepts operator captures
  by design (CORS is open for the dashboard; do not expose the port).

## Tests

`tests/test_artext_binding.py` (8): quotes by seq/URL + bounded + honest
absence; finding binding via record_finding (auto + explicit seq) and
refs persistence through promote; proxy :8788 default + fallback note;
gzip-decoded verbatim evidence row (non-compliant server); ingest endpoint
(scope labeling, session filtering `ext:` labels, fail-closed without scope,
404); ingest_sessions pickup (list-only names-only, masked ack, foothold +
audit, idempotent consumption). See also `tests/test_evidence_proxy.py`
(12 proxy tests) and `docs/recon.md` for the recon plane.

## Remaining limitations

- Extension captures headers/cookies, not bodies (MV3 debugger-API constraint).
- `ingest` trusts that the operator shares sessions only for in-scope targets;
  the scope gate labels traffic but cannot prevent a human from pasting
  off-RoE cookies — the audit trail makes it visible.
- Brotli decode requires the optional `brotli` package (honest raw fallback).
