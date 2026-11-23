# Evidence MITM, browser auth-flow telemetry, and proof quotes

This builds on the existing \`redteam.proxy.EvidenceProxy\`, \`TrafficRecorder\`,
Kali sandbox, Playwright browser, and independent finding-verification pipeline.

## Recording proxy

- The run starts the EvidenceProxy on port \`8788\` by default.
- Override the port with \`RED_EVIDENCE_PROXY_PORT\`; if the requested port is busy,
  the run falls back to an ephemeral port and reports the actual listener.
- A fresh run-scoped CA is generated under \`runs/<run_id>/proxy-ca/\`.
- The CA is installed into the Kali container trust store. Upstream TLS
  certificates are still verified against the system trust store.
- HTTP(S) tool traffic from the sandbox is routed through \`HTTP_PROXY\` /
  \`HTTPS_PROXY\`. HTTPS is decrypted only in MITM mode; passthrough rows are
  metadata-only and never claim to contain decrypted content.
- Sandbox Bash executions are also appended to \`traffic.jsonl\` as \`source=bash\`.
  Common inline authorization, cookie, password, token, OTP, and API-key values
  are redacted before the command is written.

The proxy sees HTTP-speaking tools that honor proxy environment variables.
Raw-socket traffic (for example, some Nmap modes) remains bounded by the
sandbox egress firewall but is not represented as decoded HTTP.

## Chrome / Edge extension

Load \`browser-extension/\` as an unpacked Manifest V3 extension in Chrome or Edge.
Configure the local control-plane URL, run ID, and the run token found at
\`runs/<run_id>/traffic_ingest.token\`.

The extension sends events to \`POST /api/traffic/ingest\`. The endpoint is
loopback-only, requires the per-run token, accepts a small allowlist of event
types, strips URL query strings/fragments, and appends metadata events to the
same traffic sequence.

**Privacy boundary:** the extension detects OTP/CAPTCHA challenge presence and
submission state only. It never reads OTP digits, password values, CAPTCHA
response tokens, cookies, request bodies, or response bodies. It does not solve
or bypass challenges. TrafficRecorder also redacts common auth/challenge fields
from JSON and form bodies and withholds multipart bodies.

## Decoding and proof-of-exploit quote checks

The proxy keeps the original response bytes and headers unchanged for the client.
For the evidence copy, gzip and zlib/raw-deflate bodies are decoded with a bounded
output size. Unsupported, malformed, or oversized compressed bodies are marked
as undecodable rather than treated as readable evidence. The sandbox curl path
uses \`--compressed\` so proof predicates receive decoded response text too.

\`verify_vulnerability\` supports the \`body_quote\` condition:

- \`request\`: name of the response to inspect
- \`quote\`: exact human-readable quote (maximum 2,000 characters)
- \`present\`: optional boolean, default \`true\`
- \`normalize_whitespace\`: optional boolean, default \`true\`

This makes a quote a deterministic proof predicate rather than an LLM assertion.
The existing finding lifecycle remains authoritative: a reproduced proof is
queued for independent verification; only the independent verifier can promote
it to \`confirmed\`. No new numerical PoE scale is inferred by this change.
