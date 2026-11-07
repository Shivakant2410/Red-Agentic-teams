# AI Improper Output Handling (LLM05/LLM10)

**CWE-79** · 4 skill(s) · folder `categories/ai_output_handling/`

## Skills in this shelf

- `ai/LLM output markdown XSS sink` (CWE-79)
- `ai/LLM generated code execution` (CWE-94)
- `ai/Model suggested URL SSRF` (CWE-918)
- `ai/Token burn amplification nested calls` (CWE-400)

## Technique

The model's output as an attack surface downstream: raw HTML/markdown from the model rendered by the web UI (reflected_unescaped oracle applied to an LLM sink), model-suggested code executed by the app, model-placed URLs fetched by prefetchers (SSRF via model), and nested-agent fan-out that burns tokens unboundedly (LLM10).

## Proof design (why it is falsifiable)

Sink-shaped oracles: the exact XSS token raw-in-output, executed:true with output evidence, prefetcher log hitting the collaborator URL, and json_differs on usage.model_calls between amplified and normal queries.

## Bypass variants / escalation ("think more beats level")

- Output feeding shell/db sinks beyond HTML (same oracle, different sink)
- Latent injection: model output stored, rendered to OTHER users
- Cost amplification via recursive self-calls vs parallel fan-out
- Package-hallucination (garak probe): model suggests installable names
- Denial-of-wallet framing for LLM10 findings (cost curve as evidence)

## Sources (copied & rewritten into our proof-first DSL)

- OWASP LLM Top 10 2025 — LLM05 improper output handling, LLM10 unbounded consumption
- NVIDIA/garak — xss, packagehallucination probes
- promptfoo red-team plugins — ssrf-via-model

## False positives to rule out

Escaped output that only LOOKS executable in the raw body — the reflected_unescaped oracle (raw present, escaped absent) is the discriminator.
