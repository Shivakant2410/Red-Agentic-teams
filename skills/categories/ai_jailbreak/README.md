# AI Safety-Boundary Bypass (Jailbreaks)

**CWE-1427** · 5 skill(s) · folder `categories/ai_jailbreak/`

## Skills in this shelf

- `ai/Roleplay persona pair bypass` (CWE-1427)
- `ai/Encoding obfuscation bypass` (CWE-1427)
- `ai/Refusal suppression ladder` (CWE-1427)
- `ai/Known-bad signature trigger` (CWE-1427)
- `ai/Token smuggling compression` (CWE-1427)

## Technique

Defeating refusal training one mechanism at a time: persona roleplay (DAN lineage), base64/rot13 encoding wrappers, refusal-suppression clause stacks, known-bad signature strings (garak knownbadsignatures), and zlib+base64 token smuggling. Each skill isolates ONE mechanism and pairs it with the direct-ask twin that gets refused.

## Proof design (why it is falsifiable)

Pair differential: jailbreak-wrapped ask complies (marker present), the identical bare ask is refused (marker absent) — the wrapper is proven to be the bypass, not the topic.

## Bypass variants / escalation ("think more beats level")

- Multi-turn softening ladders that never contain a single explicit ask
- Persona + encoding composites (stack two bypasses)
- Safety-filter bypass at the APP layer vs the MODEL layer (test both)
- Token-level attacks (glitch tokens) as a model-specific variant
- Refusal-vocabulary suppression (condition pins absence of 'I cannot')

## Sources (copied & rewritten into our proof-first DSL)

- NVIDIA/garak — dan.Dan_11_0, encoding, knownbadsignatures probes
- microsoft/PyRIT — converters (base64, compression)
- OWASP GenAI Red Teaming Manual v1.0 — jailbreak campaign structure

## False positives to rule out

Topic-adjacent compliance that a plain ask also gets — the plain-ask twin condition is what makes the pair a proof.
