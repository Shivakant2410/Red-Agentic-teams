# AI Prompt Injection (LLM01/ASI01)

**CWE-1427** · 6 skill(s) · folder `categories/ai_prompt_injection/`

## Skills in this shelf

- `ai/Direct instruction override flips verdict` (CWE-1427)
- `ai/Delimiter confusion crosses role boundary` (CWE-1427)
- `ai/Indirect injection via untrusted content` (CWE-1427)
- `ai/Crescendo multi-turn escalation` (CWE-1427)
- `ai/Tool-call hijack via injected directive` (CWE-1427)
- `ai/Payload splitting assembly bypass` (CWE-1427)

## Technique

Attacker-controlled text (direct turns, fake role delimiters, retrieved documents, split fragments) steers an LLM app away from operator intent — up to and including hijacking the TOOL CALLS an agentic app emits. One skill per injection vector: direct override, delimiter/role confusion, indirect via untrusted content (the lethal trifecta core), multi-turn crescendo, tool-call hijack, payload splitting/assembly.

## Proof design (why it is falsifiable)

Deterministic differentials: the injected variant emits the canary/verdict/tool-call the clean variant does not. Baselines pin that the marker is attack-caused, not ambient model chatter — the same falsifiability contract as every HTTP skill, with llm_mock fixtures standing in for the model.

## Bypass variants / escalation ("think more beats level")

- System-prompt extraction variants (see ai_system_prompt_exfil)
- Few-shot injection via prior-turn fabrication in the messages array
- Language-switch and translation-pipeline injection
- Format-injection through structured-output schemas (JSON mode confusion)
- Second-order injection: stored document poisons every future summary

## Sources (copied & rewritten into our proof-first DSL)

- NVIDIA/garak — promptinject probe family
- microsoft/PyRIT — multi-turn attack strategies
- OWASP LLM Top 10 2025 — LLM01 prompt injection
- Simon Willison — the lethal trifecta (2025-06-16)

## False positives to rule out

Model echoing benign text that merely CONTAINS the marker without obeying it — baseline-absent conditions kill this.
