# AI System Prompt Leakage & Exfiltration (LLM07/LLM02)

**CWE-200** · 4 skill(s) · folder `categories/ai_system_prompt_exfil/`

## Skills in this shelf

- `ai/System prompt direct extraction` (CWE-200)
- `ai/Markdown image exfil channel` (CWE-200)
- `ai/RAG planted document exfil` (CWE-200)
- `ai/Cross-session leakage` (CWE-200)

## Technique

Making the model reveal operator configuration or carry data out of its context: repeat-everything extraction, markdown-image exfil channels (renderer fetches attacker URL with the secret embedded), planted RAG documents that order the model to echo canaries, and cross-session memory leakage. Every skill plants a canary so the leak is provable, not confabulated.

## Proof design (why it is falsifiable)

Canary-based: the planted string (prompt_canary) appearing in output is the leak; baselines/clean-corpus twins show it is not ambient. The image-exfil skill pins the exact exfil URL shape.

## Bypass variants / escalation ("think more beats level")

- Encoding-canary variants (base64/rot13 the leak to defeat output filters)
- Partial extraction ladders (enumerate config keys one per turn)
- Exfil via link/QR/code-fence renderers instead of images
- Cross-session via shared retrieval vs shared chat memory (different fix)
- Teams/Slack-bot preview unfurlers as the fetching renderer

## Sources (copied & rewritten into our proof-first DSL)

- promptfoo red-team plugins — prompt-extraction, cross-session-leak
- OWASP LLM Top 10 2025 — LLM07 system prompt leakage, LLM02 sensitive info
- Simon Willison — exfiltration-attacks writeup collection

## False positives to rule out

Model paraphrasing or hallucinating a canary-like string — the exact-canvas regex on the planted token kills confabulation.
