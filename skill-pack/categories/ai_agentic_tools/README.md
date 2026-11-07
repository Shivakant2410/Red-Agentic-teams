# AI Agentic Tool Abuse (ASI01-ASI10 · MCP)

**CWE-269** · 7 skill(s) · folder `categories/ai_agentic_tools/`

## Skills in this shelf

- `ai/MCP tool poisoning description injection` (CWE-1427)
- `ai/MCP rug pull hash delta` (CWE-345)
- `ai/Excessive agency irreversible action` (CWE-269)
- `ai/Memory poisoning persistence` (CWE-1427)
- `ai/Inter-agent message injection` (CWE-1427)
- `ai/Goal hijack untrusted content` (CWE-348)
- `ai/Rogue sub-agent spawn` (CWE-269)

## Technique

Agent-action attacks beyond what the model says: MCP tool descriptions carrying adversarial directives (tool poisoning), silent post-approval tool mutation (rug pull), irreversible actions without confirmation gates (excessive agency), poisoned persistent memory (ASI06), injected agent-to-agent messages (ASI07), goal replacement via untrusted content (ASI01) and unapproved sub-agent spawning (ASI10).

## Proof design (why it is falsifiable)

Action-shaped oracles: tool-call JSON with attacker arguments, a json_differs between the two tools-list fetches (rug pull = silent metadata mutation, machine-checkable), confirmation-prompt absence on destructive calls, and cross-session persistence of planted memory.

## Bypass variants / escalation ("think more beats level")

- Allow-list bypass via lookalike tool names/parameters
- Poisoned MCP resources/prompts (not just tool descriptions)
- Confirmation fatigue (prompt appears but auto-accepts)
- Cascading failure via one poisoned agent feeding a downstream fleet (ASI08)
- Human-agent trust exploitation (ASI09): urgent-styled agent messages

## Sources (copied & rewritten into our proof-first DSL)

- OWASP Top 10 for Agentic Applications 2026 — ASI01-ASI10
- Invariant Labs MCP research — tool poisoning & rug pull (2025)
- OWASP LLM Top 10 2025 — LLM06 excessive agency
- microsoft/PyRIT — agentic target orchestration

## False positives to rule out

Simulated tool calls that the harness never executes — confirm the agent runtime actually dispatches before rating impact.
