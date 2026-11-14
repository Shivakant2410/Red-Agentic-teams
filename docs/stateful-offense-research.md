# Stateful offense: what the field actually has, and what we build instead

Research pass (2026-11-14). Primary source read end-to-end: "What Makes a Good
LLM Agent for Real-world Penetration Testing?" (arXiv:2602.17622, 200 failed
traces across 5 systems). Secondary: PentestGPT (Deng et al., cited 543+),
AutoPT's Pentesting State Machine, Naptime/Big Sleep (cited in the survey as
the real-world counterexample), our own `tools/logic.py` one-shot insight.

## What exists (mechanisms, not marketing)

| System | Mechanism | Measured result |
|---|---|---|
| PentestGPT | Human-in-loop copilot; Penetration Testing Tree; prompt knowledge | 5–7/13 HTB; no difficulty metrics, manual pruning |
| AutoPT | Pentesting State Machine — enforces PHASE transitions | Enforces phases; "does not assess path complexity" |
| PentestAgent | Multi-agent + RAG + function calls | Best XBOW baseline: 61% |
| VulnBot | Multi-agent tri-phase | 9/13 PentestGPT-Ben |
| TermiAgent | Memory tree (PMT) | Context management; no decision guidance |
| Cochise | AD-specialist (Kerberoast/relay/BloodHound) | GOAD leader 2/5, but 34% XBOW, 4/13 general |
| Naptime/Big Sleep | Hypothesis → fuzz harness → verified crash | Real CVEs; needs per-target harness engineering |

## The survey's hard numbers

- Failures split **Type A (42%)** — missing tools/wrong syntax/parsing — from
  **Type B (58%)** — context forgetting 18%, premature commitment 16%,
  exploration–exploitation imbalance 12%, **multi-step chain failures 12%**.
  Type A yields to engineering; Type B "persists regardless of tooling."
- **Architecture advantages decay**: performance gaps across systems compress
  by more than half when the backbone goes GPT-4o → GPT-5. Per-role prompts,
  tool belts, and memory trees are "workarounds for 2023-era model
  limitations."
- Injecting **task-difficulty estimation** cut Type B failures 58% → 27%.
- "Agents complete individual attack stages successfully but **fail to
  integrate them into coherent attack chains**" — credentials found in recon
  are forgotten by exploitation time.
- Keep **state external to context**; instruction accuracy degrades 90% → 61%
  between 40% and 80% context load; failure modes: ignoring earlier context
  42%, hallucinated tool output 31%.
- Benchmarks are contaminated (retired HTB walkthroughs are public) and
  single-path; "real engagements add business logic" that none of them test.

## The brutal read — what is generic in the field

1. **Role-play is not architecture.** Recon/exploit/verify specialists with
   per-role prompts is the default shape of every 2024–2026 system, and the
   survey proves that shape's advantage is transient. We have an orchestrator
   of exactly this shape (D-phase); it is not where durable value lives.
2. **Nobody has a falsifiable multi-step proof.** Systems chain tool calls,
   then self-grade the narrative. Business-logic bugs are one-shot — a coupon
   redeemed twice cannot be "reproduced" k-of-n — so the standard proof
   pipeline is structurally wrong for the class that matters most. Our
   `verify_workflow_abuse` (ordered attack sequence vs ordered control
   sequence, single run, independent replay) is the right primitive; what is
   missing is the ORGAN THAT MINTS such proofs automatically.
3. **State machines exist but enforce phases, not attack-state.** PSM
   says "you are in exploitation now." It never says "you are HOLDING a
   service token, therefore this gate is the next read." Phase ≠ possession.
4. **Agents carry secrets in the prompt.** Harvested credentials flow into
   model context in every surveyed design — an OPSEC hole and a
   prompt-injection surface (the survey's adversarial-environment section
   shows agents have no meta-awareness of honeypot poisoning). Nobody treats
   "the model must never hold the material" as a design constraint.
5. **Self-graded offense.** Most agent papers grade findings with the same
   model that proposed them. A pending→confirmed pipeline with an independent
   replay remains the exception (Naptime's verified-crash bar is the spirit;
   k-of-n + negative control is our letter).

## What we steal (and where it already lives here)

- **Difficulty-weighted search control** (TDA/EGATS): our bet rank
  `impact × signal strength / cost` is the same idea at hypothesis granularity;
  what to add later: per-bet horizon estimate and evidence-based pruning with
  k_min=3 attempts (our kill conditions already do this ad hoc).
- **Branch reactivation on new material**: the survey credits "credential
  propagation reactivating pruned branches" for multi-step gains. Our R6
  bearer-pivot is that mechanism's special case (a harvested token re-opens
  every gate). Generalization later: killed bets get re-queued when
  `state.tokens` / `state.principals` change.
- **State external to context**: `AttackState` already is that store. We go
  further than the survey asks: the LLM digest is credential-FREE (counts and
  URLs, never values) and proposals reference harvested material by position
  (`@harvested:0`), resolved by the executor — the model proposes what to
  test and never holds the material.

## What we build (this phase)

1. **The multi-step state organ (deterministic).** The Brain observes
   workflow-shaped mutations (POST + success markers on cart/coupon/order/
   payment/transfer surfaces) and state-bearing reads (GET whose body speaks
   total/price/balance), and mints **workflow-chain bets**: repeat the
   mutation, diff the state read. The executor reuses
   `verify_workflow_abuse`: attack sequence [mutate, read, mutate, read] with
   invariant "second read differs from first"; control sequence [mutate, read,
   read] with a second principal (fresh identity) — if the control state also
   flaps, the bet is falsified. One-shot semantics become first-class signals,
   not a specialist's hobby.
2. **The model enters one queue (the discipline, not the driver).**
   `redteam/llm/planner.py` builds a factual, credential-free digest of the
   AttackState, asks for 1–3 proposals in the exact `admit_hypothesis` schema,
   and admits them — ranked, falsifiable, kill-able, proof-pipeline-gated —
   or records the rejection reason. Garbage is rejected, not fixed up. The
   deterministic queue drains first; the model spends what is left of the
   budget. It is an amplifier, exactly like reflection.py, and it cannot
   invent findings: it can only propose tests.

## Evaluation honesty

This phase is proven the way the survey says nobody evaluates: a target no
template covers (workflow lab — coupon replay, CWE-840), the chain visible in
the run's hypothesis list (`workflow-chain*`), the LLM path exercised by a
deterministic offline fake (garbage rejected with reason, valid proposal
admitted and executed through the same pipeline), and the full suite +
live-fire over all targets as regression. Numbers in this doc are quoted from
arXiv:2602.17622 as fetched 2026-11-14; we have not rerun their benchmarks,
and our labs are fixtures, not real engagements.
