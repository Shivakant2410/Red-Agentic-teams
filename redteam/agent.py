"""The red-team agent: an OpenAI-style tool-use loop over OpenRouter free models.

We own the loop explicitly (no hidden control flow) so every tool call passes through
our scope / firewall / audit / approval path. The model backend is OpenRouter, which
rotates across free models by availability (see llm/openrouter.py).
"""

from __future__ import annotations

import json
import threading

from .config import Engagement
from .llm.openrouter import OpenRouterClient, NoModelsAvailable, to_openai_tools
from .llm.routing import PLAN
from .runtime import Halt, RepetitionGuard, compact_messages, looks_failed
from .tools import ToolContext, Tool

# A parallel exploit swarm (orchestrator.py) can have several RedTeamAgent instances in
# different threads all writing the SAME RunManifest object/file concurrently. RunManifest
# itself is a plain dataclass with nowhere natural to put a lock, so this one module-level
# lock serializes every _update_manifest() call across all agent instances in this process —
# cheap (manifest writes are infrequent, once per turn) and enough to stop interleaved
# setattr calls and concurrent file writes from corrupting it.
_manifest_lock = threading.Lock()

SYSTEM_PROMPT = """You are an assistant operating INSIDE an authorized web-application \
and API penetration test. You act only within the signed Rules of Engagement.

Engagement:
- Name: {name}
- Client: {client}
- Authorized by: {authorized_by} (authorization ref: {ticket})
- Window: {starts} to {ends}
- In-scope hosts: {allowed_hosts}
- Out-of-scope (never touch): {excluded_hosts}

Environment you operate in:
- kali_exec runs shell commands in a Kali Linux sandbox (nmap, ffuf, sqlmap, nikto,
  gobuster, curl, etc.). The sandbox firewall only lets you reach in-scope targets;
  off-scope hosts are unreachable, so don't waste steps trying.
- browser_* tools drive a headless browser for anything that needs a real DOM/JS.
- record_finding stores evidenced findings. request_approval asks a human before any
  destructive or otherwise sensitive action.

Hard rules:
1. Stay in scope. If a tool blocks or refuses something, do not try to work around it —
   note it and move on.
2. No denial-of-service, data destruction, or mass/automated exploitation. Identify and
   evidence vulnerabilities with safe, minimal proof-of-concept.
3. For destructive/intrusive actions, call request_approval first and stop if DENIED.
4. Respect the request budget; when told it's exhausted, stop and summarize.
5. Record findings only with concrete evidence. Rate confidence honestly.
6. BIAS TOWARD PROOF. The moment you suspect a vulnerability, immediately call the tool
   that PROVES it — confirm_finding (injection/generic), test_access_control, or test_idor
   (after `authenticate`). Do not spend your turns only browsing: exploration without a
   CONFIRMED finding scores nothing. Aim to confirm something within your first several
   steps, then chain from it.

YOU ARE A RED TEAM OPERATOR, NOT A SCANNER. If an objective is given, the engagement is
judged by whether you REACHED IT — not by how many vulnerabilities you listed. So:
- Think in terms of what you HOLD and what it UNLOCKS. Record it with record_access, and
  keep that map current: your next move is chosen from it.
- A vulnerability matters insofar as it yields a credential, a session, a host, or data
  that moves you toward the objective. One that leads nowhere is a side note to report,
  not a win.
- Chain relentlessly: foothold -> credentials -> discovery -> escalation -> lateral
  movement -> the objective. Use claim_objective (with evidence) when a criterion is met.
- Persistence and defense evasion are OFF unless the RoE explicitly authorizes them, and
  then only with approval.

Work methodically: map the surface, get a foothold, then push along the kill chain toward
the objective. Explain your reasoning briefly as you go. When done, summarize the
compromise path you achieved (or where you were blocked) and what you proved."""


class RedTeamAgent:
    def __init__(self, engagement: Engagement, tools: dict[str, Tool], ctx: ToolContext,
                 client: OpenRouterClient, max_steps: int = 40, graph=None, attack_tree=None,
                 memory=None, system_addon: str = "", role: str = PLAN):
        self._eng = engagement
        self._tools = tools
        self._ctx = ctx
        self._client = client
        self._max_steps = max_steps
        self._graph = graph
        self._attack_tree = attack_tree
        self._memory = memory
        self._system_addon = system_addon   # specialist-specific instructions (multi-agent)
        self._role = role                   # model role for this agent (recon=cheap, exploit=strong)
        self._budget = None      # optional BudgetTracker
        self._manifest = None    # optional (RunManifest, path) tuple

    def with_runtime(self, budget=None, manifest=None, manifest_path=None):
        """Attach a BudgetTracker and/or a RunManifest for autonomous runs."""
        self._budget = budget
        if manifest is not None and manifest_path is not None:
            self._manifest = (manifest, manifest_path)
        return self

    def _system(self) -> str:
        e = self._eng
        base = SYSTEM_PROMPT.format(
            name=e.name, client=e.client, authorized_by=e.authorized_by, ticket=e.ticket,
            starts=e.starts, ends=e.ends,
            allowed_hosts=", ".join(e.allowed_hosts),
            excluded_hosts=", ".join(e.excluded_hosts) or "(none)",
        )
        if self._system_addon:
            base += "\n\nYOUR ROLE IN THE TEAM:\n" + self._system_addon
        return base

    def run(self, objective: str, on_text=None) -> str:
        messages: list[dict] = [
            {"role": "system", "content": self._system()},
            {"role": "user", "content": objective},
        ]
        # Recall distilled lessons from past engagements and seed them up front, so the
        # agent starts each run with accumulated tradecraft rather than from scratch.
        if self._memory is not None:
            brief = self._memory.briefing(query=objective + " " + " ".join(self._eng.allowed_hosts))
            if brief:
                messages.append({"role": "user", "content": brief})
                self._ctx.audit.record("memory.recalled", chars=len(brief))
        # Proven skills: executable proofs the agent should REUSE rather than re-derive.
        if getattr(self._ctx, "skills", None) is not None:
            sbrief = self._ctx.skills.briefing(query=objective)
            if sbrief:
                messages.append({"role": "user", "content": sbrief})
                self._ctx.audit.record("skills.recalled", chars=len(sbrief))

        openai_tools = to_openai_tools([t.schema() for t in self._tools.values()])
        self._ctx.audit.record("agent.start", objective=objective)

        guard = RepetitionGuard()
        last_progress = 0          # (graph_nodes + findings) snapshot for stall detection
        stall_turns = 0
        stall_nudges_given = 0     # how many times the stall nudge below has fired
        nudges = 0                 # times we've refused an early "I'm done"

        final_text = ""
        for step in range(self._max_steps):
            # Autonomy guardrails: budget / deadline / kill switch, then keep transcript bounded.
            if self._budget is not None:
                try:
                    self._budget.check()
                except Halt as halt:
                    self._ctx.audit.record("agent.halt", reason=halt.reason, step=step)
                    self._update_manifest(status="halted", steps=step, halt_reason=halt.reason)
                    return final_text or f"Halted: {halt.reason}"
            messages = compact_messages(messages)

            try:
                result = self._client.chat(messages, tools=openai_tools, role=self._role)
            except NoModelsAvailable as exc:
                self._ctx.audit.record("agent.no_models", error=str(exc))
                self._update_manifest(status="error", steps=step, halt_reason=str(exc))
                return f"Could not get a model response: {exc}"

            if self._budget is not None:
                self._budget.add_usage(result.usage)
            self._update_manifest(status="running", steps=step,
                                  findings=len(self._ctx.findings.all()),
                                  tokens=self._budget.tokens if self._budget else 0)

            msg = result.message
            self._ctx.audit.record("agent.turn", step=step, model=result.model,
                                   finish_reason=result.finish_reason)

            content = msg.get("content") or ""
            if content:
                final_text = content
                if on_text:
                    on_text(f"[{result.model}] {content}")

            tool_calls = msg.get("tool_calls") or []
            # Append the assistant message (it carries tool_calls for the next turn), but
            # normalize a null `content` first: models often return content=None when they
            # stop, and replaying that verbatim makes the next request invalid (HTTP 400 on
            # every model). Harmless while we broke immediately; fatal once we continue.
            msg = dict(msg)
            if msg.get("content") is None:
                msg["content"] = ""
            messages.append(msg)

            if not tool_calls:
                # Don't let it quit while the objective is unmet and budget remains. A weak
                # model declares victory early; the objective is the contract, so push back.
                objective = getattr(self._ctx, "objective", None)
                access = getattr(self._ctx, "access", None)
                if objective is not None:
                    objective.autoevaluate(access)
                if (objective is not None and not objective.achieved
                        and nudges < 3 and step < self._max_steps - 2):
                    nudges += 1
                    done, total = objective.progress()
                    outstanding = ", ".join(c.description for c in objective.outstanding())
                    self._ctx.audit.record("agent.continue_nudge", step=step, nudge=nudges)
                    messages.append({"role": "user", "content":
                        f"[NOT DONE] The objective is NOT achieved ({done}/{total}). "
                        f"Outstanding: {outstanding}. You still have budget and steps. Do not "
                        f"stop — take the next concrete action that advances the objective "
                        f"(harvest secrets from what you already retrieved, try a credential, "
                        f"prove a privilege boundary, or reach the target data)."})
                    continue
                self._ctx.audit.record("agent.finish", step=step)
                self._update_manifest(status="completed", steps=step,
                                      findings=len(self._ctx.findings.all()))
                break

            for tc in tool_calls:
                fn = tc.get("function", {})
                name = fn.get("name", "")
                raw_args = fn.get("arguments", "{}")
                try:
                    args = json.loads(raw_args) if isinstance(raw_args, str) else (raw_args or {})
                except json.JSONDecodeError:
                    args, tool_out = {}, f"ERROR: could not parse arguments for {name}"
                    messages.append({"role": "tool", "tool_call_id": tc.get("id"), "content": tool_out})
                    continue
                # Repetition guard: block identical calls that keep failing.
                signature = f"{name}:" + json.dumps(args, sort_keys=True, default=str)
                blocked = guard.check_before(signature)
                if blocked is not None:
                    self._ctx.audit.record("agent.repeat_blocked", tool=name)
                    messages.append({"role": "tool", "tool_call_id": tc.get("id"),
                                     "name": name, "content": blocked})
                    continue
                tool_out = self._dispatch(name, args)
                guard.record_result(signature, looks_failed(tool_out))
                messages.append({"role": "tool", "tool_call_id": tc.get("id"),
                                 "name": name, "content": tool_out})

            # Feed current state + the adversarial plan back to the model so it works from
            # a constrained attack tree (fewer hallucinated/circular actions) and presses
            # confirmed footholds into their chained follow-ups instead of drifting.
            briefing_parts = []
            # Objective first: everything is judged by distance to the crown jewel.
            objective = getattr(self._ctx, "objective", None)
            access = getattr(self._ctx, "access", None)
            killchain = getattr(self._ctx, "killchain", None)
            if objective is not None:
                # Credit progress from demonstrated access before briefing on it.
                for cid in objective.autoevaluate(access):
                    self._ctx.audit.record("objective.auto_met", criterion_id=cid)
                briefing_parts.append(objective.briefing())
            if access is not None:
                briefing_parts.append(access.briefing(objective))
            if killchain is not None:
                briefing_parts.append(killchain.briefing(access, objective))
            if self._graph is not None:
                from .planner import state_briefing
                briefing_parts.append(state_briefing(self._graph))
            if self._attack_tree is not None:
                self._attack_tree.sync(graph=self._graph, findings=self._ctx.findings.all())
                briefing_parts.append(self._attack_tree.briefing())
            if briefing_parts:
                messages.append({"role": "user", "content": "\n\n".join(briefing_parts)})

            # Stall detection: if several turns pass with no new knowledge or findings, nudge
            # the agent to change strategy instead of grinding the same unproductive path.
            graph_nodes = len(self._graph.nodes()) if self._graph is not None else 0
            progress = graph_nodes + len(self._ctx.findings.all())
            if progress > last_progress:
                last_progress, stall_turns = progress, 0
            else:
                stall_turns += 1
            if stall_turns >= 4:
                stall_turns = 0
                stall_nudges_given += 1
                # One or two in-context nudges are worth trying (a model can genuinely
                # change tack). Beyond that, more nudges in the SAME exhausted context
                # just grind the remaining budget — better to end this specialist's turn
                # now and let the orchestrator hand off to a different specialist (e.g.
                # ACCESS or LOGIC) with a fresh context, than keep talking to a dead end.
                if stall_nudges_given > 2:
                    self._ctx.audit.record("agent.stalled_out", step=step,
                                           stall_nudges=stall_nudges_given)
                    self._update_manifest(status="completed", steps=step,
                                          findings=len(self._ctx.findings.all()))
                    return final_text or "[stalled — no progress after repeated nudges; ending this specialist's turn]"
                messages.append({"role": "user", "content":
                    "[NO PROGRESS] Several turns produced no new endpoints or findings. "
                    "Change strategy: pick a different endpoint or vulnerability class from "
                    "the plan, or move on. Do not repeat what has already failed."})
        else:
            self._ctx.audit.record("agent.max_steps", steps=self._max_steps)
            self._update_manifest(status="completed", steps=self._max_steps,
                                  findings=len(self._ctx.findings.all()))

        return final_text

    def _update_manifest(self, **fields) -> None:
        if self._manifest is None:
            return
        manifest, path = self._manifest
        with _manifest_lock:
            for k, v in fields.items():
                setattr(manifest, k, v)
            try:
                manifest.save(path)
            except Exception:
                pass

    def _dispatch(self, name: str, tool_input: dict) -> str:
        tool = self._tools.get(name)
        if tool is None:
            return f"ERROR: unknown tool {name!r}"
        try:
            return tool.run(self._ctx, **tool_input)
        except TypeError as exc:
            return f"ERROR: bad arguments for {name}: {exc}"
        except Exception as exc:  # never let a tool crash the loop
            self._ctx.audit.record("tool.exception", tool=name, error=str(exc))
            return f"ERROR while running {name}: {exc}"
