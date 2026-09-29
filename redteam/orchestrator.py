"""Multi-agent orchestrator — the "army of ants".

One agent with all tools and one giant context is the bottleneck. This splits the work
across focused specialist agents, each with a small tool set, a focused prompt, and its
own model tier, all sharing ONE brain (knowledge graph), ONE attack tree, ONE memory, and
ONE budget:

  - Recon specialist  — maps the attack surface (breadth). Runs on a cheaper model.
  - Exploit specialist — probes and CONFIRMS/chains vulnerabilities (depth). Runs on the
    strongest available model.

The orchestrator is deterministic (a disciplined commander, not another LLM to go astray):
it runs recon to populate the graph, then runs exploit rounds while the attack tree still
has untested, high-value work and the shared budget allows. Specialists share state, so
what recon finds, exploit attacks; what exploit confirms, memory learns.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .agent import RedTeamAgent
from .config import Engagement
from .llm.openrouter import OpenRouterClient
from .llm.routing import PARSE, PLAN
from .tools import ToolContext, Tool


@dataclass
class SpecialistProfile:
    name: str
    addon: str                       # role-specific system instructions
    tool_names: list[str]            # subset of the registry this specialist may use
    role: str = PLAN                 # model tier (cheap for recon, strong for exploit)
    max_steps: int = 20


RECON = SpecialistProfile(
    name="recon",
    addon=("You are the RECON specialist. Map the attack surface only: browse the app, "
           "discover endpoints, parameters, and technologies, and let them register in the "
           "knowledge graph. Do NOT try to exploit or confirm vulnerabilities — that is the "
           "exploit specialist's job. Be broad and fast."),
    tool_names=["browser_navigate", "browser_content", "browser_click", "kali_exec"],
    role=PARSE,          # breadth work -> cheaper model
    max_steps=15,
)

EXPLOIT = SpecialistProfile(
    name="exploit",
    addon=("You are the EXPLOIT specialist. The surface is already mapped in the knowledge "
           "graph and the attack tree lists prioritized untested checks. For each, PROVE the "
           "vulnerability with a reproducing check (confirm_finding / verify_vulnerability), "
           "authenticate when needed, and chain confirmed footholds. Bias hard toward "
           "confirming findings; do not re-map the surface."),
    tool_names=["confirm_finding", "verify_vulnerability", "authenticate", "kali_exec",
                "browser_navigate", "browser_content", "browser_fill"],
    role=PLAN,           # depth/reasoning work -> strongest model
    max_steps=40,
)


class Orchestrator:
    def __init__(self, engagement: Engagement, tools: dict[str, Tool], ctx: ToolContext,
                 client: OpenRouterClient, graph=None, attack_tree=None, memory=None,
                 max_exploit_rounds: int = 2):
        self._eng = engagement
        self._tools = tools
        self._ctx = ctx
        self._client = client
        self._graph = graph
        self._attack_tree = attack_tree
        self._memory = memory
        self._max_exploit_rounds = max_exploit_rounds
        self._budget = None
        self._manifest = None

    def with_runtime(self, budget=None, manifest=None, manifest_path=None):
        self._budget = budget
        if manifest is not None and manifest_path is not None:
            self._manifest = (manifest, manifest_path)
        return self

    def _make_specialist(self, profile: SpecialistProfile) -> RedTeamAgent:
        # Give the specialist only its allowed tools that actually exist in the registry.
        subset = {n: self._tools[n] for n in profile.tool_names if n in self._tools}
        agent = RedTeamAgent(self._eng, subset, self._ctx, self._client,
                             max_steps=profile.max_steps, graph=self._graph,
                             attack_tree=self._attack_tree, memory=self._memory,
                             system_addon=profile.addon, role=profile.role)
        if self._budget is not None:
            mpath = self._manifest[1] if self._manifest else None
            manifest = self._manifest[0] if self._manifest else None
            agent.with_runtime(budget=self._budget, manifest=manifest, manifest_path=mpath)
        return agent

    def _untested_remaining(self) -> int:
        if self._attack_tree is not None:
            return len(self._attack_tree.actionable(limit=999))
        if self._graph is not None:
            return len(self._graph.untested())
        return 1

    def run(self, objective: str, on_text=None) -> str:
        self._ctx.audit.record("orchestrator.start", objective=objective)

        # Phase 1 — recon (breadth, cheap model).
        self._ctx.audit.record("orchestrator.phase", phase="recon")
        recon = self._make_specialist(RECON)
        recon.run(f"{objective}\n\nThis run: RECON only — map the attack surface.", on_text=on_text)

        # Phase 2 — exploit rounds (depth, strong model) while there is untested work + budget.
        summary = ""
        for rnd in range(self._max_exploit_rounds):
            if self._budget is not None:
                try:
                    self._budget.check()
                except Exception as exc:   # Halt
                    self._ctx.audit.record("orchestrator.halt", reason=str(exc))
                    break
            if self._untested_remaining() == 0 and rnd > 0:
                break
            self._ctx.audit.record("orchestrator.phase", phase="exploit", round=rnd)
            exploit = self._make_specialist(EXPLOIT)
            summary = exploit.run(
                f"{objective}\n\nThis run: EXPLOIT round {rnd + 1} — confirm and chain "
                f"vulnerabilities from the mapped surface.", on_text=on_text) or summary

        self._ctx.audit.record("orchestrator.finish",
                               findings=len(self._ctx.findings.all()))
        return summary
