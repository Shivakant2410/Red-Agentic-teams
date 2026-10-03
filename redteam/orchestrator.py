"""Multi-agent orchestrator — the "army of ants".

One agent with all tools and one giant context is the bottleneck. This splits the work
across focused specialist agents, each with a small tool set, a focused prompt, and its
own model tier, all sharing ONE brain (knowledge graph), ONE attack tree, ONE memory, and
ONE budget:

  - Recon specialist   — maps the attack surface (breadth). Runs on a cheaper model.
  - Exploit specialist — probes and PROVES/chains vulnerabilities (depth). Runs on the
    strongest available model.
  - Verify specialist  — independently re-checks every pending finding before anything
    may count (see tools/independent_verify.py). Runs in a FRESH context, never the
    context that proposed the finding.
  - Access specialist  — once a confirmed foothold exists, PRESSES it: harvest secrets,
    try credentials, prove privilege boundaries. Mechanical, procedural work, separated
    out so the exploit specialist's context stays focused on proving new bugs instead of
    also reasoning about what a foothold unlocks.
  - Logic specialist   — hunts BUSINESS-LOGIC bugs (price tampering, race conditions,
    skipped workflow steps) on endpoints that look workflow-shaped. This is the class of
    bug pattern-matched vuln scanning misses entirely: it requires reasoning about the
    app's domain, not a payload library, and its proof (tools/logic.py) is structurally
    different (ordered multi-step sequences, single-run + control) from the single/
    differential-request proofs everything else uses.

The orchestrator is deterministic (a disciplined commander, not another LLM to go astray):
recon populates the graph; then each round is EXPLOIT -> VERIFY -> (ACCESS -> VERIFY)* ->
LOGIC -> VERIFY, where the ACCESS loop runs only as long as the KILL CHAIN says there is a
foothold worth pressing, and the LOGIC round only runs when recon turned up endpoints that
look workflow-shaped (cart/checkout/coupon/payment/...) — no point spending a round hunting
business logic on an app that's just a static content site. Specialists share state, so
what recon finds, exploit attacks; what exploit confirms, access presses; what any
specialist proves, memory learns.

EXPLOIT itself is a SWARM, not one thread of reasoning: AttackTree.actionable() is a
prioritized (technique, target) worklist, and when it's non-empty each round fans out
up to max_swarm_workers separate EXPLOIT contexts running CONCURRENTLY (ThreadPoolExecutor),
each pulling and atomically claiming the next untried pair via AttackTree.claim() so no
two workers burn turns on the same hypothesis. Findings land in the shared, now
thread-safe FindingStore exactly as a single EXPLOIT would write them; VERIFY still runs
once per round over everything the whole swarm left pending. Falls back to a single
EXPLOIT context (the pre-swarm behavior) whenever there's nothing actionable yet (e.g.
right after recon, before the attack tree has anything seeded) — this is a strict
addition, not a replacement of the serial path.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field

from .agent import RedTeamAgent
from .attack_tree import FAILED, TECHNIQUES, TODO
from .config import Engagement
from .killchain import (CREDENTIAL_ACCESS, DISCOVERY, LATERAL_MOVEMENT,
                        PRIVILEGE_ESCALATION)
from .llm.openrouter import OpenRouterClient
from .llm.routing import PARSE, PLAN
from .tools import ToolContext, Tool

# Kill-chain stages that mean "there is a foothold worth pressing further" — if
# KillChain.recommend() names any of these, an ACCESS round (not another EXPLOIT round)
# is the next useful move.
_ACCESS_STAGES = {CREDENTIAL_ACCESS, PRIVILEGE_ESCALATION, LATERAL_MOVEMENT, DISCOVERY}

# Endpoint URL/key fragments that suggest a multi-step, stateful workflow — the shape of
# thing business-logic bugs live in. Heuristic, not exhaustive: a miss here just means the
# LOGIC round doesn't run (cheap to skip), a false match just means it runs and finds
# nothing (cheap to waste a round on) — asymmetric cost, so a loose heuristic is fine.
_WORKFLOW_HINTS = ("cart", "checkout", "coupon", "voucher", "discount", "order", "payment",
                   "pay", "redeem", "transfer", "withdraw", "booking", "reserve", "apply",
                   "submit", "vote", "like", "quantity", "balance", "wallet")


def _looks_workflow_shaped(graph) -> bool:
    if graph is None:
        return False
    from .knowledge import ENDPOINT
    return any(hint in ep.key.lower() for ep in graph.nodes(ENDPOINT) for hint in _WORKFLOW_HINTS)


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
           "exploit specialist's job. You MAY authenticate (log in as a basic/seeded user) "
           "purely to get past a login wall and see what's behind it — logging in is "
           "mapping, not exploiting. If the app has a multi-step login (e.g. submit a "
           "username, then a password at a second URL), use authenticate's "
           "second_url_template rather than guessing follow-up URLs by hand. Be broad and "
           "fast."),
    tool_names=["browser_navigate", "browser_content", "browser_click", "kali_exec", "authenticate"],
    role=PARSE,          # breadth work -> cheaper model
    max_steps=15,
)

EXPLOIT = SpecialistProfile(
    name="exploit",
    addon=("You are the EXPLOIT specialist. The surface is already mapped in the knowledge "
           "graph and the attack tree lists prioritized untested checks. For each, PROVE the "
           "vulnerability with a reproducing check (confirm_finding / verify_vulnerability), "
           "authenticate when needed, and chain confirmed footholds. Bias hard toward "
           "confirming findings; do not re-map the surface. NOTE: your checks only reach "
           "pending_verification — a separate pass independently re-checks them before "
           "anything counts. That is by design; keep proving, don't try to self-promote."),
    tool_names=["confirm_finding", "verify_vulnerability", "authenticate", "kali_exec",
                "browser_navigate", "browser_content", "browser_fill"],
    role=PLAN,           # depth/reasoning work -> strongest model
    max_steps=40,
)

ACCESS = SpecialistProfile(
    name="access",
    addon=("You are the ACCESS specialist. A confirmed foothold already exists — the kill "
           "chain briefing tells you which stage to press (credential access, privilege "
           "escalation, discovery, or lateral movement). Your job is mechanical, not "
           "exploratory: harvest secrets from material you already hold (extract_secrets), "
           "try candidates against in-scope probes (try_credential), and prove privilege "
           "boundaries differentially (prove_privilege) — never label access yourself; "
           "prove_privilege's own check still only reaches pending_verification, same as "
           "every other proof tool. Use record_access only to note leads/edges you "
           "discover, not to self-grant held access. Do NOT hunt new vulnerability "
           "classes — that is the exploit specialist's job; if nothing presses further, "
           "say so and stop."),
    tool_names=["extract_secrets", "try_credential", "prove_privilege", "record_access",
                "authenticate", "kali_exec", "browser_navigate", "browser_content"],
    role=PARSE,          # procedural/mechanical work once a path is already known -> cheaper model
    max_steps=20,
)

LOGIC = SpecialistProfile(
    name="logic",
    addon=("You are the LOGIC specialist. Endpoints that look workflow-shaped (cart, "
           "checkout, coupon, payment, voucher, order, transfer, booking, ...) are in the "
           "knowledge graph. Reason about what the APP'S DOMAIN assumes should be true — a "
           "coupon used once, a price computed server-side, a step that can't be skipped, "
           "an action that can't be repeated — and try to break that assumption. Use "
           "verify_workflow_abuse: give an ordered attack_steps sequence (e.g. redeem the "
           "same coupon twice, or submit a negative quantity, or call the 'confirm order' "
           "step without first calling 'add payment'), an ordered control_steps sequence "
           "doing the SAME workflow honestly (ideally with a fresh identifier — a "
           "different coupon/order), and the invariant that proves the attack sequence "
           "broke something the control didn't. This is NOT re-run k-of-n like the other "
           "proof tools — business logic is usually one-shot, so get the sequence right "
           "the first time rather than spraying payloads. Authenticate first if the "
           "workflow needs a session. Do NOT hunt injection/XSS/access-control here — "
           "that's the exploit specialist's job; only pursue bugs where the vulnerability "
           "IS the business rule being violated, not a technical injection flaw."),
    tool_names=["verify_workflow_abuse", "authenticate", "browser_navigate", "browser_content",
                "browser_fill", "browser_click"],
    role=PLAN,           # requires reasoning about the specific app's domain, not pattern-matching
    max_steps=25,
)

VERIFY = SpecialistProfile(
    name="verify",
    addon=("You are the VERIFY specialist — the adversary inside the team. You did not "
           "propose any of these findings and you owe them no loyalty. For each pending "
           "finding, call verify_finding_independently(finding_id) and accept whatever "
           "verdict comes back: it reproduces the check fresh and forces a negative "
           "control, so your job is just to run it for every pending finding, not to "
           "argue with the result. Work through ALL pending findings before stopping."),
    tool_names=["verify_finding_independently"],
    role=PLAN,           # independence matters more than cost here; use the strong pool
    max_steps=15,
)


def run_verify_pass(engagement: Engagement, tools: dict[str, Tool], ctx: ToolContext,
                    client: OpenRouterClient, objective: str, budget=None, on_text=None) -> int:
    """Run an independent VERIFY specialist over every pending finding, in a FRESH context.

    Shared by both run modes: the orchestrator calls this between exploit rounds, and
    single-agent mode (cli.py) calls it after the main run — a single continuous context
    must never be allowed to grade its own pending findings, even outside multi-agent mode.
    Returns the number of findings still pending afterward (0 = fully cleared).
    """
    pending = ctx.findings.pending()
    if not pending:
        return 0
    ctx.audit.record("verify_pass.start", pending=len(pending))
    subset = {n: tools[n] for n in VERIFY.tool_names if n in tools}
    verifier = RedTeamAgent(engagement, subset, ctx, client, max_steps=VERIFY.max_steps,
                            system_addon=VERIFY.addon, role=VERIFY.role)
    if budget is not None:
        verifier.with_runtime(budget=budget)
    ids = ", ".join(f.id for f in pending)
    verifier.run(
        f"{objective}\n\nThis run: VERIFY — independently re-check these pending findings "
        f"(finding_id values): {ids}. Call verify_finding_independently once per id. Do not "
        f"skip any.", on_text=on_text)
    remaining = len(ctx.findings.pending())
    ctx.audit.record("verify_pass.finish", remaining=remaining)
    return remaining


class Orchestrator:
    def __init__(self, engagement: Engagement, tools: dict[str, Tool], ctx: ToolContext,
                 client: OpenRouterClient, graph=None, attack_tree=None, memory=None,
                 max_exploit_rounds: int = 12, max_access_rounds: int = 4,
                 max_swarm_workers: int = 3):
        self._eng = engagement
        self._tools = tools
        self._ctx = ctx
        self._client = client
        self._graph = graph
        self._attack_tree = attack_tree
        self._memory = memory
        # These are SAFETY CEILINGS, not targets — the loop stops far earlier whenever
        # there's no untested work left, the objective is achieved, or the budget runs
        # out (see run()/_run_access_loop()). The old default of 2 was an arbitrary
        # constant that could cut a run off mid-chain even with budget and untested work
        # remaining; the ceiling now exists only to bound a pathological worst case
        # (e.g. an attack tree that keeps unlocking new chained work indefinitely),
        # not to cap a normal engagement.
        self._max_exploit_rounds = max_exploit_rounds
        self._max_access_rounds = max_access_rounds   # ceiling on the press-the-foothold loop
        # Small on purpose: every worker is a full free-model context (its own system
        # prompt + briefing overhead), so more workers is more TOKENS per round, not just
        # more wall-clock parallelism — under a tight daily free-model request quota (see
        # Phase 5/6 notes), 3 concurrent is the realistic ceiling, not a target to raise
        # without also raising the token budget.
        self._max_swarm_workers = max_swarm_workers
        self._budget = None
        self._manifest = None

    def with_runtime(self, budget=None, manifest=None, manifest_path=None):
        self._budget = budget
        if manifest is not None and manifest_path is not None:
            self._manifest = (manifest, manifest_path)
        return self

    def _make_specialist(self, profile: SpecialistProfile, addon_suffix: str = "") -> RedTeamAgent:
        # Give the specialist only its allowed tools that actually exist in the registry.
        subset = {n: self._tools[n] for n in profile.tool_names if n in self._tools}
        addon = profile.addon + addon_suffix
        agent = RedTeamAgent(self._eng, subset, self._ctx, self._client,
                             max_steps=profile.max_steps, graph=self._graph,
                             attack_tree=self._attack_tree, memory=self._memory,
                             system_addon=addon, role=profile.role)
        if self._budget is not None:
            mpath = self._manifest[1] if self._manifest else None
            manifest = self._manifest[0] if self._manifest else None
            agent.with_runtime(budget=self._budget, manifest=manifest, manifest_path=mpath)
        return agent

    def _run_exploit_swarm(self, objective: str, round_no: int, on_text=None) -> str:
        """Fan out EXPLOIT across up to max_swarm_workers CONCURRENT contexts, each
        claiming and working a distinct (technique, target) pair from AttackTree's
        prioritized worklist, instead of one context working the list serially. Falls
        back to a single EXPLOIT context (the old behavior) when there's nothing
        actionable yet — this never regresses a run with no attack tree seeded."""
        if self._attack_tree is None:
            exploit = self._make_specialist(EXPLOIT)
            return exploit.run(
                f"{objective}\n\nThis run: EXPLOIT round {round_no + 1} — confirm and "
                f"chain vulnerabilities from the mapped surface.", on_text=on_text) or ""

        actionable = self._attack_tree.actionable(limit=self._max_swarm_workers * 4)
        if not actionable:
            exploit = self._make_specialist(EXPLOIT)
            return exploit.run(
                f"{objective}\n\nThis run: EXPLOIT round {round_no + 1} — confirm and "
                f"chain vulnerabilities from the mapped surface.", on_text=on_text) or ""

        n_workers = min(self._max_swarm_workers, len(actionable))
        self._ctx.audit.record("orchestrator.swarm_start", round=round_no,
                               workers=n_workers, actionable=len(actionable))

        def worker(worker_id: int) -> str:
            summary = ""
            # Each worker claims its OWN next item each time through the loop (not a
            # fixed slice assigned upfront) so a fast worker that finishes its hypothesis
            # quickly picks up the next untried one instead of sitting idle while a
            # slower sibling is still on its first.
            while True:
                claimed = None
                for node in self._attack_tree.actionable(limit=self._max_swarm_workers * 4):
                    if self._attack_tree.claim(node.technique, node.target):
                        claimed = node
                        break
                if claimed is None:
                    break   # nothing left unclaimed — this worker is done
                if self._budget is not None:
                    try:
                        self._budget.check()
                    except Exception:
                        break
                technique = TECHNIQUES.get(claimed.technique)
                desc = technique.description if technique else claimed.technique
                findings_before = len(self._ctx.findings.all())
                exploit = self._make_specialist(
                    EXPLOIT, addon_suffix=f"\n\nYOUR ASSIGNED TARGET THIS TURN: "
                    f"{claimed.technique} on {claimed.target} — {desc}. Work ONLY this "
                    f"hypothesis; other workers are covering the rest of the attack tree "
                    f"in parallel.")
                summary = exploit.run(
                    f"{objective}\n\nThis run: EXPLOIT swarm worker {worker_id} round "
                    f"{round_no + 1} — prove {claimed.technique} on {claimed.target}.",
                    on_text=on_text) or summary
                # A landed finding (pending or already confirmed) means this hypothesis is
                # under its normal lifecycle now — sync() (called every turn inside
                # RedTeamAgent.run()) will promote the node to COMPLETED once VERIFY
                # confirms it, same self-grading-free path every other finding takes.
                #
                # If NOTHING landed, mark it FAILED rather than freeing it back to TODO:
                # claim() only claims a TODO node, so FAILED makes it unclaimable for the
                # REST OF THIS ROUND — freeing back to TODO instead causes an infinite
                # loop (this same worker, or another, immediately re-claims and re-tries
                # the identical empty hypothesis forever, since nothing else changed).
                # FAILED is not terminal across rounds: the next exploit round can still
                # reset stale FAILED nodes back to TODO via attack_tree.sync() picking up
                # new graph/finding state, so a hypothesis that failed with a thin surface
                # can still be retried once more context exists.
                if len(self._ctx.findings.all()) == findings_before:
                    self._attack_tree.mark(claimed.technique, claimed.target, FAILED)
            return summary

        summary = ""
        with ThreadPoolExecutor(max_workers=n_workers) as pool:
            futures = [pool.submit(worker, i) for i in range(n_workers)]
            for fut in as_completed(futures):
                try:
                    summary = fut.result() or summary
                except Exception as exc:
                    self._ctx.audit.record("orchestrator.swarm_worker_error", error=str(exc))
        return summary

    def _run_access_loop(self, objective: str, on_text=None) -> str:
        """Press a confirmed foothold as far as the kill chain says it goes.

        Runs ACCESS -> VERIFY (prove_privilege also only reaches pending_verification)
        repeatedly while KillChain.recommend() still names a pressing stage, stopping as
        soon as the achieved-stage set stops growing (no more progress from pressing) or
        the round ceiling / budget is hit — never a fixed number of rounds regardless of
        whether there's anything left to press.
        """
        access, killchain = getattr(self._ctx, "access", None), getattr(self._ctx, "killchain", None)
        if access is None or killchain is None:
            return ""
        summary = ""
        last_achieved = set(killchain.achieved())
        for rnd in range(self._max_access_rounds):
            if self._budget is not None:
                try:
                    self._budget.check()
                except Exception as exc:   # Halt
                    self._ctx.audit.record("orchestrator.halt", reason=str(exc))
                    break
            objective_obj = getattr(self._ctx, "objective", None)
            recs = killchain.recommend(access, objective_obj)
            if not (_ACCESS_STAGES & set(recs)):
                break   # kill chain says the next move is new exploitation, not pressing
            self._ctx.audit.record("orchestrator.phase", phase="access", round=rnd,
                                   recommend=recs)
            specialist = self._make_specialist(ACCESS)
            summary = specialist.run(
                f"{objective}\n\nThis run: ACCESS round {rnd + 1} — press the confirmed "
                f"foothold toward: {', '.join(recs)}.", on_text=on_text) or summary

            still_pending = run_verify_pass(self._eng, self._tools, self._ctx, self._client,
                                            objective, budget=self._budget, on_text=on_text)
            if still_pending:
                self._ctx.audit.record("orchestrator.verify_incomplete", remaining=still_pending)

            achieved_now = set(killchain.achieved())
            if achieved_now == last_achieved:
                break   # stalled — pressing isn't advancing the kill chain further
            last_achieved = achieved_now
        return summary

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
        # Each round is followed by a VERIFY round in a FRESH, separate context: the
        # exploit specialist's checks only ever reach pending_verification, and nothing
        # downstream (objective credit, access-graph holds, the skill library) may act on
        # a finding until an independent context has tried to kill it and failed to.
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
            objective_obj = getattr(self._ctx, "objective", None)
            if objective_obj is not None and objective_obj.achieved:
                self._ctx.audit.record("orchestrator.objective_achieved", round=rnd)
                break
            if self._attack_tree is not None and rnd > 0:
                # Give nodes that failed in an EARLIER round another chance now that this
                # round may have more graph/finding context — never reset within the same
                # round that set FAILED (see retry_failed()'s own docstring).
                self._attack_tree.retry_failed()
            self._ctx.audit.record("orchestrator.phase", phase="exploit", round=rnd)
            summary = self._run_exploit_swarm(objective, rnd, on_text) or summary

            self._ctx.audit.record("orchestrator.phase", phase="verify")
            still_pending = run_verify_pass(self._eng, self._tools, self._ctx, self._client,
                                            objective, budget=self._budget, on_text=on_text)
            if still_pending:
                self._ctx.audit.record("orchestrator.verify_incomplete", remaining=still_pending)

            summary = self._run_access_loop(objective, on_text) or summary

        # Phase 3 — logic round: business-logic bugs don't chain off exploit findings the
        # way access-pressing does, so one round after the surface is mapped and exploited
        # is enough — gated on the surface actually looking workflow-shaped, so an app
        # that's just static content doesn't burn a round and steps on nothing.
        budget_remains = True
        if self._budget is not None:
            try:
                self._budget.check()
            except Exception as exc:   # Halt
                self._ctx.audit.record("orchestrator.halt", reason=str(exc))
                budget_remains = False
        if budget_remains and _looks_workflow_shaped(self._graph):
            self._ctx.audit.record("orchestrator.phase", phase="logic")
            logic = self._make_specialist(LOGIC)
            summary = logic.run(
                f"{objective}\n\nThis run: LOGIC — find and prove business-logic bugs "
                f"on the workflow-shaped endpoints already mapped.", on_text=on_text) or summary

            self._ctx.audit.record("orchestrator.phase", phase="verify")
            still_pending = run_verify_pass(self._eng, self._tools, self._ctx, self._client,
                                            objective, budget=self._budget, on_text=on_text)
            if still_pending:
                self._ctx.audit.record("orchestrator.verify_incomplete", remaining=still_pending)

        self._ctx.audit.record("orchestrator.finish",
                               findings=len(self._ctx.findings.all()),
                               confirmed=len([f for f in self._ctx.findings.all()
                                             if f.confidence == "confirmed"]))
        return summary
