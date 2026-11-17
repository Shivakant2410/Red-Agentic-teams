"""The lifecycle registry — every state machine in the platform, in ONE place.

THE PROBLEM THIS ENDS: until D1 the platform's lifecycles were *implicit* — the
states lived as bare strings scattered across write sites ("running" here,
"completed" there), the legal transitions lived in comments (or nowhere), and
each consumer (dashboard badge, coverage map, bench scorer, report generator)
re-hard-coded its own copy of the vocabulary. Three drift bugs had already
landed by the time this module was written:

  - `Finding`'s docstring listed five confidence states while the merge code in
    FindingStore.add() silently accepted a sixth ("firm") — the vocabulary was
    only discoverable by reading the merge conditionals;
  - coverage.py had to tolerate a legacy "confirmed" attack-tree status that
    the tree itself never writes (an alias only visible in the consumer);
  - the dashboard's StatusBadge hard-codes the four run statuses, with
    "unknown" rendering muted — the one safety net between a vocabulary change
    and a silently-wrong operator UI.

THE DECISION (docs/state-machines.md, §Decision): one module owns the
vocabulary, the transition tables, the WRITER matrix (who may set what), and a
machine-readable export. Three audiences, one source of truth:

  - DX — modules import their constants from here (`from .states import
    TREE_TODO as TODO`), so renaming or extending a lifecycle is a one-file
    change the type checker and the test suite can see end-to-end;
  - AX — an agent (or any tool) can enumerate every lifecycle, its legal
    transitions, its terminal states, and who may write them without reading
    source: `python -m redteam.states --json`, or live at
    `GET /api/state-machines`. The hypotheses' lifecycle stays authoritative
    in swarm/hypotheses.py and is re-exported here at call time, so there is
    exactly one table even though that machine predates this module;
  - UX — the operator-facing states an auditor sees in events.jsonl, the
    coverage map, and the dashboard are now *specified* somewhere: an unknown
    status is by definition a bug, not a vocabulary extension.

TOLERANCE POLICY (the "without breaking anything" contract): D1 changes
vocabulary ownership, NOT runtime strictness. Write paths keep accepting what
they accepted yesterday (e.g. AttackTree.mark() still takes any string, and old
run artifacts still load); the tables are the contract new code must honor and
the audit trail consumers may now rely on. Tightening writes (rejecting
unknown/illegal transitions) is deliberately deferred behind a future strict
mode so no stacked run, bench, or artifact can regress.

This module imports NOTHING from the package at import time (the hypothesis
table is pulled lazily inside machines()), so every low-level module —
findings, attack_tree, killchain, runtime, run — can import its constants from
here without circular-import risk.
"""

from __future__ import annotations

# -- run manifest (runtime.RunManifest; written by agent.py / server.py) -----------

RUN_RUNNING = "running"
RUN_COMPLETED = "completed"
RUN_HALTED = "halted"
RUN_ERROR = "error"

RUN_STATES = (RUN_RUNNING, RUN_COMPLETED, RUN_HALTED, RUN_ERROR)
RUN_INITIAL = RUN_RUNNING
# Terminal for a run PROCESS: the manifest is never restarted in-place — a new
# run gets a new manifest. server.py may write "error" from any prior state
# when the engine thread dies; that is a state OVERRIDE, not a transition, and
# is recorded in WRITERS rather than widened here.
RUN_TRANSITIONS: dict[str, tuple[str, ...]] = {
    RUN_RUNNING: (RUN_COMPLETED, RUN_HALTED, RUN_ERROR),
    RUN_COMPLETED: (),
    RUN_HALTED: (),
    RUN_ERROR: (),
}

# -- approval gate (run.py HeadlessApprover; approvals.json contract) --------------

APPROVAL_PENDING = "pending"
APPROVAL_RESOLVED = "resolved"

APPROVAL_STATES = (APPROVAL_PENDING, APPROVAL_RESOLVED)
APPROVAL_INITIAL = APPROVAL_PENDING
APPROVAL_TERMINAL = (APPROVAL_RESOLVED,)
# `approved` is a separate boolean dimension carried on the resolved record —
# "resolved with approved=False" (a denial, or the STOP kill file's auto-deny)
# is a resolved outcome, not a third state. Exactly one pending record per
# request; resolution is idempotent-refusing (a second resolve returns False).
APPROVAL_TRANSITIONS: dict[str, tuple[str, ...]] = {
    APPROVAL_PENDING: (APPROVAL_RESOLVED,),
    APPROVAL_RESOLVED: (),
}

# -- attack-tree node (attack_tree.py AttackNode) -----------------------------------

TREE_TODO = "todo"
TREE_IN_PROGRESS = "in_progress"
TREE_COMPLETED = "completed"
TREE_FAILED = "failed"

TREE_STATES = (TREE_TODO, TREE_IN_PROGRESS, TREE_COMPLETED, TREE_FAILED)
TREE_INITIAL = TREE_TODO
TREE_TERMINAL = (TREE_COMPLETED,)
TREE_TRANSITIONS: dict[str, tuple[str, ...]] = {
    TREE_TODO: (TREE_IN_PROGRESS, TREE_COMPLETED),
    # claim() moves TODO -> IN_PROGRESS; a lease expiry may drop it back to
    # TODO (documented release path in AttackTree.claim()).
    TREE_IN_PROGRESS: (TREE_COMPLETED, TREE_FAILED, TREE_TODO),
    # FAILED is retryable exactly once per orchestrator round via
    # retry_failed() — resetting more often would undo the FAILED status
    # within the same round it was set (the infinite empty-retry loop it
    # exists to prevent). The reset is FAILED -> TODO, never straight to
    # COMPLETED: a re-trial must pass through a fresh attempt.
    TREE_FAILED: (TREE_TODO,),
    TREE_COMPLETED: (),
}
# Legacy read-alias: very old run artifacts may carry "confirmed" where the
# tree would now write "completed" (coverage.py already tolerates it on read).
# Kept OUT of the write vocabulary on purpose — new code must write COMPLETED.
TREE_LEGACY_ALIASES: dict[str, str] = {"confirmed": TREE_COMPLETED}

# -- kill-chain stage (killchain.py StageState) --------------------------------------

STAGE_NOT_STARTED = "not_started"
STAGE_IN_PROGRESS = "in_progress"
STAGE_ACHIEVED = "achieved"

STAGE_STATES = (STAGE_NOT_STARTED, STAGE_IN_PROGRESS, STAGE_ACHIEVED)
STAGE_INITIAL = STAGE_NOT_STARTED
STAGE_TERMINAL = (STAGE_ACHIEVED,)
# The forward flow is not_started -> in_progress -> achieved. KillChain.mark()
# is deliberately operator-authoritative (it may revert a stage when evidence
# shows it was over-claimed), so the table documents the FORWARD flow; a revert
# is an operator override that must carry a note, exactly like a run manifest
# override. PERSISTENCE / DEFENSE_EVASION additionally require explicit RoE
# sign-off before IN_PROGRESS (killchain.GATED) — an approval-gate on the
# transition, not a separate state.
STAGE_TRANSITIONS: dict[str, tuple[str, ...]] = {
    STAGE_NOT_STARTED: (STAGE_IN_PROGRESS, STAGE_ACHIEVED),
    STAGE_IN_PROGRESS: (STAGE_ACHIEVED,),
    STAGE_ACHIEVED: (),
}

# -- finding confidence (findings.py Finding.confidence) ------------------------------
#
# The funnel from the C1 doctrine: an observation is not a hypothesis, a
# hypothesis is not a finding, a finding is not confirmed until the independent
# verification pipeline confirms it. The confidence axis is the finding-side
# realization of that doctrine.

CONF_TENTATIVE = "tentative"                    # agent recorded it, no k-of-n check yet
CONF_FIRM = "firm"                              # agent's own k-of-n check passed (self-graded)
CONF_PENDING_VERIFICATION = "pending_verification"  # queued for the independent pipeline
CONF_CONFIRMED = "confirmed"                    # independent re-check reproduced it
CONF_FALSIFIED = "falsified"                    # a benign control produced the same signal
CONF_NOT_REPRODUCIBLE = "not_reproducible"      # the pipeline could not reproduce (weak verdict)

FINDING_STATES = (CONF_TENTATIVE, CONF_FIRM, CONF_PENDING_VERIFICATION,
                  CONF_CONFIRMED, CONF_FALSIFIED, CONF_NOT_REPRODUCIBLE)
FINDING_INITIAL = CONF_TENTATIVE
# Terminal = the record is closed either way but STAYS ON RECORD (auditable
# false positives are a feature). CONFIRMED/FALSIFIED can never be overwritten;
# NOT_REPRODUCIBLE is deliberately NOT terminal — it is a statement about the
# environment, not the bug, so verify_finding_independently accepts it back for
# a re-check (tools/independent_verify.py's guard is written as "confidence in
# (pending_verification, not_reproducible)").
FINDING_TERMINAL = (CONF_CONFIRMED, CONF_FALSIFIED)
FINDING_TRANSITIONS: dict[str, tuple[str, ...]] = {
    # Merge forward-upgrade (FindingStore.add): a proof-carrying record
    # supersedes self-assertions on the same dedup key.
    CONF_TENTATIVE: (CONF_FIRM, CONF_PENDING_VERIFICATION, CONF_CONFIRMED),
    CONF_FIRM: (CONF_PENDING_VERIFICATION, CONF_CONFIRMED),
    # The independent pipeline's promote() verdicts.
    CONF_PENDING_VERIFICATION: (CONF_CONFIRMED, CONF_FALSIFIED, CONF_NOT_REPRODUCIBLE),
    CONF_NOT_REPRODUCIBLE: (CONF_PENDING_VERIFICATION, CONF_CONFIRMED, CONF_FALSIFIED),
    CONF_CONFIRMED: (),
    CONF_FALSIFIED: (),
}

# WHO may write which confidence (the writer matrix). This is the load-bearing
# half of the finding machine: the states say what exists, the writers say who
# may say so. "agent" here means the LLM via the record_finding tool;
# "tool:deterministic" means FIRST-PARTY tools that ran a deterministic k-of-n
# check with a benign control (confirm_finding, test_access_control, test_idor,
# apply_skill, template_search) — they are a verification path, not an agent
# opinion, and legitimately create CONFIRMED records directly.
FINDING_WRITERS: tuple[dict, ...] = (
    {"writer": "agent:record_finding",
     "may_set": (CONF_TENTATIVE, CONF_FIRM)},
    {"writer": "tool:deterministic_proof",
     "may_set": (CONF_TENTATIVE, CONF_FIRM, CONF_CONFIRMED)},
    {"writer": "verify:pipeline (FindingStore.promote)",
     "may_set": (CONF_CONFIRMED, CONF_FALSIFIED, CONF_NOT_REPRODUCIBLE)},
    {"writer": "store:merge (FindingStore.add, forward-only)",
     "may_set": (CONF_FIRM, CONF_PENDING_VERIFICATION, CONF_CONFIRMED)},
)

# -- mission lifecycle (mission/commander.py — Phase 2 coordination core) -------------
#
# A mission is the operator-level unit of work (one objective, one authorized
# engagement). The Commander is the lifecycle authority; the mission layer NEVER
# decides offensive truth — task success, confirmed findings (FindingStore), and
# AttackTree completion are three independent things (docs/builder01-phase2-
# mission-design.md C-4).

MISSION_PLANNED = "planned"
MISSION_RUNNING = "running"
MISSION_SUCCEEDED = "succeeded"
MISSION_FAILED = "failed"
MISSION_HALTED = "halted"
MISSION_CANCELLED = "cancelled"

MISSION_STATES = (MISSION_PLANNED, MISSION_RUNNING, MISSION_SUCCEEDED,
                  MISSION_FAILED, MISSION_HALTED, MISSION_CANCELLED)
MISSION_INITIAL = MISSION_PLANNED
MISSION_TRANSITIONS: dict[str, tuple[str, ...]] = {
    MISSION_PLANNED: (MISSION_RUNNING, MISSION_CANCELLED),
    MISSION_RUNNING: (MISSION_SUCCEEDED, MISSION_FAILED, MISSION_HALTED,
                      MISSION_CANCELLED),
    # Terminal in every direction: a finished mission is never restarted in
    # place (a new run dir + new mission_id, same as the run machine).
    MISSION_SUCCEEDED: (),
    MISSION_FAILED: (),
    MISSION_HALTED: (),
    MISSION_CANCELLED: (),
}

# -- mission task lifecycle (mission/task.py + mission/scheduler.py) -------------------
#
# A task is ONE claimable unit (normally one (technique, target) tree node).
# Ownership is established by the claim trio (task CAS -> AttackTree.claim ->
# HypothesisRegistry claim) and protected by a lease with a FENCING TOKEN:
# every worker mutation must present the token it was dispatched with, so a
# superseded worker's late write is rejected even before the wall-clock sweep
# (the sweep bumps the token; timeout alone never proves an operation stopped).
# EXPIRED is re-armable while attempts remain (retry policy), else FAILED.
# BLOCKED_DUPLICATE = the hypothesis layer reported the same investigation as
# already-owned this round; the tree node is released and the task re-arms.

TASK_PENDING = "pending"
TASK_CLAIMED = "claimed"
TASK_RUNNING = "running"
TASK_SUCCEEDED = "succeeded"
TASK_FAILED = "failed"
TASK_BLOCKED_DUPLICATE = "blocked_duplicate"
TASK_EXPIRED = "expired"
TASK_CANCELLED = "cancelled"

TASK_STATES = (TASK_PENDING, TASK_CLAIMED, TASK_RUNNING, TASK_SUCCEEDED,
               TASK_FAILED, TASK_BLOCKED_DUPLICATE, TASK_EXPIRED,
               TASK_CANCELLED)
TASK_INITIAL = TASK_PENDING
TASK_TRANSITIONS: dict[str, tuple[str, ...]] = {
    TASK_PENDING: (TASK_CLAIMED, TASK_CANCELLED),
    # CLAIMED -> PENDING is the journaled rollback (TASK_CLAIM_ABORTED) when a
    # later claim-trio step loses; recovery reconcile produces the same edge.
    TASK_CLAIMED: (TASK_RUNNING, TASK_PENDING, TASK_BLOCKED_DUPLICATE,
                   TASK_EXPIRED, TASK_CANCELLED),
    TASK_RUNNING: (TASK_SUCCEEDED, TASK_FAILED, TASK_EXPIRED, TASK_CANCELLED),
    TASK_BLOCKED_DUPLICATE: (TASK_PENDING, TASK_CANCELLED),
    TASK_EXPIRED: (TASK_PENDING, TASK_FAILED),
    TASK_FAILED: (TASK_PENDING,),      # retry policy: attempts < max_attempts only
    TASK_SUCCEEDED: (),
    TASK_CANCELLED: (),
}

# -- knowledge-graph node lifecycle (knowledge.py Node.lifecycle) ----------------------
#
# Phase E2 (docs/adr-002-unified-intelligence-graph.md): the graph keeps every
# historical observation (nothing is ever deleted) and adds an explicit
# currency dimension so old state can stop masquerading as current state.
# STALE = the observation itself is no longer trusted (entity went quiet or a
# retest invalidated the mapping); REMEDIATED = a finding-backed relationship
# on this entity was independently proven fixed. ACTIVE = fresh observation.
# A fresh observation clears STALE (re-observation is stronger evidence than
# aging) but NOT REMEDIATED (an endpoint answering again says nothing about
# whether the vulnerability is back — only a new confirmed finding could
# re-establish that, and the finding pipeline, not the graph, owns that call).

KG_ACTIVE = "active"
KG_STALE = "stale"
KG_REMEDIATED = "remediated"

KG_LIFECYCLE_STATES = (KG_ACTIVE, KG_STALE, KG_REMEDIATED)
KG_LIFECYCLE_INITIAL = KG_ACTIVE
KG_LIFECYCLE_TRANSITIONS: dict[str, tuple[str, ...]] = {
    KG_ACTIVE: (KG_STALE, KG_REMEDIATED),
    KG_STALE: (KG_ACTIVE,),          # re-observation only (KnowledgeGraph.observe)
    KG_REMEDIATED: (KG_ACTIVE,),     # only a future independently-confirmed re-proof
}

# -- access hold lifecycle (access.py AccessNode held/invalidated_at) ------------------
#
# The AccessGraph stays the sole authority for demonstrated access. REVOKED is
# the honest answer to "we held it then; do we still?": the hold happened and
# stays on record (append-only history), but a revoked node is no longer
# current. Re-holding REQUIRES a new demonstration through the existing gate
# (hold() with a REQUIRED_SOURCE-eligible source) — an agent assertion can
# never resurrect a revoked holding. Written today by the retest-fixed bridge
# (retest.invalidate_after_fix) and available to any future evidence path.

HOLD_ACTIVE = "held"
HOLD_REVOKED = "revoked"

HOLD_LIFECYCLE_STATES = (HOLD_ACTIVE, HOLD_REVOKED)
HOLD_LIFECYCLE_INITIAL = HOLD_ACTIVE
HOLD_LIFECYCLE_TRANSITIONS: dict[str, tuple[str, ...]] = {
    HOLD_ACTIVE: (HOLD_REVOKED,),
    HOLD_REVOKED: (HOLD_ACTIVE,),    # only via hold() with a fresh demonstration
}

# -- machine registry -----------------------------------------------------------------
#
# Machines owned here, plus the hypothesis lifecycle, which stays authoritative
# in swarm/hypotheses.py (it predates this module and is event-sourced with its
# own VALID_TRANSITIONS). HYPO is merged in at CALL time via a function-level
# import — that keeps this module importable by the lowest-level modules
# (findings, runtime, ...) with zero circular-import risk.

_OWNED: dict[str, dict] = {
    "run": {
        "states": RUN_STATES, "initial": RUN_INITIAL,
        "terminal": tuple(t for t, nxt in RUN_TRANSITIONS.items() if not nxt),
        "transitions": RUN_TRANSITIONS,
        "writers": (
            {"writer": "agent loop (agent.py)",
             "may_set": (RUN_RUNNING, RUN_COMPLETED, RUN_HALTED)},
            {"writer": "server watchdog (server.py)",
             "may_set": (RUN_ERROR,)},
            {"writer": "bench harness (raw_baseline.py)",
             "may_set": (RUN_COMPLETED, RUN_ERROR)},
        ),
        "consumers": ("dashboard StatusBadge (4 tones + muted unknown)",
                      "bench/ladder.py scoring", "report.py summary",
                      "GET /api/runs + SSE run.finish"),
        "notes": "Terminal for a run process; a new run gets a new manifest. "
                 "RUN_ERROR may be written as an override from any state when "
                 "the engine thread dies.",
    },
    "approval": {
        "states": APPROVAL_STATES, "initial": APPROVAL_INITIAL,
        "terminal": APPROVAL_TERMINAL,
        "transitions": APPROVAL_TRANSITIONS,
        "writers": (
            {"writer": "engine thread (HeadlessApprover.approve creates; kill switch auto-denies)",
             "may_set": (APPROVAL_PENDING, APPROVAL_RESOLVED)},
            {"writer": "operator via POST /api/approvals/{id} (run.resolve_approval)",
             "may_set": (APPROVAL_RESOLVED,)},
        ),
        "consumers": ("approvals.json file contract", "GET/POST /api/.../approvals",
                      "dashboard ApprovalCard"),
        "notes": "approved is a boolean dimension on the resolved record, not a "
                 "third state; the STOP kill file resolves pending approvals as "
                 "denials. Resolution is single-flip (second resolve returns False).",
    },
    "attack_tree_node": {
        "states": TREE_STATES, "initial": TREE_INITIAL,
        "terminal": TREE_TERMINAL,
        "transitions": TREE_TRANSITIONS,
        "writers": (
            {"writer": "specialists via claim()/mark()/confirm()",
             "may_set": (TREE_TODO, TREE_IN_PROGRESS, TREE_COMPLETED, TREE_FAILED)},
            {"writer": "orchestrator via retry_failed() (once per round)",
             "may_set": (TREE_TODO,)},
        ),
        "consumers": ("server.py /api/runs/{id} bucket counts",
                      "coverage.py tested/attempted derivation",
                      "dashboard RunDetail.attack_tree"),
        "notes": "Legacy read alias: 'confirmed' in old artifacts reads as "
                 "completed. FAILED -> TODO is the once-per-round retry path; "
                 "re-marking the current status is a no-op by design (bandit "
                 "win-inflation guard).",
    },
    "killchain_stage": {
        "states": STAGE_STATES, "initial": STAGE_INITIAL,
        "terminal": STAGE_TERMINAL,
        "transitions": STAGE_TRANSITIONS,
        "writers": (
            {"writer": "tools on proof (KillChain.mark)",
             "may_set": (STAGE_IN_PROGRESS, STAGE_ACHIEVED)},
            {"writer": "operator override (with a note)",
             "may_set": STAGE_STATES},
        ),
        "consumers": ("agent briefing (KillChain.briefing)", "report.py",
                      "dashboard KillChainList"),
        "notes": "The table is the FORWARD flow; mark() stays operator-"
                 "authoritative for reverts. PERSISTENCE/DEFENSE_EVASION are "
                 "GATED: the IN_PROGRESS transition requires explicit RoE "
                 "sign-off (an approval gate on the edge, not a state).",
    },
    "finding_confidence": {
        "states": FINDING_STATES, "initial": FINDING_INITIAL,
        "terminal": FINDING_TERMINAL,
        "transitions": FINDING_TRANSITIONS,
        "writers": FINDING_WRITERS,
        "consumers": ("verify pipeline worklist (FindingStore.pending)",
                      "access-graph + objective crediting (only confirmed)",
                      "attack_tree.sync() unlock + bandit wins",
                      "report.py", "dashboard FindingsTable"),
        "notes": "not_reproducible is a WEAK verdict about the environment and "
                 "stays re-checkable; confirmed/falsified are immutable and the "
                 "record stays on file either way. Nothing may credit an "
                 "objective or access node from anything but confirmed.",
    },
    "mission": {
        "states": MISSION_STATES, "initial": MISSION_INITIAL,
        "terminal": tuple(t for t, nxt in MISSION_TRANSITIONS.items() if not nxt),
        "transitions": MISSION_TRANSITIONS,
        "writers": (
            {"writer": "commander (mission/commander.py — lifecycle authority)",
             "may_set": MISSION_STATES},
            {"writer": "operator via control plane (halt/cancel)",
             "may_set": (MISSION_HALTED, MISSION_CANCELLED)},
        ),
        "consumers": ("mission.json record", "GET /api/missions*",
                      "mission_journal.jsonl replay"),
        "notes": "One mission : N run directories by model (run_ids is a list); "
                 "in Phase 2 exactly one run is minted and mission_id == that "
                 "run_id by CONSTRUCTION, never by hard-coded equality — "
                 "downstream components must keep treating the two fields as "
                 "independent (C1). A finished mission is never restarted in "
                 "place. Mission success is an EXECUTION outcome: it never "
                 "implies a confirmed finding (C4 — only the independent "
                 "verification pipeline may confirm).",
    },
    "mission_task": {
        "states": TASK_STATES, "initial": TASK_INITIAL,
        "terminal": tuple(t for t, nxt in TASK_TRANSITIONS.items() if not nxt),
        "transitions": TASK_TRANSITIONS,
        "writers": (
            {"writer": "scheduler via claim trio (mission/scheduler.py: "
                       "task CAS -> AttackTree.claim -> hypothesis claim)",
             "may_set": (TASK_CLAIMED, TASK_RUNNING, TASK_PENDING,
                         TASK_BLOCKED_DUPLICATE)},
            {"writer": "fenced worker completion (complete_task/fail_task with "
                       "the current lease token)",
             "may_set": (TASK_SUCCEEDED, TASK_FAILED)},
            {"writer": "lease sweep (expire_claims; token bumped, liveness "
                       "consulted before stealing a live worker)",
             "may_set": (TASK_EXPIRED,)},
            {"writer": "retry policy / recovery reconcile (re-arm or exhaust)",
             "may_set": (TASK_PENDING, TASK_FAILED)},
            {"writer": "operator cancel", "may_set": (TASK_CANCELLED,)},
        ),
        "consumers": ("mission.json task records", "GET /api/missions/{id}",
                      "mission_journal.jsonl replay + recovery reconcile"),
        "notes": "Ownership is journaled BEFORE any work starts (journal-first). "
                 "Every worker mutation is fenced by the lease token issued at "
                 "claim time; a rejected stale write is audited "
                 "TASK_RESULT_REJECTED and never re-fed to the bandit. Task "
                 "SUCCEEDED means EXECUTION succeeded — never that a finding "
                 "was confirmed or that the attack-tree node completed (C4); "
                 "the tree completes only via sync() on a CONFIRMED finding.",
    },
    "kg_node_lifecycle": {
        "states": KG_LIFECYCLE_STATES, "initial": KG_LIFECYCLE_INITIAL,
        "terminal": (),
        "transitions": KG_LIFECYCLE_TRANSITIONS,
        "writers": (
            {"writer": "retest-fixed bridge (retest.invalidate_after_fix via "
                       "KnowledgeGraph.mark_remediated)",
             "may_set": (KG_REMEDIATED,)},
            {"writer": "graph maintenance (KnowledgeGraph.mark_stale)",
             "may_set": (KG_STALE, KG_ACTIVE)},
            {"writer": "re-observation (KnowledgeGraph.observe)",
             "may_set": (KG_ACTIVE,)},
        ),
        "consumers": ("graph_view.py attack-path projection (status decoration)",
                      "KnowledgeGraph.summary() lifecycle counts",
                      "access/objective consumers read the graph only via "
                      "existing node data"),
        "notes": "Currency dimension, never deletion: stale/remediated nodes "
                 "keep their full observation history. Re-observation clears "
                 "stale but not remediated. Marking is a read-model decoration "
                 "and can never authorize, execute, or confirm anything.",
    },
    "access_hold": {
        "states": HOLD_LIFECYCLE_STATES, "initial": HOLD_LIFECYCLE_INITIAL,
        "terminal": (),
        "transitions": HOLD_LIFECYCLE_TRANSITIONS,
        "writers": (
            {"writer": "demonstration paths (hold() — set_session, "
                       "postex, prove_privilege, creditor; source-gated "
                       "downstream by objective.REQUIRED_SOURCE)",
             "may_set": (HOLD_ACTIVE,)},
            {"writer": "retest-fixed bridge (retest.invalidate_after_fix via "
                       "AccessGraph.revoke)",
             "may_set": (HOLD_REVOKED,)},
        ),
        "consumers": ("AccessGraph.held()/reached()/frontier() (revoked nodes "
                      "drop out of current holdings)",
                      "graph_view.py (revoked holdings never render as current)",
                      "objective.autoevaluate (a revoked hold cannot credit)"),
        "notes": "Append-only in spirit: revocation records when/why and keeps "
                 "the historical evidence; re-holding requires a fresh "
                 "demonstration, so an agent assertion cannot resurrect it.",
    },
}


def machines() -> dict[str, dict]:
    """All lifecycle machines, with the hypothesis lifecycle merged in.

    The hypothesis table is imported lazily (call time, not import time) so the
    modules that own the OTHER lifecycles can import constants from here
    without any import cycle. There is exactly one copy of each table: the
    hypothesis machine's ONLY authoritative copy remains
    swarm/hypotheses.VALID_TRANSITIONS; this re-exports it verbatim.
    """
    from .swarm.hypotheses import VALID_TRANSITIONS as _HYP, PROPOSED as _HYP_INIT, TERMINAL as _HYP_TERM
    merged = dict(_OWNED)
    merged["hypothesis"] = {
        "states": tuple(_HYP.keys()),
        "initial": _HYP_INIT,
        "terminal": tuple(_HYP_TERM),
        "transitions": {k: tuple(v) for k, v in _HYP.items()},
        "writers": (
            {"writer": "workers via HypothesisRegistry (claim/evidence/verify outcomes)",
             "may_set": tuple(_HYP.keys())},
        ),
        "consumers": ("research forum briefings", "swarm projections",
                      "benchmarks/phase1_collective.py"),
        "notes": "Event-sourced (STATUS_CHANGED events); PROPOSED never sees "
                 "BLOCKED/STALE (an unadopted suspicion is simply not worked); "
                 "only record_verification_outcome() may set CONFIRMED/REFUTED.",
    }
    return merged


def describe(machine: str) -> dict:
    """One machine's spec. Raises KeyError naming the unknown machine — an
    unknown lifecycle in caller code should be loud, not silently empty."""
    try:
        return machines()[machine]
    except KeyError:
        raise KeyError(f"unknown state machine {machine!r}; known: "
                       f"{', '.join(sorted(machines()))}") from None


def can_transition(machine: str, current: str, nxt: str) -> bool:
    """Is `current -> nxt` a legal transition of `machine`?

    Unknown *states* are not transitions (False), and the machine name must be
    exact (KeyError) — both choices keep typos loud.
    """
    spec = describe(machine)
    return nxt in spec["transitions"].get(current, ())


def next_states(machine: str, current: str) -> tuple[str, ...]:
    """Legal successor states of `current` in `machine` (empty for terminal/
    unknown states — an unknown state has no successors by definition)."""
    return describe(machine)["transitions"].get(current, ())


def is_known(machine: str, status: str) -> bool:
    """Is `status` part of `machine`'s vocabulary at all (any state, any era)?"""
    return status in describe(machine)["states"]


EXPORT_VERSION = 3   # bump whenever a lifecycle table changes (Phase 2 added
                     # the mission + mission_task machines; Phase E2 added
                     # kg_node_lifecycle + access_hold)


def machines_json() -> dict:
    """The machine-readable export (AX surface): stable key order, JSON-safe.

    Served at GET /api/state-machines and printed by `python -m redteam.states
    --json`. Versioned so consumers can detect vocabulary changes; bump
    EXPORT_VERSION whenever a table changes.
    """
    all_machines = machines()
    out = {"version": EXPORT_VERSION, "machines": {}}
    for name in sorted(all_machines):
        spec = all_machines[name]
        out["machines"][name] = {
            "states": list(spec["states"]),
            "initial": spec["initial"],
            "terminal": list(spec["terminal"]),
            "transitions": {k: list(v) for k, v in spec["transitions"].items()},
            "writers": [dict(w) for w in spec["writers"]],
            "consumers": list(spec["consumers"]),
            "notes": spec["notes"],
        }
    return out


def _main(argv: list[str] | None = None) -> int:
    """`python -m redteam.states [--json]` — the no-server introspection path
    (agents in sandboxed/air-gapped labs, CI linting, operator sanity checks)."""
    import argparse
    import json
    parser = argparse.ArgumentParser(
        description="Print every lifecycle state machine in the platform.")
    parser.add_argument("--json", action="store_true",
                        help="machine-readable output (stable ordering)")
    parser.add_argument("--machine", default=None,
                        help="restrict output to one machine")
    args = parser.parse_args(argv)
    import sys
    if args.machine and args.machine not in machines():
        print(f"unknown machine: {args.machine}; known: "
              f"{', '.join(sorted(machines()))}", file=sys.stderr)
        return 2

    if args.json:
        data = machines_json()
        if args.machine:
            data["machines"] = {k: v for k, v in data["machines"].items()
                                if k == args.machine}
            if not data["machines"]:
                print(f"unknown machine: {args.machine}", file=sys.stderr)
                return 2
        print(json.dumps(data, indent=2))
        return 0

    for name, spec in sorted(machines().items()):
        if args.machine and name != args.machine:
            continue
        print(f"[{name}]")
        print(f"  initial : {spec['initial']}")
        for state in spec["states"]:
            nxt = spec["transitions"].get(state, ())
            tag = "  (terminal)" if not nxt else ""
            print(f"  {state:<24} -> {', '.join(nxt) if nxt else '-'}{tag}")
        if spec["terminal"]:
            print(f"  terminal: {', '.join(spec['terminal'])}")
        print()
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(_main())
