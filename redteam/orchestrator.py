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
import json
from pathlib import Path
import threading

from .agent import RedTeamAgent
from .attack_tree import FAILED, TECHNIQUES, TODO, technique_cost
from .sandbox.detection_belief import BeliefFilter
from .config import Engagement
from .events import coerce_payload
from .killchain import (ACHIEVED, CREDENTIAL_ACCESS, DISCOVERY, INITIAL_ACCESS,
                        LATERAL_MOVEMENT, PRIVILEGE_ESCALATION)
from .hands import (OPTIONAL_TOOLS, hands_briefing, skills_briefing)
from .llm.openrouter import OpenRouterClient
from .llm.routing import PARSE, PLAN
from .reflection import coach_note, reflect
from .strategy import EngagementStrategy, reset_tree_nudges
from .thesis import generate_theses, theses_briefing, write_theses
from .swarm import (AWAITING_VERIFICATION, CONFIRMED, REFUTED, EvidenceRef,
                    ResearchBundle, SwarmError, weakness_for_technique)
from .tools import ToolContext, Tool
from .errors import record_suppressed_error


def sync_inventory_into_graph(inventory, graph) -> dict:
    """Inventory -> KnowledgeGraph synchronization bridge (Phase E2, ADR-002).

    The audit's finding F2: AssetInventory passively records every answering
    host/port (tools/http.py fingerprints each response), but the KnowledgeGraph's
    host/service layer only ever filled from kali_exec output parsing — so the
    "unified" graph had a hole at its root and the two stores never reconciled.
    This bridge makes the inventory the KG's host/service FEEDER while the
    inventory stays the host/service authority and the KG stays the relationship
    authority.

    ELIGIBILITY POLICY (deliberate, ADR-002): only services with a real observed
    response (`status_last` > 0) become graph nodes. Imported/declared asset-feed
    rows (status_last=None) stay inventory-only — an operator-supplied feed is
    data, never a live observation, and must not widen what the graph presents
    as the answering surface. Failure/denied probes (status 0) are likewise
    skipped: a knock that got nothing is not a service.

    IDEMPOTENCY: every write is a KnowledgeGraph.observe() merge (same key
    re-observed = attrs merged, last_seen refreshed, sources corroborated) —
    calling this twice changes nothing but freshness, which is exactly the
    temporal signal we want (last_seen IS the staleness evidence).

    SAFETY: pure in-memory state work — no network, no scope logic, no findings,
    no attack-tree authority. Cannot widen scope (both stores were scope-checked
    at their own write time) and cannot create demonstrated access.
    """
    if inventory is None or graph is None:
        return {"bridged": 0, "skipped_unanswered": 0}
    from .knowledge import HOST, SERVICE, canonical_host, _now
    bridged = skipped = 0
    try:
        rows = inventory.iter_services()
    except Exception as exc:   # a broken inventory must never break the run
        record_suppressed_error(None, "orchestrator", "bridge_inventory", exc)
        return {"bridged": 0, "skipped_unanswered": 0, "error": type(exc).__name__}
    for host, svc in rows:
        try:
            status = svc.get("status_last")
            if not status:
                skipped += 1
                continue
            scheme = str(svc.get("scheme") or "tcp")
            port = int(svc.get("port") or 0)
            if port <= 0:
                skipped += 1
                continue
            chost = canonical_host(host)
            inv_key = f"{scheme}/{port}"
            source = str(svc.get("source") or "inventory")
            # HOST node — canonical spelling; the raw inventory spelling is
            # preserved as foreign-reference metadata (ADR-002 §Join strategy).
            graph.observe(
                HOST, chost,
                attrs={"inventory_host": host},
                source="inventory",
                evidence_refs=[_inv_evidence_ref(host, inv_key, svc)],
            )
            # SERVICE node + host -> runs -> service edge.
            skey = f"{chost}:{port}"
            graph.observe(
                SERVICE, skey,
                attrs={"scheme": scheme, "port": port,
                       "inventory_key": inv_key,
                       **({"server": str(svc["server"])[:120]} if svc.get("server") else {}),
                       **({"title": str(svc["title"])[:120]} if svc.get("title") else {}),
                       **({"auth": True} if svc.get("auth") else {})},
                source="inventory",
                relate_to=f"{HOST}:{chost}", relation="runs",
                evidence_refs=[_inv_evidence_ref(host, inv_key, svc)],
            )
            bridged += 1
        except Exception as exc:
            record_suppressed_error(None, "orchestrator", "bridge_inventory_row", exc,
                                    severity="info", host=host)
            skipped += 1   # one bad row must not poison the bridge
    return {"bridged": bridged, "skipped_unanswered": skipped}


def _inv_evidence_ref(host: str, inv_key: str, svc: dict) -> dict:
    """EvidenceRef-shaped provenance for one bridged observation. The artifact
    reference points at the inventory row itself (host + service key), so the
    provenance resolves to a real record the run persisted."""
    from .knowledge import _now
    return {
        "evidence_id": f"inv-{host}-{inv_key}",
        "kind": "observation",
        "origin": "target",
        "source": "inventory",
        "source_agent": "inventory_bridge",
        "artifact_ref": f"inventory.json:hosts[{host}].services[{inv_key}]",
        "summary": (f"{svc.get('scheme')}/{svc.get('port')} answered "
                    f"{svc.get('status_last')} (server: {str(svc.get('server') or '')[:60]})"),
        "ts": _now(),
    }


def profile_for(technique: str | None):
    """Module-level alias so callers (and tests) can reach the router without the
    specialists import — kept as a function attribute to avoid a circular import
    at module load time (specialists.py imports SpecialistProfile from here)."""
    from .specialists import profile_for as _pf
    return _pf(technique)

# Kill-chain stages that mean "there is a foothold worth pressing further" — if
# KillChain.recommend() names any of these, an ACCESS round (not another EXPLOIT round)
# is the next useful move.
_ACCESS_STAGES = {CREDENTIAL_ACCESS, PRIVILEGE_ESCALATION, LATERAL_MOVEMENT, DISCOVERY}

# Endpoint URL/key fragments that suggest a multi-step, stateful workflow — the shape of
# thing business-logic bugs live in. Heuristic, not exhaustive: a miss here just means the
# LOGIC round doesn't run (cheap to skip), a false match just means it runs and finds
# nothing (cheap to waste a round on) — asymmetric cost, so a loose heuristic is fine.
# A keyword whitelist (cart/checkout/coupon/...) only fires on apps whose
# endpoints happen to be named like a textbook shop. Real targets name their
# money/ownership flows anything — offers, bundles, balance, transactions,
# payouts, shipping labels — so a keyword gate SILENTLY SKIPS the logic round on
# exactly the high-value apps. These hints now only BOOST confidence; the gate
# below runs logic on any app that is actually stateful (forms, writes, or a
# session), because that is where every business-logic bug lives. Running and
# finding nothing is cheap; skipping a real app is the expensive mistake.
_WORKFLOW_HINTS = ("cart", "checkout", "coupon", "voucher", "discount", "order", "payment",
                   "pay", "redeem", "transfer", "withdraw", "booking", "reserve", "apply",
                   "submit", "vote", "like", "quantity", "balance", "wallet",
                   "offer", "bundle", "bid", "refund", "payout", "escrow", "ship",
                   "invoice", "subscription", "credit", "fee", "price", "listing")


def _looks_workflow_shaped(graph) -> bool:
    """Run the LOGIC round on any app that DOES something — not just ones whose
    endpoints match a keyword list. Business-logic bugs live wherever state is
    created or changed, regardless of what the endpoints are named."""
    if graph is None:
        return False
    from .knowledge import ENDPOINT, PARAMETER
    # 1. Keyword hint on any endpoint, OR a state-mutating method (forms are
    #    recorded as endpoints with a non-GET method / form_params metadata).
    for ep in graph.nodes(ENDPOINT):
        low = ep.key.lower()
        if any(hint in low for hint in _WORKFLOW_HINTS):
            return True
        attrs = ep.attrs or {}
        method = str(attrs.get("method", "")).upper()
        if method and method not in ("GET", "HEAD", "OPTIONS"):
            return True  # POST/PUT/PATCH/DELETE mutates state = a workflow
        if attrs.get("form_params"):
            return True  # a submittable form = user-driven state
    # 2. Any discovered parameter = user-controllable input/state. Pure static
    #    content sites have none, so this still cheaply skips them.
    try:
        if any(True for _ in graph.nodes(PARAMETER)):
            return True
    except Exception as exc:
        record_suppressed_error(None, "orchestrator", "inspect_graph_parameters", exc)
    return False


@dataclass
class SpecialistProfile:
    name: str
    addon: str                       # role-specific system instructions
    tool_names: list[str]            # subset of the registry this specialist may use
    role: str = PLAN                 # model tier (cheap for recon, strong for exploit)
    max_steps: int = 20


RECON = SpecialistProfile(
    name="recon",
    addon=(
        "You are the RECON specialist: the team's autonomous reconnaissance "
        "workstation. Your job is to MAP the authorized attack surface "
        "thoroughly and honestly — never to exploit or confirm "
        "vulnerabilities (EXPLOIT/VERIFY own that). You MAY authenticate (log "
        "in as a basic/seeded user) purely to get past a login wall and map "
        "what is behind it; if the engagement brief hands you a ready-made "
        "token/cookie, register it with set_session instead of inventing a "
        "login. Multi-step logins: use authenticate's second_url_template.\n"
        "Work in phases, and CHECK what is already known before you repeat it "
        "(evidence_search / observations list every recorded claim with its "
        "source and validation state — re-discovering recorded work wastes "
        "steps):\n"
        "Phase A (understand): read the objective and the RoE scope in your "
        "brief; note supplied credentials/sessions; probe proxy_status to "
        "learn whether TLS is decrypted or tunneled and where captured "
        "history lives.\n"
        "Phase B (passive): passive_recon first — DNS, TLS certificate "
        "metadata (SAN domains!), robots.txt, sitemap.xml, security headers, "
        "cookie flags, technology fingerprints — all recorded with source and "
        "mode.\n"
        "Phase C (initial active mapping): surface_scan (one call, no "
        "arguments) knocks on every host/port the RoE allows and fills the "
        "asset inventory (asset_read shows what it filled); then host_probe/"
        "port_scan for fingerprinting and ports on LIVE hosts only.\n"
        "WAF RULE (critical — do NOT scan into a wall): if a curl/httpx/"
        "http_probe response is a Cloudflare or WAF challenge (a 'waf_block' "
        "flag, 'Just a moment', a 403/503 challenge page), the host is bot-"
        "protected. Retrying raw HTTP the same way will ALWAYS be blocked — stop "
        "doing it. Switch immediately to browser_navigate (a real browser passes "
        "the passive challenge) and browser_session_status to check whether the "
        "session is already warmed. If the BROWSER also hits an interactive "
        "CAPTCHA/Turnstile, report that a human must warm the session and move "
        "on — never loop on a wall.\n"
        "Phase D (browser): browse like a person — browser_navigate the entry "
        "points, browser_click/browser_fill through flows, browser_screenshot "
        "key states, and READ browser_requests (every XHR/fetch the frontend "
        "fired = real API surface) + browser_inspect_request for the "
        "interesting ones + browser_console for errors that leak routes. "
        "spa_recon walks SPA shells for API routes without credentials.\n"
        "Phase E (API + content): content_discovery (path wordlists), crawl "
        "(link/JS walk), param_discovery (hidden params), http_probe for raw "
        "API surfaces (JSON endpoints, versioned APIs, OpenAPI docs), "
        "graphql_inspect when a GraphQL endpoint answers, jwt_inspect on "
        "tokens you legitimately hold. Your EVIDENCE WORKSPACE is inspectable: "
        "proxy_history/proxy_filter and proxy_history_query re-read what the "
        "browser, proxy and tools already captured (all in one traffic log); "
        "proxy_replay / replay_request re-send a captured request under the "
        "same scope/budget/approval controls (approval-gated, no new "
        "targets).\n"
        "Phase F (corroborate): every lead from a crawler/binary is a CLAIM "
        "until a first-party method agrees — crosscheck_lead it (verdicts "
        "corroborated/contradicted/unverifiable land in the observation log); "
        "drop contradicted leads, keep unverifiable ones marked as such.\n"
        "Phase G (handoff): end with a compact structured summary — live "
        "hosts/services, entry points, technologies, endpoints with methods/"
        "params, API surfaces, auth boundaries, security-header notes, "
        "unverified leads, coverage gaps (what you could NOT test and why). "
        "The graph/observations carry your evidence to EXPLOIT/LOGIC/VERIFY.\n"
        "Discipline: use tools deliberately (never re-run the same discovery "
        "on the same target in one run), search your evidence (evidence_search "
        "/ evidence_inspect) before re-scanning, respect the RoE budget, and "
        "report honestly — partial coverage is reported as partial, never as "
        "complete."),
    tool_names=["passive_recon", "observations", "proxy_status", "proxy_history",
                "proxy_inspect", "proxy_filter", "proxy_replay",
                "surface_scan", "host_probe", "port_scan", "content_discovery",
                "crawl", "param_discovery", "spa_recon", "crosscheck_lead",
                "http_probe", "jwt_inspect", "graphql_inspect",
                "browser_navigate", "browser_content", "browser_click",
                "browser_fill", "browser_screenshot", "browser_requests",
                "browser_inspect_request", "browser_console",
                "authenticate", "set_session", "kali_exec",
                "search_peer_traces",
                "evidence_search", "evidence_inspect", "proxy_history_query",
                "replay_request", "asset_read"],
    role=PARSE,          # breadth work -> cheaper model
    max_steps=40,        # the phased recon workflow (A-G) over the full unified
                         # discovery+evidence-workspace stack (35 hands) needs
                         # more than one step per tool (test_hands enforces this)
)

EXPLOIT = SpecialistProfile(
    name="exploit",
    addon=("You are the EXPLOIT specialist. The surface is already mapped in the knowledge "
           "graph and the attack tree lists prioritized untested checks. For each, PROVE the "
           "vulnerability with a reproducing check (confirm_finding / verify_vulnerability), "
           "authenticate when needed, and chain confirmed footholds. Separate LOOKING from "
           "PROVING: use http_probe to inspect responses, validate a session, or walk an ID "
           "space — it never records anything — and only fire confirm_finding once you have "
           "a hypothesis worth proving; confirm_finding costs verification trials, probes "
           "do not. If the engagement brief hands you a ready-made token/cookie, register it "
           "with set_session instead of hand-writing headers everywhere. Bias hard toward "
           "confirming findings; do not re-map the surface. NOTE: your checks only reach "
           "pending_verification — a separate pass independently re-checks them before "
           "anything counts. That is by design; keep proving, don't try to self-promote."),
    tool_names=["find_techniques", "crosscheck_lead", "apply_skill", "confirm_finding",
                "verify_vulnerability", "authenticate", "set_session",
                "http_probe", "kali_exec", "mint_canary", "poll_canary",
                "test_access_control", "test_idor", "grade_evidence", "search_peer_traces",
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
           "every other proof tool. Use http_probe with as_session to exercise a held "
           "session against endpoints the brief names (e.g. the objective's target) — its "
           "response tells you whether the session reaches further before you spend a "
           "proving step. Use record_access only to note leads/edges you discover, not to "
           "self-grant held access. Do NOT hunt new vulnerability "
           "classes — that is the exploit specialist's job; if nothing presses further, "
           "say so and stop."),
    tool_names=["extract_secrets", "try_credential", "prove_privilege", "record_access",
                "authenticate", "set_session", "http_probe", "kali_exec",
                "browser_navigate", "browser_content"],
    role=PARSE,          # procedural/mechanical work once a path is already known -> cheaper model
    max_steps=20,
)

LOGIC = SpecialistProfile(
    name="logic",
    addon=("You are the LOGIC specialist — the team's deep-thinking attacker. This is the "
           "class of bug a scanner CANNOT find and an AI that only knows the OWASP top-10 "
           "WILL miss. Your edge is reasoning about THIS specific application, not running a "
           "payload library. The program pays MORE for these than their raw CVSS suggests.\n"
           "STEP 1 — understand the business. From the recon evidence (endpoints, params, "
           "forms, flows, the pages you can read), infer what this application actually IS "
           "and how it creates value: who are the actors (buyer/seller/admin/guest), what "
           "objects do they own (listings, orders, offers, bundles, balances, payouts, "
           "messages), and what are the MONEY and OWERSHIP and STATE-TRANSITION flows "
           "between them? Write this model down first — do not skip to attacking.\n"
           "STEP 2 — enumerate the invariants the app TRUSTS. For each flow, name what the "
           "server assumes is always true: a price is computed server-side not sent by the "
           "client; an item must be paid before it ships; escrow releases only after "
           "delivery; a user can only act on objects they own; a discount/refund/credit "
           "can't exceed what was paid; a state can't move backwards; an action can't be "
           "repeated or raced. These are app-specific — derive them from THIS domain, not a "
           "generic checklist.\n"
           "STEP 3 — attack the invariant, and CHAIN. The highest-impact findings combine "
           "a weak primitive with a flow: a guessable/mutable object reference + the refund "
           "or payout flow = money extraction; a skippable step + a trust boundary = free "
           "goods or seller fraud; a race on a balance/offer = double-spend. Reason about "
           "how a small flaw becomes financial loss or account takeover when chained, and "
           "test the CHAIN, not just the isolated primitive.\n"
           "PROVE IT with verify_workflow_abuse: an ordered attack_steps sequence (the "
           "abuse), an ordered control_steps sequence doing the SAME flow honestly (ideally "
           "with a fresh identifier), and the INVARIANT whose violation proves impact. "
           "Business logic is usually one-shot — reason the sequence out correctly rather "
           "than spraying. Use http_probe and multiple sessions (authenticate / set_session) "
           "to drive cross-account tests (act as A on B's object), but ONLY ever against "
           "objects YOU own on both sides — never a real user's data. Authenticate first if "
           "a flow needs a session. Do NOT hunt injection/XSS/access-control as technical "
           "flaws — that's EXPLOIT's job; pursue bugs where the vulnerability IS the broken "
           "business rule, especially ones with financial or trust impact."),
    tool_names=["verify_workflow_abuse", "verify_race_condition", "authenticate",
                "set_session", "http_probe",
                "browser_navigate", "browser_content", "browser_fill", "browser_click",
                "browser_login", "browser_session_status", "browser_requests",
                "browser_inspect_request", "find_techniques", "grade_evidence"],
    role=PLAN,           # requires reasoning about the specific app's domain, not pattern-matching
    max_steps=30,
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

# Phase 3 mission tasks: one role-specific line per task instruction (concise
# task scoping — the profile addon already carries the full method discipline).
_ROLE_TASK_LINES = {
    "recon": "This is a recon SLICE of the mission: map what the task names, let "
             "discoveries register in the knowledge graph, do not exploit.",
    "exploit": "Prove THIS assigned check with your class discipline; separate "
               "looking (http_probe) from proving (confirm_finding costs "
               "verification trials).",
    "access": "Press the confirmed foothold this task names — harvest, try, prove "
              "boundaries per your briefing; do not hunt new vuln classes.",
    "logic": "Probe the workflow assumption this task names with "
             "verify_workflow_abuse (ordered attack vs control steps).",
}


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
        # Live-fire regression (run 20261022-1239): in single-agent mode the model may
        # legitimately call verify_finding_independently MID-RUN, so by the time the
        # post-run pass arrives there is nothing pending — and the early return below
        # used to skip collection entirely, leaving a confirmed finding on the
        # objective's target uncollected. Crediting runs even when verification is
        # already clear; the sweep is idempotent and only ever acts on confirmed work.
        from .credit import credit_confirmed_findings
        try:
            credit_confirmed_findings(ctx)
        except Exception as exc:
            record_suppressed_error(ctx.audit, "orchestrator", "credit_failed", exc)
        return 0
    ctx.audit.record("verify_pass.start", pending=len(pending))
    subset = {n: tools[n] for n in VERIFY.tool_names if n in tools}
    verifier = RedTeamAgent(engagement, subset, ctx, client, max_steps=VERIFY.max_steps,
                            system_addon=(VERIFY.addon + "\n\n"
                                          + skills_briefing("verify", held=set(subset))),
                            role=VERIFY.role,
                            agent_name="verify")
    if budget is not None:
        verifier.with_runtime(budget=budget)
    ids = ", ".join(f.id for f in pending)
    verifier.run(
        f"{objective}\n\nThis run: VERIFY — independently re-check these pending findings "
        f"(finding_id values): {ids}. Call verify_finding_independently once per id. Do not "
        f"skip any.", on_text=on_text)
    remaining = len(ctx.findings.pending())
    ctx.audit.record("verify_pass.finish", remaining=remaining)
    # Creditor: collection is nobody's implicit job. A confirmed finding on the
    # objective's target must convert into access hold + criterion credit WITHOUT
    # depending on the model remembering to call record_access/claim_objective —
    # live-fire showed a fully-proven, independently-confirmed IDOR sitting there
    # uncollected because the final linkage never left the model's head. The sweep is
    # deterministic, gated by the same REQUIRED_SOURCE rules as everything else, and
    # idempotent (see credit.py).
    from .credit import credit_confirmed_findings
    try:
        credit_confirmed_findings(ctx)
    except Exception as exc:   # collection must never crash the pipeline
        record_suppressed_error(ctx.audit, "orchestrator", "credit_failed", exc)
    return remaining


# -- Phase B3 scheduler constants (the mu/V/SCALE rationale lives here on purpose:
#    next to the class the numbers feed, where a reviewer will look first) ----------
#
# These calibrate the drift-plus-penalty controller against ONE fixed ruler: the
# OPSEC price table attack_tree.TECHNIQUE_COST, whose entire domain is [1.0, 5.0]
# (quiet probes 1.0, mid techniques ~2.0, bulk exfil 5.0, mean 2.46 over 13
# techniques). Every constant below is anchored in that domain — nothing is magic.
#
# DEFAULT_MU = 2.0 — the sustainable per-claim loudness: the swarm's AVERAGE claim
#   may cost as much as access.control/idor (2.0) without detection pressure
#   accumulating. Claims quieter than mu repay pressure (a cost-1 probe drains the
#   queue by 1), claims louder accrue it (an exfil adds 3). This is the conservative
#   choice by construction: mu sits BELOW the table's mean (2.46), so an ordinary
#   mixed basket stays near-stable while any loud-heavy streak drifts Q up — slow to
#   forgive, quick to throttle.
#
# DEFAULT_V = 1.0 — the weight of progress (learned yield-per-cost, a Thompson draw
#   divided by cost, so bounded in [0, 1]) against the pressure term Q*cost. At V=1
#   the progress pull is at most 1 credit while any Q >= 1 makes the pressure term
#   dominate — i.e. under ANY real detection pressure the scheduler prefers stealth
#   over yield (conservative default), and at Q=0 the order is exactly the legacy
#   yield-per-cost ranking regardless of V. Overt engagements raise V toward SCALE
#   (yield competes with a fully-alerted detector); assumed-breach stealth lowers it.
#
# DEFAULT_SCALE = 4.0 — converts the belief filter's risk in [0,1] into noise-credit
#   pressure on the SAME ruler: risk=1.0 (detector effectively certain) presses as
#   hard as the loudest single technique minus one quiet probe (5 - 1 = 4); risk=0.5
#   presses like one access.control (2.0) over the sustainable rate. With the default
#   round budget of 12, a fully-alerted belief withholds a third of a round — a real
#   throttle that never paralyzes the swarm.
DEFAULT_MU = 2.0
DEFAULT_V = 1.0
DEFAULT_SCALE = 4.0


class DriftPlusPenaltyScheduler:
    """Per-round OPSEC spend controller for the exploit swarm (Phase B3; supersedes
    NoiseBudget's flat one-shot greedy knapsack, docs/multi-gambit.md §3.4).

    THE MODEL: every claim spends the technique's OPSEC price (attack_tree.
    technique_cost) from a per-round allowance, AND accrues detection pressure in a
    virtual queue — the Lyapunov drift-plus-penalty recursion

        Q(t+1) = max(Q(t) + noise_cost(a) - mu, 0)

    applied per action on try_spend() (and unwound on refund(): a lost claim race
    means no request was ever sent, so its pressure never happened). Q is a DEBT in
    noise credits: spending louder than mu borrows against the future.

    THE BLEND (where the POMDP plugs in): the pressure the controller actually acts
    on is

        Q(t) = max(raw_accumulator(t), belief_filter.risk_score(t) * SCALE)

    The raw accumulator alone would only rise after the noise was already spent; the
    belief term is the immediate override — a challenge burst observed by tools/
    http.py's hook raises risk_score within one round and the scheduler throttles
    NOW, without waiting for the queue to drift up. The raw term keeps the pressure
    honest in the other direction: a noisy-but-unnoticed streak still owes its debt.

    THE DECISION: each claim cycle, candidates from the tree's actionable frontier
    are ranked by

        score(a) = Q(t) * noise_cost(a) - V * progress_value(a)

    and the swarm walks them cheapest-score-first (min score, ascending), skipping
    candidates that don't fit the remaining allowance — the same greedy fill shape
    NoiseBudget always had, with a pressure-aware order instead of a flat one.
    progress_value is the existing yield estimate: the bandit's Thompson draw
    divided by the technique's cost (exactly BanditStore.select's score), so at
    Q=0 the ranking degenerates to the legacy yield-per-cost order — the old
    behavior is the Q=0 special case, not a lost sibling. Ties keep the tree's
    priority order (stable sort — the same equal-split tie-breaking the knapsack
    relied on). Without a bandit, progress is a constant and the order degenerates
    to the tree's order at Q=0, cheap-first under pressure.

    THE THROTTLE: the round allowance restored by reset() is
    max(mu, total - Q(t)) — pressure withholds budget one-for-one (the debt is
    denominated in the same credits), floored at mu so the swarm can always afford
    one sustainable claim and never deadlocks against its own queue.

    Thread-safe — swarm workers spend concurrently. The public interface is
    NoiseBudget's exactly (remaining / can_afford / try_spend / refund / reset);
    `NoiseBudget` remains as an alias below so every existing caller and test
    keeps working unchanged."""

    def __init__(self, total: float, *, mu: float = DEFAULT_MU, V: float = DEFAULT_V,
                 scale: float = DEFAULT_SCALE, bandit=None, belief=None):
        self._total = max(float(total), 0.0)
        self._remaining = self._total
        self._lock = threading.Lock()
        self._mu = max(float(mu), 1e-6)
        self._V = max(float(V), 0.0)
        self._scale = max(float(scale), 0.0)
        self._bandit = bandit     # BanditStore | None — progress_value's source
        self._belief = belief     # BeliefFilter | None — the POMDP side of the blend
        self._q_raw = 0.0         # raw_accumulator: the cross-round virtual queue

    # -- pressure state ------------------------------------------------------------

    def q_effective(self) -> float:
        """Q(t) = max(raw_accumulator, belief risk * SCALE) — read live so a
        challenge burst throttles the very next claim, not the next round."""
        with self._lock:
            raw = self._q_raw
        risk = 0.0
        if self._belief is not None:
            try:
                risk = float(self._belief.risk_score())
            except Exception as exc:
                record_suppressed_error(None, "orchestrator", "read_belief_risk", exc,
                                        severity="info")
                risk = 0.0   # a broken POMDP degrades to raw-queue-only, never blocks
        return max(raw, risk * self._scale)

    def _risk_snapshot(self) -> float:
        if self._belief is None:
            return 0.0
        try:
            return float(self._belief.risk_score())
        except Exception as exc:
            record_suppressed_error(None, "orchestrator", "snapshot_belief_risk", exc,
                                    severity="info")
            return 0.0

    # -- NoiseBudget-compatible accounting -------------------------------------------

    @property
    def remaining(self) -> float:
        with self._lock:
            return self._remaining

    def can_afford(self, cost: float) -> bool:
        with self._lock:
            return self._remaining >= cost - 1e-9

    def try_spend(self, cost: float) -> bool:
        """Atomically reserve `cost` from the remaining allowance AND advance the
        pressure queue one action (Q <- max(Q + cost - mu, 0)); False if it doesn't
        fit (the caller moves on to a cheaper candidate — nothing was spent)."""
        with self._lock:
            if self._remaining >= cost - 1e-9:
                self._remaining -= cost
                self._q_raw = max(self._q_raw + cost - self._mu, 0.0)
                return True
            return False

    def refund(self, cost: float) -> None:
        """Return a reservation (capped at the total — refunds can never mint
        budget that was never there) and unwind the claim's pressure step."""
        with self._lock:
            self._remaining = min(self._total, self._remaining + cost)
            self._q_raw = max(self._q_raw - cost + self._mu, 0.0)

    def reset(self) -> None:
        """Start a new round: restore the allowance, throttled by current pressure
        (max(mu, total - Q(t))) — called ONCE per exploit round. 'Per-round' is the
        documented contract (RunOptions.round_noise_budget); without the reset,
        round 0's spend starves every later round and the swarm stops exploring
        after its first claims (caught by the product E2E run of 2026-10-30: 12
        rounds started, only round 0 ever claimed). The PRESSURE QUEUE is
        deliberately NOT reset — cross-round memory is the entire point; only the
        round's bookkeeping allowance starts whole."""
        with self._lock:
            # Hard cap first (the round budget is a CONTRACT — spend must never
            # exceed total), then the pressure throttle, then the mu floor so the
            # swarm can always afford one sustainable claim (only meaningful when
            # total > mu; the cap always wins).
            self._remaining = min(self._total, max(self._mu, self._total
                                                   - max(self._q_raw, self._risk_snapshot() * self._scale)))

    # -- candidate ranking (replaces the flat greedy knapsack order) ------------------

    def rank(self, candidates: list[tuple]) -> list[dict]:
        """Score candidates by drift-plus-penalty and return them cheapest-score
        first. `candidates` are (technique, bucket, cost) or (technique, bucket,
        cost, meta) tuples exactly like BanditStore.select takes; a meta is
        returned verbatim on the item. score(a) = Q*cost - V*progress with
        progress = Thompson draw / cost when a bandit is attached (one draw per
        candidate, input order — so a fixed seed reproduces BanditStore.select's
        draws and, at Q=0, its exact order), else a constant (order = tree order
        at Q=0, cheap-first under pressure). Stable sort: equal scores keep the
        tree's priority order — the knapsack's equal-split tie-breaking."""
        q = self.q_effective()
        scored: list[dict] = []
        for item in candidates:
            if len(item) == 4:
                technique, bucket, cost, meta = item
                has_meta = True
            else:
                technique, bucket, cost = item
                meta, has_meta = None, False
            cost = max(float(cost), 1e-6)
            draw = None
            if self._bandit is not None:
                try:
                    draw = float(self._bandit.sample(technique, bucket))
                except Exception as exc:
                    record_suppressed_error(None, "orchestrator", "sample_bandit_prior", exc,
                                            severity="info", technique=technique, bucket=bucket)
                    draw = None
            progress = (draw / cost) if draw is not None else 1.0
            entry = {"technique": technique, "bucket": bucket, "cost": cost,
                     "progress": progress, "score": q * cost - self._V * progress}
            if draw is not None:
                entry["draw"] = draw
            if has_meta:
                entry["meta"] = meta
            scored.append(entry)
        scored.sort(key=lambda s: s["score"])   # stable — ties keep tree order
        return scored


# Backward-compatibility alias: NoiseBudget's public interface is the scheduler's
# accounting subset, and every existing caller/test imports this name. The class
# above IS the replacement; this alias IS the contract that nothing else had to move.
NoiseBudget = DriftPlusPenaltyScheduler


class Orchestrator:
    def __init__(self, engagement: Engagement, tools: dict[str, Tool], ctx: ToolContext,
                 client: OpenRouterClient, graph=None, attack_tree=None, memory=None,
                 max_exploit_rounds: int = 12, max_access_rounds: int = 4,
                 max_swarm_workers: int = 3, noise_budget: float | None = None,
                 detection=None, noise_mu: float | None = None,
                 noise_V: float | None = None,
                 research_dir: str | Path | None = None):
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
        # Phase B3 — the detection belief (POMDP over the defender's state): adopt one
        # wired by the caller (run.py / tests) or create our own, and expose it on the
        # shared ToolContext so tools/http.py's observation hook feeds THE SAME filter
        # the scheduler reads. Every multi-agent run gets the filter (the hook is
        # best-effort and costs nothing); only the scheduler CONSUMES it.
        self._detection = detection or getattr(ctx, "detection", None) or BeliefFilter()
        try:
            if getattr(ctx, "detection", None) is not self._detection:
                ctx.detection = self._detection
        except Exception as exc:
            record_suppressed_error(getattr(ctx, "audit", None), "orchestrator",
                                    "attach_detection_context", exc, severity="info")
        # Per-round OPSEC budget (docs/multi-gambit.md §3.4): None/0 = unlimited
        # spend (exact legacy behavior); a positive value drives the
        # DriftPlusPenaltyScheduler — per-round allowance, drift-plus-penalty claim
        # ordering (Q*cost - V*progress), and the POMDP blend that throttles the
        # swarm when the belief filter sees the defender reacting. mu/V default to
        # the calibrated module constants; run.py exposes both as per-run knobs
        # (RunOptions.noise_mu / noise_V) for per-engagement tuning.
        self._noise = None
        if noise_budget and noise_budget > 0:
            self._noise = DriftPlusPenaltyScheduler(
                noise_budget,
                mu=DEFAULT_MU if noise_mu is None else max(float(noise_mu), 1e-6),
                V=DEFAULT_V if noise_V is None else max(float(noise_V), 0.0),
                bandit=getattr(attack_tree, "bandit", None),
                belief=self._detection)
        self._budget = None
        self._manifest = None
        # Reflection state defaults (re-created fresh per run() — a new engagement
        # starts with clean reflections; these exist so direct method use never
        # hits an attribute error).
        self._reflections: list[dict] = []
        self._reflection_notes: list[str] = []
        # Phase B5 defaults (re-created fresh per run() — a new engagement starts
        # with a clean strategy state; these exist so direct method use in tests
        # never hits an attribute error).
        self._strategy = EngagementStrategy()
        self._round_claims: list[str] = []
        self._confirmed_seen: set = set()   # tree node ids already fed to the ledger
        # Phase C1 — collective intelligence layer (redteam/swarm/, ADR-001): a
        # run-scoped hypothesis registry + research forum. research_dir=None keeps
        # it in-memory (zero file I/O — legacy callers and direct-construction tests
        # are unchanged); run.py passes the run dir so a killed run replays.
        # The bundle is per-Orchestrator (per engagement) — no global state.
        self._research = ResearchBundle.for_run(
            str(getattr(engagement, "name", "") or "engagement"),
            run_dir=research_dir, bus=getattr(ctx, "events", None))
        self._research_hyp_by_node: dict[str, str] = {}       # tree node id -> hypothesis id
        self._research_finding_hyp: dict[str, str] = {}       # finding id -> hypothesis id
        self._research_verdicts_seen: dict[str, str] = {}     # finding id -> last mirrored confidence
        # Run directory for inspectable artifacts (thesis.jsonl). None keeps the
        # thesis layer purely in-memory, same policy as the research bundle.
        self._run_dir = Path(research_dir) if research_dir else None

    def with_runtime(self, budget=None, manifest=None, manifest_path=None,
                     terminal_manifest_writes: bool = True):
        """Attach a BudgetTracker and/or a RunManifest for autonomous runs.

        terminal_manifest_writes=False marks every specialist THIS orchestrator
        builds as a task-scoped manifest writer (mission mode): they update
        steps/tokens/findings on the shared run manifest but never its run-level
        status — the mission driver owns the terminal state."""
        self._budget = budget
        self._terminal_manifest_writes = terminal_manifest_writes
        if manifest is not None and manifest_path is not None:
            self._manifest = (manifest, manifest_path)
        return self

    @property
    def ctx(self) -> ToolContext:
        """Read-only access to the run's shared ToolContext for composition
        layers built ON the orchestrator (Phase 3: the mission executor diffs
        the shared FindingStore and audit for real evidence refs). This is the
        SAME context every specialist runs with — exposing it creates no
        second authority."""
        return self._ctx

    def _make_specialist(self, profile: SpecialistProfile, addon_suffix: str = "",
                         agent_name: str | None = None,
                         max_steps: int | None = None) -> RedTeamAgent:
        # Give the specialist only its allowed tools that actually exist in the registry.
        subset = {n: self._tools[n] for n in profile.tool_names if n in self._tools}
        # Phase E1 hands: a profile name that is neither held nor an OPTIONAL (browser/
        # sandbox disabled) tool used to drop SILENTLY here — the A10/surface_scan class
        # of drift, invisible until a worker needed the hand. Now it is fail-OBSERVABLE:
        # the static discipline (profile.tool_names == HANDS[agent], tools exist) is
        # enforced fail-loud by tests/test_hands.py; at runtime the drop is audited so
        # a live run shows exactly which hand a specialist was promised and lost.
        unheld = [n for n in profile.tool_names
                  if n not in self._tools and n not in OPTIONAL_TOOLS]
        if unheld:
            self._ctx.audit.record("specialist.hands.unheld", specialist=profile.name,
                                   unheld=unheld)
        # The hands/skills briefing: what each held tool costs and may be trusted as,
        # and which declared procedures the agent may execute — filtered to hands the
        # agent can actually raise (a briefing teaching an unraisable hand is the
        # same drift again).
        addon = (profile.addon + addon_suffix + "\n\n"
                 + hands_briefing(profile.name, subset) + "\n\n"
                 + skills_briefing(profile.name, held=set(subset)))
        # agent_name override: the swarm gives each concurrent worker a UNIQUE telemetry
        # identity (exploit-w0, exploit-w1, ...) so peer-trace search can attribute
        # observations to a specific sibling hypothesis. Without it every worker shows
        # up as the same "exploit" role and "peer" means nobody in particular.
        agent = RedTeamAgent(self._eng, subset, self._ctx, self._client,
                             max_steps=(profile.max_steps if max_steps is None
                                        else max(int(max_steps), 1)),
                             graph=self._graph,
                             attack_tree=self._attack_tree, memory=self._memory,
                             system_addon=addon, role=profile.role,
                             agent_name=agent_name or profile.name,
                             terminal_manifest_writes=getattr(
                                 self, "_terminal_manifest_writes", True))
        if self._budget is not None:
            mpath = self._manifest[1] if self._manifest else None
            manifest = self._manifest[0] if self._manifest else None
            agent.with_runtime(budget=self._budget, manifest=manifest, manifest_path=mpath)
        return agent

    def _evidence_digest(self) -> tuple[str, set[str]]:
        """A compact, model-readable picture of what recon observed — the input
        the thesis generator reasons over. Returns (digest_text, endpoint_keys)
        where the keys ground the evidence-support score in thesis.py."""
        if self._graph is None:
            return "", set()
        from .knowledge import ENDPOINT, PARAMETER, TECHNOLOGY, SERVICE, HOST
        lines: list[str] = []
        keys: set[str] = set()

        def _sample(kind, label, cap=40):
            rows = []
            try:
                for n in self._graph.nodes(kind):
                    rows.append(n)
                    if len(rows) >= cap:
                        break
            except Exception as exc:
                record_suppressed_error(self._ctx.audit, "orchestrator", "sample_graph_nodes", exc,
                                        severity="info", node_kind=kind)
                return
            if rows:
                lines.append(f"{label} ({len(rows)}{'+' if len(rows) >= cap else ''}):")
                for n in rows:
                    attrs = n.attrs or {}
                    extra = ""
                    method = str(attrs.get("method", "")).upper()
                    if method:
                        extra += f" [{method}]"
                    if attrs.get("form_params"):
                        extra += f" form_params={list(attrs['form_params'])[:8]}"
                    if attrs.get("title"):
                        extra += f" title={str(attrs['title'])[:60]!r}"
                    lines.append(f"  - {n.key}{extra}")
                    if kind == ENDPOINT:
                        keys.add(n.key.lower())

        _sample(HOST, "Hosts")
        _sample(SERVICE, "Services")
        _sample(TECHNOLOGY, "Technologies")
        _sample(ENDPOINT, "Endpoints", cap=60)
        _sample(PARAMETER, "Parameters", cap=40)
        return "\n".join(lines), keys

    def _generate_theses(self, lens: str, objective: str, on_text=None):
        """Generate, log and brief ranked attack theses for a lens
        ('exploit'|'logic'). Returns the briefing string ('' on any failure —
        the run is lifted by theses, never dependent on them)."""
        try:
            digest, keys = self._evidence_digest()
            world_model = getattr(self._ctx, "world_model", None)
            projection = None
            if world_model is not None:
                traffic_path = (self._run_dir / "traffic.jsonl") if self._run_dir else None
                refresh = world_model.refresh_from_sources(
                    getattr(self._ctx, "evidence_store", None), traffic_path)
                projection = world_model.compact_projection()
                facts = projection.get("facts", [])
                if facts:
                    # The typed projection replaces the old raw text digest in
                    # the model prompt. Keep its keys only for thesis grounding.
                    digest = ""
                    for fact in facts:
                        if fact.get("key"):
                            keys.add(str(fact["key"]))
                        keys.update(str(ref) for ref in fact.get("evidence_ref_ids", []))
                self._ctx.audit.record(
                    "world_model.refreshed", lens=lens, facts=len(facts), **refresh)
            if not digest and not (projection and projection.get("facts")):
                return ""
            theses = generate_theses(
                self._client, lens=lens, evidence_digest=digest,
                evidence_keys=keys, objective_text=objective,
                log=self._ctx.audit.record, world_model_projection=projection)
            if not theses:
                return ""
            # Persist the inspectable artifact next to the run's other evidence.
            if self._run_dir:
                write_theses(self._run_dir / "thesis.jsonl", theses)
            # Seed the attack tree from the THESIS's own technique — including
            # classes NOT in the static catalog. This is how the agent's
            # target-specific reasoning, not a predefined menu, decides what gets
            # tested: a novel technique id becomes a first-class frontier item the
            # generic EXPLOIT profile works (profile_for falls back to EXPLOIT for
            # unknown ids). The thesis score boosts its priority so a strong,
            # target-specific bet outranks the generic entry techniques.
            if self._attack_tree is not None:
                for t in theses:
                    if not (t.technique and t.target):
                        continue
                    try:
                        self._attack_tree.seed_technique(t.technique, t.target)
                        # Lift this node on the frontier by its thesis score (the
                        # strategist-boost channel only reorders in-scope work).
                        boost = getattr(self._attack_tree, "_strategy_boost", None)
                        if boost is not None:
                            boost[f"{t.technique}@{t.target}"] = 50.0 + 50.0 * float(t.score)
                    except Exception as exc:
                        record_suppressed_error(self._ctx.audit, "orchestrator",
                                                "apply_thesis_priority", exc)
            if on_text and theses:
                on_text(f"[thesis:{lens}] top bet ({theses[0].score:.2f}): "
                        f"{theses[0].belief[:140]}")
            return theses_briefing(theses)
        except Exception as exc:
            record_suppressed_error(self._ctx.audit, "orchestrator",
                                    "generate_thesis_brief", exc, lens=lens)
            return ""

    # -- Phase 3: mission task-level execution -----------------------------------
    # One task, one specialist, NO phase sequence. The mission scheduler owns
    # the claim trio (task reservation, AttackTree claim, hypothesis claim)
    # BEFORE this is called — execute_task neither claims nor releases
    # anything, never calls _run_exploit_swarm(), and never restarts recon,
    # verification, or other phases per dispatch. It is the same specialist
    # construction machinery run() uses, aimed at exactly one assigned task.

    def execute_task(self, task_view: dict, on_text=None, objective: str = "") -> str:
        """Execute ONE mission task through the existing specialist machinery.

        Routing (the EXISTING authorities, no second registry):
          recon   -> RECON
          exploit -> profile_for(technique) — the class-specialist router —
                     falling back to the generic EXPLOIT profile
          access  -> ACCESS
          logic   -> LOGIC
          verify  -> the existing independent verification pass
                     (run_verify_pass: fresh VERIFY context, existing
                     FindingStore; the only confirmation authority)

        Step budget: the task's execution-plane carve, never widening the
        specialist profile's own ceiling (min(task max_steps, profile
        max_steps)). Engagement-level budget/OPSEC/request limits stay with
        the shared BudgetTracker and ScopeGuard the agent already runs under.

        Returns the agent's final text. A clean return is an EXECUTION outcome
        only (C4) — it never implies a confirmed finding or a completed tree
        node. Raises on construction/routing errors; the mission executor maps
        exceptions to EXEC_FAILED and the scheduler fences the task failure.
        """
        role = str(task_view.get("role", "") or "")
        task_id = str(task_view.get("task_id", "") or "")
        if role == "verify":
            return self._execute_verify_task(task_view, on_text=on_text,
                                             objective=objective)
        if role == "access":
            # Correction gate: the ACCESS specialist's method assumes a
            # demonstrated foothold to press. Mission-plan dependencies do not
            # PROVE access was obtained — only the existing AccessGraph /
            # KillChain evidence does. Without it no specialist is constructed
            # or run; the scheduler's readiness gate keeps the task PENDING
            # (the same not-ready semantics dependencies use) until a foothold
            # is demonstrated.
            reason = self.access_precondition_reason(task_view)
            if reason:
                raise ValueError(
                    f"access prerequisite not met — task stays blocked, no "
                    f"specialist constructed: {reason}")
        profile, step_budget = self._profile_for_task(task_view)
        instruction = self._task_instruction(task_view, profile, step_budget,
                                             objective=objective)
        agent = self._make_specialist(profile, agent_name=f"mission-{task_id}",
                                      max_steps=step_budget)
        self._ctx.audit.record("mission.task.execute", task_id=task_id, role=role,
                               specialist=profile.name, max_steps=step_budget,
                               technique=task_view.get("technique", ""),
                               target=task_view.get("target", ""))
        return agent.run(instruction, on_text=on_text)

    def _profile_for_task(self, task_view: dict) -> tuple[SpecialistProfile, int]:
        """Role -> existing SpecialistProfile (+ the task's step carve). Exploit
        routes through the existing class-specialist router; unknown roles fail
        loud instead of inventing a specialist."""
        role = str(task_view.get("role", "") or "")
        if role == "recon":
            profile = RECON
        elif role == "access":
            profile = ACCESS
        elif role == "logic":
            profile = LOGIC
        elif role == "exploit":
            # The existing router: class expert per technique, generic EXPLOIT
            # fallback (specialists.profile_for — NOT a second mapping).
            profile = profile_for(task_view.get("technique") or None)
        else:
            raise ValueError(
                f"mission task role {role!r} has no specialist routing "
                f"(expected recon|exploit|access|logic|verify)")
        # C3: the task's execution-plane carve can only TIGHTEN the profile's
        # own ceiling — a task-level limit never widens engagement permissions.
        task_steps = int(task_view.get("max_steps", 0) or 0)
        step_budget = profile.max_steps if task_steps <= 0 else min(task_steps,
                                                                    profile.max_steps)
        return profile, step_budget

    def _task_instruction(self, task_view: dict, profile: SpecialistProfile,
                          step_budget: int, *, objective: str = "") -> str:
        """Concise task-scoped instruction from the task view — NOT the whole
        mission plan, no invented targets, no scope widening."""
        role = task_view.get("role", "")
        technique = task_view.get("technique", "")
        target = task_view.get("target", "")
        lines = [f"{objective}\n\nThis run: ONE mission task." if objective
                 else "This run: ONE mission task."]
        lines.append(f"TASK: {task_view.get('title', '')} ({task_view.get('task_id', '')})")
        lines.append(f"YOUR ROLE: {profile.name} — execute ONLY this assigned task.")
        if technique and target:
            lines.append(f"ASSIGNED CHECK: {technique} on {target}. The attack-tree "
                         f"node is ALREADY claimed by the mission scheduler — do the "
                         f"work; do not claim or release the node.")
        elif target:
            lines.append(f"TARGET: {target} — in-scope targets only (the RoE scope "
                         f"guard is authoritative); never invent or widen targets.")
        lines.append(f"STEP BUDGET: at most {step_budget} steps for this task.")
        lines.append(_ROLE_TASK_LINES.get(role, ""))
        lines.append("Your checks only reach pending_verification — the independent "
                     "verification pass confirms; do not self-promote.")
        return "\n".join(line for line in lines if line)

    def _execute_verify_task(self, task_view: dict, on_text=None,
                             objective: str = "") -> str:
        """Mission verify role: the EXISTING independent verification pass —
        a fresh VERIFY context over the shared FindingStore. The specialist
        that proposed a finding never self-confirms; a pass with nothing
        pending is an honest no-op, and promotion stays inside
        FindingStore.promote."""
        task_id = str(task_view.get("task_id", "") or "")
        pending = self._ctx.findings.pending()
        if not pending:
            self._ctx.audit.record("mission.verify.nothing_pending", task_id=task_id)
            return ("verification task complete: no pending findings — nothing to "
                    "verify (the independent verifier remains the only "
                    "confirmation authority)")
        self._ctx.audit.record("mission.verify.start", task_id=task_id,
                               pending=len(pending))
        still_pending = run_verify_pass(self._eng, self._tools, self._ctx,
                                        self._client,
                                        objective or str(task_view.get("title", "")),
                                        budget=self._budget, on_text=on_text)
        self._ctx.audit.record("mission.verify.finish", task_id=task_id,
                               remaining=still_pending)
        return (f"independent verification pass complete: {len(pending)} pending "
                f"finding(s) re-checked, {still_pending} still pending "
                f"(verdicts recorded by the existing pipeline)")

    # -- ACCESS prerequisite gate (foothold required before pressing) -----------
    # The check reads ONLY the existing authorities: the shared AccessGraph
    # (held nodes are "demonstrated, not assumed" — the same evidence the
    # classic ACCESS loop consumes via killchain.recommend()) or the
    # KillChain's INITIAL_ACCESS stage. No new foothold store, graph, state
    # machine, or authority.
    #
    # Intended foothold lifecycle (all of it on the existing authorities —
    # the SINGLE canonical invalidation path is PR #13's retest-fixed bridge):
    #   demonstrated  — access.hold() (tools, or the creditor on a confirmed
    #                   finding, which stamps structured finding_id provenance)
    #                   sets held=True; the KillChain may journal the
    #                   INITIAL_ACCESS milestone.
    #   invalidated   — a retest verdict of FIXED, through retest.py's
    #                   invalidate_after_fix(), revokes the holdings the
    #                   finding demonstrably supported via the graph's own
    #                   lifecycle: AccessGraph.revoke() (held=False, with
    #                   invalidated_at/invalidation_reason and the evidence
    #                   retained — node.revoked()/revoked_nodes() is the
    #                   record). The KillChain stage is deliberately NOT
    #                   auto-demoted: it journals what WAS achieved.
    #   gate          — active holdings win; a revoked holding CONTRADICTS
    #                   the historical stage, so the gate fails closed (an
    #                   achieved INITIAL_ACCESS must never stand in for a
    #                   foothold current evidence says is gone); only a graph
    #                   with no revocation record (or no graph at all) may
    #                   fall back to the achieved stage. Re-demonstration
    #                   (hold() re-activation) re-opens the gate.

    def access_precondition_reason(self, task_view: dict) -> str:
        """Why an ACCESS task must NOT dispatch yet ("" = proceed).

        Scoped to the access role — every other role proceeds unchanged. A
        valid, demonstrated, ACTIVE foothold — an AccessGraph node with
        held=True, or — when the graph carries no revocation record — a
        KillChain INITIAL_ACCESS stage marked achieved — satisfies the gate.
        A revoked holding (held=False, invalidated_at set, evidence retained)
        never does, and its record overrides the achieved stage (fail closed)
        until a foothold is demonstrated again. Wired by run.py into the
        mission scheduler's readiness gate, which keeps the task PENDING
        (existing lifecycle semantics) until satisfied; execute_task also
        enforces it directly so the specialist can never be constructed
        without a foothold.
        """
        if str(task_view.get("role", "") or "") != "access":
            return ""                     # the gate is access-only
        if self._active_foothold():
            return ""
        access = getattr(self._ctx, "access", None)
        killchain = getattr(self._ctx, "killchain", None)
        if access is None and killchain is None:
            return "no access evidence authorities on the shared context"
        if access is not None and access.revoked_nodes():
            return ("foothold invalidated: the AccessGraph carries a "
                    "demonstrated-then-revoked holding (e.g. a FIXED retest) "
                    "and the achieved INITIAL_ACCESS stage must not stand in "
                    "for it — demonstrate a foothold again to proceed")
        return ("no demonstrated foothold: the shared AccessGraph holds no "
                "active node and KillChain INITIAL_ACCESS is not achieved")

    def _active_foothold(self) -> bool:
        access = getattr(self._ctx, "access", None)
        if access is not None:
            if access.held():
                return True
            # Current evidence AGAINST the foothold: a demonstrated-then-
            # revoked holding (e.g. the retest-fixed bridge's invalidate_
            # after_fix) contradicts the historical KillChain milestone —
            # never let the stale stage stand in for it.
            if access.revoked_nodes():
                return False
        killchain = getattr(self._ctx, "killchain", None)
        return (killchain is not None
                and killchain.status(INITIAL_ACCESS) == ACHIEVED)

    # -- telemetry --------------------------------------------------------------

    def _emit(self, etype: str, **fields) -> None:
        bus = getattr(self._ctx, "events", None)
        if bus is not None:
            try:
                bus.emit(etype, role="orchestrator", **fields)
            except Exception as exc:
                record_suppressed_error(self._ctx.audit, "orchestrator",
                                        "emit_event", exc, event_type=etype)

    def _phase(self, phase: str, **extra) -> None:
        self._ctx.audit.record("orchestrator.phase", phase=phase, **extra)
        self._emit("phase.change", phase=phase, **extra)

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
        # The evidence-join layer (redteam/synthesis.py): deterministic composition of
        # run observations into per-(technique, target) attack ideas. This does NOT
        # select — the tree's actionable()/claim() order is untouched — it ENRICHES
        # whatever a worker claims, so the claim -> worker handoff carries evidence and
        # a draft check instead of a bare pair plus one generic sentence. Failure here
        # degrades to an audit record; the swarm runs exactly as before.
        idea_map: dict = {}
        try:
            from .synthesis import synthesize
            for idea in synthesize(self._ctx):
                idea_map[(idea.technique, idea.target)] = idea
            if idea_map:
                self._ctx.audit.record(
                    "synthesis.round", round=round_no, ideas=len(idea_map),
                    top=[f"{t} on {tg}" for (t, tg) in list(idea_map)[:3]])
        except Exception as exc:
            record_suppressed_error(self._ctx.audit, "orchestrator", "synthesis_round", exc, stage="round")
        if self._noise is not None:
            self._noise.reset()   # per-ROUND allowance: throttled by current pressure
            self._emit("scheduler.state", round=round_no,
                       q=round(self._noise.q_effective(), 4),
                       risk=round(self._detection.risk_score(), 4),
                       allowance=round(self._noise.remaining, 4))

        def worker(worker_id: int) -> str:
            summary = ""
            # Each worker claims its OWN next item each time through the loop (not a
            # fixed slice assigned upfront) so a fast worker that finishes its hypothesis
            # quickly picks up the next untried one instead of sitting idle while a
            # slower sibling is still on its first.
            while True:
                claimed = None
                nodes = self._attack_tree.actionable(limit=self._max_swarm_workers * 4)
                if not nodes:
                    break
                if self._noise is not None:
                    # Drift-plus-penalty claim order (Phase B3, docs/multi-gambit.md
                    # §3.4): the tree's frontier is re-sorted by Q*cost - V*progress,
                    # so at zero pressure the swarm buys the highest learned yield-
                    # per-cost first (the legacy bandit order), and under detection
                    # pressure (raw queue or the belief filter's POMDP) it pivots to
                    # quiet gambits. Candidates still come ONLY from the tree's
                    # actionable frontier — the scheduler reorders in-scope work,
                    # it never creates, authorizes, or widens anything.
                    ranked = self._noise.rank(
                        [(n.technique, n.bucket, technique_cost(n.technique), n)
                         for n in nodes])
                    for item in ranked:
                        node, cost = item["meta"], item["cost"]
                        if not self._noise.try_spend(cost):
                            continue   # doesn't fit the remaining allowance — a cheaper one may
                        if self._attack_tree.claim(node.technique, node.target):
                            claimed = node
                            break
                        self._noise.refund(cost)   # lost the claim race — allowance and pressure back
                else:
                    for node in nodes:
                        if self._attack_tree.claim(node.technique, node.target):
                            claimed = node
                            break
                if claimed is None:
                    break   # nothing left unclaimed/affordable — this worker is done
                # Phase C1 — the claimed (technique, target) becomes a registered,
                # atomically-claimed research hypothesis (redteam/swarm). A lost
                # registry claim means a live sibling owns the equivalent hypothesis:
                # do not double-investigate — release the noise reservation, mark the
                # tree node FAILED (unclaimable for THIS round, retryable next round,
                # same rationale as the empty-attempt FAILED below) and move on. A
                # research-layer ERROR never suppresses work: the swarm proceeds
                # exactly as Gen-1 did (degrade to audit record, never crash).
                hyp, suppressed = self._research_claim_for_node(claimed, worker_id,
                                                                idea=idea_map.get(
                                                                    (claimed.technique,
                                                                     claimed.target)))
                if suppressed:
                    if self._noise is not None:
                        self._noise.refund(technique_cost(claimed.technique))
                    self._attack_tree.mark(claimed.technique, claimed.target, FAILED)
                    continue
                # Phase B5: the strategy ledger's claim evidence comes straight from
                # the claim loop (list.append is atomic under the GIL — swarm workers
                # race here, and a torn count is impossible).
                self._round_claims.append(claimed.technique)
                self._emit("swarm.claim", worker=worker_id, round=round_no,
                           technique=claimed.technique, target=claimed.target)
                if self._budget is not None:
                    try:
                        self._budget.check()
                    except Exception as exc:
                        record_suppressed_error(self._ctx.audit, "orchestrator", "check_worker_budget", exc,
                                                severity="info", worker_id=worker_id)
                        break
                technique = TECHNIQUES.get(claimed.technique)
                desc = technique.description if technique else claimed.technique
                # Phase C1: track finding identity (not just count) so the swarm's
                # own hypothesis gets the finding attached as evidence afterward.
                findings_before_ids = {f.id for f in self._ctx.findings.all()}
                # Gen-3 class routing: every claimed hypothesis goes to the OWASP class
                # expert that owns the technique (see specialists.py) — claim/noise/
                # verify machinery unchanged. Unowned techniques still run the generic
                # EXPLOIT profile, and RED_CLASS_SPECIALISTS=0 disables routing outright
                # (the specialists-vs-generalist A/B switch).
                profile = profile_for(claimed.technique)
                research_note = self._research_note_for(hyp)
                idea_brief = ""
                idea = idea_map.get((claimed.technique, claimed.target))
                if idea is not None:
                    try:
                        from .synthesis import brief
                        idea_brief = "\n\n" + brief(idea)
                    except Exception as exc:
                        record_suppressed_error(self._ctx.audit, "orchestrator", "format_synthesis_brief", exc,
                                                severity="info", technique=claimed.technique)
                        idea_brief = ""
                exploit = self._make_specialist(
                    profile, agent_name=f"{profile.name}-w{worker_id}",
                    addon_suffix=f"\n\nYOUR ASSIGNED TARGET THIS TURN: "
                    f"{claimed.technique} on {claimed.target} — {desc}. Work ONLY this "
                    f"hypothesis; other workers are covering the rest of the attack tree "
                    f"in parallel. You are {profile.name}-w{worker_id}: if you need context "
                    f"you don't have (an error body, a token shape, whether a sibling already "
                    f"looked here), search_peer_traces shows what the OTHER workers' raw "
                    f"tool activity actually saw — hits are leads, prove them yourself."
                    + (f"\n\nRESEARCH BRIEFING (run-scoped hypothesis registry — this is "
                       f"recorded context, not proof; every claim still needs YOUR proof "
                       f"through the normal pipeline):\n{research_note}" if research_note else "")
                    + idea_brief)
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
                new_findings = [f for f in self._ctx.findings.all()
                                if f.id not in findings_before_ids]
                # Phase C1: the swarm's hypothesis gets the attempt's outcome attached —
                # evidence + AWAITING_VERIFICATION on a landed finding, counter-evidence
                # + lease release on an empty attempt (the next round's briefing then
                # says "prior attempts exist", turning wasted work into reusable context).
                self._research_after_attempt(claimed, worker_id, round_no, new_findings)
                if not new_findings:
                    self._attack_tree.mark(claimed.technique, claimed.target, FAILED)
            return summary

        summary = ""
        with ThreadPoolExecutor(max_workers=n_workers) as pool:
            futures = [pool.submit(worker, i) for i in range(n_workers)]
            for fut in as_completed(futures):
                try:
                    summary = fut.result() or summary
                except Exception as exc:
                    record_suppressed_error(self._ctx.audit, "orchestrator", "swarm_worker", exc)
        return summary

    # -- Phase C1: collective-intelligence plumbing (redteam/swarm/, ADR-001) -----
    #
    # Three rules govern every helper below:
    #   1. The registry records research; it never selects, authorizes, or widens
    #      work — the attack tree remains the only selector (its deterministic
    #      actionable()/claim() order is untouched).
    #   2. The independent verification pipeline remains the ONLY authority over
    #      confidence: CONFIRMED/REFUTED on a hypothesis is a mirror of
    #      FindingStore verdicts, never a cause of them.
    #   3. A research-layer failure degrades to an audit record — the swarm runs
    #      exactly as Gen-1 did when the registry/forum is unavailable.

    def _research_claim_for_node(self, node, worker_id, idea=None):
        """Find-or-register + atomically claim the hypothesis for a claimed tree node.

        `idea` (optional) is a synthesis.AttackIdea for this (technique, target): its
        expected_behavior/proposed_test ride into the registry's own slots, and its
        evidence observations attach as EvidenceRefs (kind=observation, source=synthesis)
        so the hypothesis records WHY the node looked attackable — the rationale chain
        survives the run, not just the verdict.

        Returns (hypothesis, suppressed):
          (hyp, False)  — the worker owns the hypothesis; proceed (with briefing).
          (None, True)  — a live sibling owns the equivalent hypothesis; the caller
                          suppresses this duplicate investigation.
          (None, False) — research layer failed; the caller proceeds unresearched
                          (degrade, never crash).
        """
        agent = f"exploit-w{worker_id}"
        try:
            technique = TECHNIQUES.get(node.technique)
            claim_text = (f"{node.technique} on {node.target}"
                          + (f": {technique.description}" if technique else ""))
            hyp, _ = self._research.claim_or_register(
                asset_ref=node.target,
                weakness_class=weakness_for_technique(node.technique),
                claim=claim_text, agent=agent, technique=node.technique,
                expected_behavior=(idea.expected_behavior if idea is not None else ""),
                proposed_test=(idea.proposed_test if idea is not None else ""))
            if hyp is None:
                self._ctx.audit.record("research.duplicate_suppressed",
                                       technique=node.technique, target=node.target,
                                       worker=agent)
                return None, True
            self._research_hyp_by_node[node.id] = hyp.hypothesis_id
            if idea is not None and getattr(idea, "evidence", None):
                try:
                    for i, obs in enumerate(idea.evidence):
                        self._research.registry.attach_evidence(
                            hyp.hypothesis_id,
                            EvidenceRef(evidence_id=f"ev-syn-{node.id}-{i}",
                                        kind="observation", origin="agent",
                                        source_agent="synthesis",
                                        artifact_ref=str(obs.ref)[:200],
                                        summary=f"[{obs.source}/{obs.kind}] "
                                                f"{str(obs.detail)[:180]}",
                                        ts=self._research_ts()),
                            agent)
                except Exception as exc:
                    record_suppressed_error(self._ctx.audit, "orchestrator", "research_synthesis_evidence", exc,
                                            hypothesis_id=hyp.hypothesis_id)
            return hyp, False
        except SwarmError as exc:      # registry-level issue (e.g. malformed target)
            record_suppressed_error(self._ctx.audit, "orchestrator", "research_claim", exc,
                                    technique=node.technique)
            return None, False
        except Exception as exc:       # forum/journal trouble must never break a run
            record_suppressed_error(self._ctx.audit, "orchestrator", "research_claim", exc,
                                    technique=node.technique)
            return None, False

    def _research_note_for(self, hyp) -> str:
        """Bounded research briefing for the specialist (prior attempts, sibling
        hypotheses, forum observations). Empty string = nothing worth saying."""
        if hyp is None:
            return ""
        return self._research.worker_note(hyp)

    def _research_after_attempt(self, node, worker_id: int, round_no: int,
                                new_findings: list) -> None:
        """Attach the attempt's outcome to the node's hypothesis: landed findings
        become evidence + AWAITING_VERIFICATION (the hypothesis is no longer being
        worked — verification owns it now); an empty attempt becomes counter-evidence
        and the lease is released so a later round can re-claim with full history."""
        if node.id not in self._research_hyp_by_node:
            return
        hyp_id = self._research_hyp_by_node[node.id]
        agent = f"exploit-w{worker_id}"
        try:
            if new_findings:
                for f in new_findings:
                    self._research.registry.attach_evidence(
                        hyp_id,
                        EvidenceRef(evidence_id=f"ev-finding-{f.id}", kind="finding",
                                    origin="agent", source_agent=agent,
                                    artifact_ref=f.id,
                                    summary=f"{f.severity}: {f.title} @ {f.target}",
                                    ts=self._research_ts()),
                        agent)
                    self._research.registry.set_status(
                        hyp_id, AWAITING_VERIFICATION, agent, finding_id=f.id,
                        reason=f"finding {f.id} landed; awaiting independent verification")
                    self._research_finding_hyp[f.id] = hyp_id
                    self._research.forum.publish(
                        "observation.created", source_agent=agent,
                        payload={"hypothesis_id": hyp_id, "summary": f"finding {f.id} "
                                 f"({f.severity}): {f.title} @ {f.target}",
                                 "origin": "agent"},
                        agent_role="exploit", subject_hypothesis_id=hyp_id,
                        asset_ref=node.target)
            else:
                self._research.registry.attach_counter_evidence(
                    hyp_id,
                    EvidenceRef(evidence_id=f"ev-attempt-{node.id}-r{round_no}",
                                kind="attempt", origin="agent", source_agent=agent,
                                artifact_ref=f"node:{node.id}",
                                summary=f"round {round_no + 1} attempt produced no "
                                        f"proof; hypothesis remains unconfirmed",
                                ts=self._research_ts()),
                    agent)
                self._research.registry.release(
                    hyp_id, agent, reason="attempt produced no proof")
        except SwarmError as exc:
            record_suppressed_error(self._ctx.audit, "orchestrator", "research_after_attempt", exc,
                                    hypothesis_id=hyp_id)
        except Exception as exc:
            record_suppressed_error(self._ctx.audit, "orchestrator", "research_after_attempt", exc,
                                    hypothesis_id=hyp_id)

    def _research_ts(self) -> str:
        from datetime import datetime, timezone
        return datetime.now(timezone.utc).isoformat()

    def _mirror_verification_outcomes(self) -> int:
        """Mirror the INDEPENDENT verification pipeline's verdicts onto the swarm's
        hypotheses — the only path a hypothesis takes to CONFIRMED/REFUTED.

        Direction matters: this runs AFTER run_verify_pass has already promoted or
        falsified findings through FindingStore.promote(). It reflects verdicts, it
        never causes them, and a pending finding leaves its hypothesis in
        AWAITING_VERIFICATION (never CONFIRMED). Not-reproducible/rejected returns
        the hypothesis to ACTIVE (unproven, re-attemptable), counter-evidence intact.
        Returns how many verdicts were newly mirrored."""
        mirrored = 0
        try:
            for f in self._ctx.findings.all():
                current = getattr(f, "confidence", "")
                if current not in ("confirmed", "falsified", "not_reproducible", "rejected"):
                    continue
                if self._research_verdicts_seen.get(f.id) == current:
                    continue   # already mirrored at this confidence — sync() re-runs are free
                hyp_id = self._research_finding_hyp.get(f.id)
                if hyp_id is None:
                    self._research_verdicts_seen[f.id] = current
                    continue   # finding outside the swarm's hypothesis set
                try:
                    self._research.registry.record_verification_outcome(
                        hyp_id, verdict=current, finding_id=f.id,
                        by_agent="verify-pipeline")
                    self._research_verdicts_seen[f.id] = current
                    mirrored += 1
                except SwarmError as exc:
                    # An invalid mirror (e.g. a stale finding promoted after the
                    # hypothesis moved on) is an audit note, not a run failure.
                    record_suppressed_error(self._ctx.audit, "orchestrator", "research_mirror_skipped", exc,
                                            severity="info", hypothesis_id=hyp_id, finding_id=f.id)
                    self._research_verdicts_seen[f.id] = current
        except Exception as exc:
            record_suppressed_error(self._ctx.audit, "orchestrator", "research_mirror", exc)
        return mirrored

    def _research_summary(self) -> dict:
        try:
            return {"registry": self._research.registry.stats(),
                    "forum": self._research.forum.stats()}
        except Exception as exc:
            record_suppressed_error(self._ctx.audit, "orchestrator", "read_research_summary", exc,
                                    severity="info")
            return {}

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
            # Phase C1: the pipeline just spoke — mirror its verdicts onto hypotheses.
            self._mirror_verification_outcomes()

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
        # Reflection state: accumulated strategist notes steer later rounds and land in
        # the run directory (reflections.json) for the report/dashboard.
        self._reflections: list[dict] = []
        self._reflection_notes: list[str] = []
        # Phase B5 — the cross-round strategy state (redteam/strategy.py): directives
        # with TTLs, released on evidence or expiry, carried through reflection
        # failures; the strategist amends it instead of restarting every round.
        self._strategy = EngagementStrategy()
        self._round_claims: list[str] = []   # this round's claimed techniques (evidence)
        self._confirmed_seen: set = set()

        # Phase 0 — deterministic recon runs once, before either driver starts (see
        # cli.py's call to run_deterministic_recon) so single-agent and multi-agent runs
        # get identical treatment instead of duplicating this per-driver.

        # Phase 1 — recon (breadth, cheap model).
        self._phase("recon")
        recon = self._make_specialist(RECON)
        recon.run(f"{objective}\n\nThis run: RECON only — map the attack surface.", on_text=on_text)

        # Phase 1.5 — ATTACK THESES (strong model). Before any exploitation, reason
        # about THIS target in writing: what is exploitable, why, which trusted
        # invariant breaks, how a primitive chains to impact. The ranked theses
        # (novelty x impact x evidence) brief the exploit swarm so it attacks
        # target-specific reasoning, not a generic technique menu. Logged to
        # thesis.jsonl as the run's inspectable "approach" record.
        self._exploit_theses_brief = self._generate_theses("exploit", objective, on_text)

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
            self._phase("exploit", round=rnd)
            # Coach's notes from the last reflection steer this round's specialists.
            round_objective = objective
            # The attack theses brief every exploit round so the swarm pursues the
            # ranked, target-specific reasoning rather than a generic class list.
            if getattr(self, "_exploit_theses_brief", ""):
                round_objective = round_objective + "\n\n" + self._exploit_theses_brief
            if self._reflection_notes:
                round_objective = round_objective + "\n\n" + self._reflection_notes[-1]
            summary = self._run_exploit_swarm(round_objective, rnd, on_text) or summary

            # Learned-state broadcast (docs/multi-gambit.md §4.1): the store's
            # sufficient statistics go on the bus every round. Dashboards get "what
            # has the swarm learned"; peers subscribed via bandit.make_sync_handler
            # merge foreign payloads (this run's own source is skipped by the
            # handler — merging it back would double-count evidence). Evidence
            # only: min_trials=1 drops sampling-created zero-trial arms.
            tree_bandit = getattr(self._attack_tree, "bandit", None) \
                if self._attack_tree is not None else None
            if tree_bandit is not None:
                bus = getattr(self._ctx, "events", None)
                if bus is not None:
                    self._emit("bandit.state", arms=tree_bandit.export_state(min_trials=1),
                               source=getattr(bus, "run_id", "orchestrator"))

            self._phase("verify", round=rnd)
            still_pending = run_verify_pass(self._eng, self._tools, self._ctx, self._client,
                                            objective, budget=self._budget, on_text=on_text)
            if still_pending:
                self._ctx.audit.record("orchestrator.verify_incomplete", remaining=still_pending)
            # Phase C1: mirror the verification pass's verdicts onto the swarm's
            # hypotheses (CONFIRMED/REFUTED are reflections of the pipeline, never
            # causes of finding confidence).
            self._mirror_verification_outcomes()
            if self._attack_tree is not None:
                # Phase E2: inventory->KG bridge first (host/service observations
                # reach the graph the same place the tree re-syncs), then the tree
                # sync. Bridge is idempotent; failure degrades to an audit record.
                bridge = sync_inventory_into_graph(self._ctx.inventory, self._graph)
                if bridge.get("error") or bridge.get("skipped_unanswered"):
                    self._ctx.audit.record("orchestrator.inventory_bridge",
                                           **{k: v for k, v in bridge.items() if k != "error"})
                # Promote nodes this pass just confirmed NOW: only worker agents sync
                # (on their own turns), so a confirmation landing in the final verify
                # pass would otherwise never promote — no COMPLETED, no unlock, and
                # the bandit never sees its win. sync is idempotent (mark() refuses
                # same-status re-marks), so mid-run confirmations are not re-fed.
                self._attack_tree.sync(graph=self._graph, findings=self._ctx.findings.all())

            summary = self._run_access_loop(objective, on_text) or summary

            # Strategy reflection (Gen-2): a strong model reads this round's factual
            # digest and redirects the swarm — attack-tree boosts + coach's notes. The
            # run never depends on it succeeding (see reflection.py's failure policy).
            self._reflect_on_round(objective, rnd)

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
            self._phase("logic")
            # Logic-lens theses: model the app's actors/value-flows, name the
            # trusted invariants, reason about chaining a primitive into financial
            # or ATO impact — then the specialist proves that written reasoning.
            logic_brief = self._generate_theses("logic", objective, on_text)
            logic = self._make_specialist(LOGIC, addon_suffix=(
                ("\n\n" + logic_brief) if logic_brief else ""))
            summary = logic.run(
                f"{objective}\n\nThis run: LOGIC — find and prove business-logic bugs "
                f"on the workflow-shaped endpoints already mapped.", on_text=on_text) or summary

            self._phase("verify", phase_end="logic")
            still_pending = run_verify_pass(self._eng, self._tools, self._ctx, self._client,
                                            objective, budget=self._budget, on_text=on_text)
            if still_pending:
                self._ctx.audit.record("orchestrator.verify_incomplete", remaining=still_pending)
            self._mirror_verification_outcomes()
            if self._attack_tree is not None:
                sync_inventory_into_graph(self._ctx.inventory, self._graph)
                self._attack_tree.sync(graph=self._graph, findings=self._ctx.findings.all())

        # Final creditor sweep (idempotent — see run_verify_pass note): catches a
        # confirmation that landed after the last verify pass funneled through.
        from .credit import credit_confirmed_findings
        try:
            credit_confirmed_findings(self._ctx)
        except Exception as exc:
            self._record_suppressed_error(ctx.audit, "orchestrator", "credit_failed", exc)

        confirmed_count = len([f for f in self._ctx.findings.all()
                               if f.confidence == "confirmed"])
        self._ctx.audit.record("orchestrator.finish",
                               findings=len(self._ctx.findings.all()),
                               confirmed=confirmed_count)
        # Phase C1: the run's research record on the bus + audit trail (the journal
        # itself remains replayable from disk when research_dir was given).
        research = self._research_summary()
        if research:
            self._ctx.audit.record("research.summary", **research)
            self._emit("run.research.summary", **research)
        self._emit("run.summary", findings=len(self._ctx.findings.all()),
                   confirmed=confirmed_count, reflections=len(self._reflections))
        return summary

    def mission_attack_frontier(self, limit: int = 6) -> list[dict]:
        """Return ranked, currently claimable mission work from the canonical tree.

        AttackTree remains the selector. Synthesis only enriches an already
        selected node, and the MissionScheduler still owns the actual claim.
        """
        if self._attack_tree is None:
            return []
        from .attack_tree import TODO, technique_cost
        from .synthesis import brief, synthesize
        ideas = {}
        try:
            for idea in synthesize(self._ctx):
                ideas[(idea.technique, idea.target)] = idea
        except Exception as exc:
            record_suppressed_error(self._ctx.audit, "orchestrator", "mission_synthesis", exc)
        candidates = [n for n in self._attack_tree.actionable(limit=max(limit * 4, limit))
                      if n.status == TODO]
        # Match the classic loop's drift-plus-penalty ordering when configured;
        # the mission scheduler still performs the actual OPSEC reservation.
        if self._noise is not None and candidates:
            ranked = self._noise.rank([
                (n.technique, n.bucket, technique_cost(n.technique), n)
                for n in candidates])
            candidates = [item["meta"] for item in ranked]
        selected = []
        for node in candidates:
            profile = profile_for(node.technique)
            title = f"{profile.name}: {node.technique} on {node.target}"
            idea = ideas.get((node.technique, node.target))
            if idea is not None:
                try:
                    title += " — " + brief(idea, max_chars=900)
                except Exception as exc:
                    record_suppressed_error(self._ctx.audit, "orchestrator",
                                            "format_attack_idea", exc)
            selected.append({
                "title": title[:1800],
                "role": "exploit",
                "technique": node.technique,
                "target": node.target,
                "max_steps": int(profile.max_steps),
                "opsec_allowance": float(technique_cost(node.technique)),
            })
            if len(selected) >= limit:
                break
        self._ctx.audit.record(
            "mission.frontier.selected",
            candidates=len(candidates),
            selected=[f"{x['technique']}@{x['target']}" for x in selected])
        return selected

    def record_mission_task_outcome(self, task_view: dict,
                                    evidence: tuple[dict, ...] | list[dict]) -> None:
        """Close the mission task's existing hypothesis claim with real outcomes.

        The scheduler passes the hypothesis id it already claimed. Finding
        evidence is attached before verification so the existing verifier
        mirror can move that same hypothesis to CONFIRMED/REFUTED. An attempt
        with no finding records counter-evidence and releases its lease.
        """
        hyp_id = str(task_view.get("hypothesis_id", "") or "")
        node_id = str(task_view.get("node_id", "") or "")
        if node_id and str(task_view.get("role", "")) == "exploit":
            self._round_claims.append(str(task_view.get("technique", "") or ""))
        if not hyp_id or not node_id:
            return
        agent = str(task_view.get("role", "exploit") or "exploit")
        self._research_hyp_by_node[node_id] = hyp_id
        finding_refs = [str(ev.get("ref", "")) for ev in evidence
                        if ev.get("kind") == "finding" and ev.get("ref")]
        try:
            attached = []
            for finding_id in finding_refs:
                finding = self._ctx.findings.get(finding_id)
                if finding is None:
                    continue
                self._research.registry.attach_evidence(
                    hyp_id,
                    EvidenceRef(
                        evidence_id=f"ev-finding-{finding_id}",
                        kind="finding", origin="agent",
                        source_agent=agent, artifact_ref=finding_id,
                        summary=f"{finding.severity}: {finding.title} @ {finding.target}",
                        ts=self._research_ts()),
                    agent)
                self._research_finding_hyp[finding_id] = hyp_id
                attached.append(finding_id)
            if attached:
                self._research.registry.set_status(
                    hyp_id, AWAITING_VERIFICATION, agent,
                    finding_id=attached[-1],
                    reason=f"mission task produced {len(attached)} finding(s); awaiting independent verification")
            else:
                task_id = str(task_view.get("task_id", "mission-task") or "mission-task")
                self._research.registry.attach_counter_evidence(
                    hyp_id,
                    EvidenceRef(
                        evidence_id=f"ev-mission-empty-{task_id}",
                        kind="observation", origin="agent",
                        source_agent=agent, artifact_ref=task_id,
                        summary="Mission task ended without producing a finding; no proof outcome asserted.",
                        ts=self._research_ts()),
                    agent)
                self._research.registry.release(
                    hyp_id, agent, reason="mission task ended without a finding")
        except Exception as exc:
            record_suppressed_error(self._ctx.audit, "orchestrator", "mission_research_attempt", exc,
                                    hypothesis_id=hyp_id)

    def mission_reconcile_after_verification(self) -> dict:
        """Apply the classic loop's reusable post-verification joins.

        This mirrors verifier outcomes, bridges observed inventory into the
        existing KnowledgeGraph, synchronizes the canonical AttackTree, and
        runs deterministic objective/access credit. It does not select, claim,
        dispatch, or create any parallel state authority.
        """
        mirrored = self._mirror_verification_outcomes()
        bridge = {"skipped": True}
        if getattr(self._ctx, "inventory", None) is not None and self._graph is not None:
            bridge = sync_inventory_into_graph(self._ctx.inventory, self._graph)
        synced = 0
        if self._attack_tree is not None:
            before = len(self._attack_tree.confirmed_chain())
            self._attack_tree.sync(graph=self._graph,
                                   findings=self._ctx.findings.all())
            synced = max(0, len(self._attack_tree.confirmed_chain()) - before)
        from .credit import credit_confirmed_findings
        credited = credit_confirmed_findings(self._ctx)
        result = {"hypotheses_mirrored": mirrored, "inventory_bridge": bridge,
                  "new_confirmed_nodes": synced, "credits": credited}
        self._ctx.audit.record("mission.reconcile", **{
            "hypotheses_mirrored": mirrored,
            "new_confirmed_nodes": synced,
            "credits": len(credited)})
        return result

    def mission_access_state(self) -> dict:
        """Return the current KillChain-directed ACCESS opportunity, if any."""
        access = getattr(self._ctx, "access", None)
        killchain = getattr(self._ctx, "killchain", None)
        if access is None or killchain is None:
            return {}
        recommendations = [stage for stage in killchain.recommend(
            access, getattr(self._ctx, "objective", None))
            if stage in _ACCESS_STAGES]
        if not recommendations:
            return {}
        holdings = sorted(f"{node.kind}:{node.key}" for node in access.held())
        return {"recommendations": recommendations,
                "achieved": sorted(killchain.achieved()),
                "holdings": holdings}

    def mission_logic_required(self) -> bool:
        """Use the classic workflow-shape detector as the LOGIC task gate."""
        return _looks_workflow_shaped(self._graph)

    def mission_reflect_after_round(self, objective: str, round_no: int) -> None:
        """Run the existing strategist once at a mission round boundary."""
        if not getattr(self._eng, "enable_reflection", True):
            self._round_claims = []
            return
        try:
            self._reflect_on_round(objective, round_no)
        except Exception as exc:
            record_suppressed_error(self._ctx.audit, "orchestrator", "reflection", exc,
                                    round=round_no + 1)

    def mission_objective_achieved(self) -> bool | None:
        """Return the structured objective result, or None when no criteria exist."""
        objective = getattr(self._ctx, "objective", None)
        if objective is None:
            return None
        return bool(objective.achieved)

    def _reflect_on_round(self, objective: str, round_no: int) -> None:
        """One strategist call per completed round; folds the round's evidence into
        the cross-round strategy state (Phase B5, redteam/strategy.py), lets the
        strategist AMEND that state instead of restarting, and re-applies exactly
        the surviving directives to the tree. Never raises."""
        if not getattr(self._eng, "enable_reflection", True):
            return
        if self._budget is not None:
            try:
                self._budget.check()
            except Exception as exc:
                record_suppressed_error(self._ctx.audit, "orchestrator", "check_reflection_budget", exc,
                                        severity="info")
                return   # out of budget — skip the strategist, reflection is optional
        tail = []
        try:
            tail = self._ctx.audit.read_all()[-120:]
        except Exception as exc:
            record_suppressed_error(self._ctx.audit, "orchestrator", "read_audit_tail", exc)
        # Phase B5 — evidence in, deterministic decay out: what the swarm claimed
        # this round (its own claim loop) and what the tree confirmed (only NEWLY
        # completed nodes — confirmed_chain() repeats, the ledger must not), then
        # tick() expires TTLs and releases directives on evidence — whether or not
        # the strategist answers (forgetting is never LLM-dependent).
        confirmed: list[str] = []
        if self._attack_tree is not None:
            try:
                for n in self._attack_tree.confirmed_chain():
                    if n.id not in self._confirmed_seen:
                        self._confirmed_seen.add(n.id)
                        confirmed.append(n.technique)
            except Exception as exc:
                record_suppressed_error(self._ctx.audit, "orchestrator", "read_confirmed_chain", exc,
                                        severity="info")
                confirmed = []
        self._strategy.observe_round(round_no + 1, self._round_claims, confirmed)
        self._round_claims = []
        released = self._strategy.tick(round_no + 1)
        objective_obj = getattr(self._ctx, "objective", None)
        reflection = reflect(
            self._client,
            objective_text=objective,
            round_no=round_no + 1,
            objective=objective_obj,
            findings=self._ctx.findings.all(),
            attack_tree=self._attack_tree,
            killchain=getattr(self._ctx, "killchain", None),
            audit_tail=tail,
            notes_so_far=self._reflection_notes,
            strategy_brief=self._strategy.brief() or None,
        )
        amended = None
        if reflection is not None:
            amended = self._strategy.amend(reflection, round_no + 1)
        applied = self._apply_strategy_state()
        if reflection is None:
            # The amplifier failed. The state still decayed above and the surviving
            # directives remain applied for the next round — the run continues
            # exactly as Gen-1 did, with a strategy that still forgets on schedule.
            if released:
                self._ctx.audit.record("orchestrator.strategy_released",
                                       round=round_no + 1, released=released)
                self._emit("strategy.state", round=round_no + 1, released=released,
                           **self._strategy.state())
            return
        reflection["round"] = round_no + 1
        reflection["boosts_applied"] = applied
        reflection["strategy_amended"] = amended
        reflection["strategy_released"] = released
        self._reflections.append(reflection)
        self._reflection_notes.append(coach_note(reflection))
        self._ctx.audit.record("orchestrator.reflection", round=round_no + 1,
                               boosts=applied)
        if released:
            self._ctx.audit.record("orchestrator.strategy_released",
                                   round=round_no + 1, released=released)
        self._emit("reflection", round=round_no + 1, boosts_applied=applied,
                   assessment=reflection["assessment"],
                   focus_next=reflection.get("focus_next") or [])
        self._emit("strategy.state", round=round_no + 1, released=released,
                   **self._strategy.state())
        # Persist for the report/dashboard even if the process dies mid-run.
        if self._manifest is not None:
            try:
                out_dir = Path(self._manifest[1]).parent
                out_dir.mkdir(parents=True, exist_ok=True)
                (out_dir / "reflections.json").write_text(
                    json.dumps(self._reflections, indent=2, ensure_ascii=False),
                    encoding="utf-8")
                (out_dir / "strategy.json").write_text(
                    json.dumps(self._strategy.to_dict(), indent=2,
                               ensure_ascii=False), encoding="utf-8")
            except Exception as exc:
                record_suppressed_error(self._ctx.audit, "orchestrator",
                                        "persist_strategy_state", exc)

    def _apply_strategy_state(self) -> int:
        """Phase B5 — the strategy object is the ONLY writer of tree nudges: restore
        the nudge layer to neutral, then apply exactly the live directives. A
        released directive genuinely releases (the old apply-once-forever behavior
        is gone), and a live directive survives a failed reflection. Returns how
        many boosts landed on real nodes — the audit event's shape is unchanged."""
        if self._attack_tree is None:
            return 0
        reset_tree_nudges(self._attack_tree)
        press, avoid = self._strategy.directives_for_tree()
        try:
            return self._attack_tree.apply_strategy(prioritize=press,
                                                    deprioritize=avoid)
        except Exception as exc:
            record_suppressed_error(self._ctx.audit, "orchestrator", "apply_strategy_state", exc)
            return 0
