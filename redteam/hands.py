"""Agent hands and skills — what each specialist HOLDS and may EXECUTE (Phase E1).

The audit this phase answers (the "too generic" finding): a SpecialistProfile was a
bare name list plus prose. Three consequences, all observed:

  1. Hands with no stated discipline. A profile held "http_probe" but nothing said
     the tool's output is a first-party OBSERVATION (never a finding), or that a
     content_discovery lead must be crosschecked before it aims anything. The trust
     ladder (redteam/tools/crosscheck.py, TRUST_MATRIX) existed — but nothing bound
     it to the agents who must obey it.
  2. Unheld hands. Tools built in D0/D2 (content_discovery, crawl, param_discovery,
     host_probe, port_scan, xss_reflect_probe, find_techniques, apply_skill) were in
     the registry but in NO profile's tool_names — in a multi-agent run the team
     never held them. Worse: A10's addon said "START with surface_scan" while its
     tool_names did not include surface_scan — the prompt taught a hand the agent
     could never raise.
  3. Silent subset drops. _make_specialist filtered with ``if n in self._tools``,
     so a typo'd tool name in a profile silently vanished instead of failing loud.

This module is the fix, and it is deliberately NOT another tool:

  A Hand says what a held tool is FOR, what it COSTS (a step vs a verification
  trial), what its output may be TRUSTED as (the trust classes mirror the crosscheck
  vocabulary — lead classes, ground truth, offline parse, proof trials), and what
  the agent OWES before believing it (the crosscheck obligation).

  A Skill is a DECLARED procedure: entry condition (evidence that triggers it),
  concrete steps naming tools, exit criterion, and the proof shape it feeds. Skills
  are validated to only name tools the owning agent actually holds — a skill that
  references a hand the agent doesn't have is a registration error, not advice.

Everything fails closed: every profile tool must have a Hand and vice versa (no
untaught hands, no unheld teachings), hand tools must exist in the registry, skill
tool refs must be held, and trust classes must agree with TRUST_MATRIX/EXEMPT.
Introspection: ``python -m redteam.hands --json`` (parity with states/crosscheck).
"""

from __future__ import annotations

from dataclasses import dataclass
import json
import sys

# Tools that build_registry may legitimately omit (sandbox/browser disabled) —
# a profile listing these is valid even when the run is headless. Everything
# else must exist in the registry or validation raises.
OPTIONAL_TOOLS = frozenset({
    "kali_exec", "local_exec",
    "browser_navigate", "browser_content", "browser_click", "browser_fill",
    "browser_screenshot", "browser_requests", "browser_inspect_request",
    "browser_console", "browser_login", "browser_session_status",
    # proxy_* tools degrade honestly without a running EvidenceProxy, but the
    # RECON profile lists them, so a proxy-less registry must stay valid.
    "proxy_status", "proxy_history", "proxy_inspect", "proxy_filter",
    "proxy_replay",
})

# Trust classes — the SAME vocabulary the crosscheck layer enforces, so a hand's
# trust claim and the trust matrix can never drift apart (test_hands locks this).
#   ground-truth           : reads the RoE allowlist itself (EXEMPT in the matrix)
#   offline-parse          : deterministic parse of material already held (EXEMPT)
#   lead-crosschecked      : a TRUST_MATRIX lead class — second method or it doesn't count
#   deterministic-honest   : registered honest-empty in the matrix (graphql_inspect);
#                            feeds a READY spec to the proof pipeline, claims nothing alone
#   first-party-observation: OUR OWN request/response (probe, browser, cred try) —
#                            evidence that aims the next step, never a finding by itself
#   proof-trial            : reproduce + negative control; verdict belongs to the pipeline
#   peer-read              : a sibling worker's observation, not your own evidence
TRUST_CLASSES = frozenset({
    "ground-truth", "offline-parse", "lead-crosschecked", "deterministic-honest",
    "first-party-observation", "proof-trial", "peer-read",
})

# Meta hands: they read OUR OWN state/docs/process and make NO claim about the
# target, so the crosscheck policy (which governs TARGET claims) does not apply.
META_TOOLS = frozenset({"find_techniques", "find_attack_templates", "request_approval"})


@dataclass(frozen=True)
class Hand:
    """One tool as ONE agent holds it: purpose, cost, trust, obligation."""
    tool: str
    purpose: str        # what this hand is for, concretely
    cost: str           # "step" (an ordinary step) | "verification-trial" (burns budget)
    trust: str          # one of TRUST_CLASSES
    obligation: str     # what the agent owes before believing/acting on the output


@dataclass(frozen=True)
class Skill:
    """A declared procedure one agent may execute. Not advice — a binding with
    entry evidence, tool-naming steps, an exit criterion, and a proof shape."""
    name: str
    agent: str
    when: str           # entry condition: the evidence that triggers it
    steps: tuple[str, ...]
    tools: tuple[str, ...]   # structural refs — validated ⊆ the agent's hands
    exit: str
    proof: str


# ---------------------------------------------------------------------------
# The hand registry — one Hand per TOOL (the discipline of a tool does not change
# per agent; role flavor lives in the skills). Ordered so briefings read naturally.
# ---------------------------------------------------------------------------

_HAND: dict[str, Hand] = {
    # -- mapping / surface ------------------------------------------------------
    "surface_scan": Hand(
        tool="surface_scan",
        purpose="knock on every host/port the RoE allows, once, and fill the asset "
                "inventory — the alive-map every later step aims at",
        cost="step", trust="ground-truth",
        obligation="one call, no arguments, first thing in a mapping round; a host it "
                   "did not answer for is dead to this run — never spend a step on it"),
    "host_probe": Hand(
        tool="host_probe",
        purpose="binary-assisted liveness + technology fingerprint of discovered URLs "
                "(httpx/nmap class leads)",
        cost="step", trust="lead-crosschecked",
        obligation="its endpoint/service claims are LEADS: crosscheck_lead them "
                   "first-party (GET / raw TCP) before any probe aims at one"),
    "port_scan": Hand(
        tool="port_scan",
        purpose="RoE-bounded port scan of in-scope hosts (nmap class)",
        cost="step", trust="lead-crosschecked",
        obligation="every open-port claim must survive a raw first-party TCP connect "
                   "via crosscheck_lead before it goes in the graph"),
    "content_discovery": Hand(
        tool="content_discovery",
        purpose="wordlist-driven path discovery on a live host (ffuf class) — backups, "
                "dotfiles, admin paths, API roots",
        cost="step", trust="lead-crosschecked",
        obligation="a claimed path is not a path until a first-party GET reaches it "
                   "(crosscheck_lead); 404/410 on the re-fetch kills the lead"),
    "crawl": Hand(
        tool="crawl",
        purpose="link/JS crawl of a live host (katana class) — the app's own map of itself",
        cost="step", trust="lead-crosschecked",
        obligation="crawled URLs are leads until a first-party GET reaches them "
                   "(crosscheck_lead)"),
    "param_discovery": Hand(
        tool="param_discovery",
        purpose="hidden-parameter discovery on an endpoint (arjun class)",
        cost="step", trust="lead-crosschecked",
        obligation="a claimed param is not real until a first-party WITH/WITHOUT pair "
                   "actually differs (crosscheck_lead); identical response kills it"),
    "spa_recon": Hand(
        tool="spa_recon",
        purpose="walk a SPA's bundle to infer its API routes",
        cost="step", trust="lead-crosschecked",
        obligation="inferred routes are leads: a first-party GET (or a 405 on a "
                   "POST-able route) corroborates, 404 kills"),
    "http_probe": Hand(
        tool="http_probe",
        purpose="raw first-party HTTP fetch — the second method the crosscheck layer "
                "itself trusts; read responses, classify contexts, shape hypotheses",
        cost="step", trust="first-party-observation",
        obligation="an observation aims the next step; it NEVER records a finding — "
                   "proving is verify_vulnerability/confirm_finding's job"),
    "browser_navigate": Hand(
        tool="browser_navigate",
        purpose="drive the real browser to a URL — JS-rendered surfaces the probe cannot see",
        cost="step", trust="first-party-observation",
        obligation="what you SEE is an observation; pair with browser_content to read it"),
    "browser_content": Hand(
        tool="browser_content",
        purpose="read the live DOM/text of the page the browser is on",
        cost="step", trust="first-party-observation",
        obligation="observations only — stored-payload rendering here still needs a "
                   "proof tool to count"),
    "browser_click": Hand(
        tool="browser_click",
        purpose="click a page element by role/name — drive multi-step flows",
        cost="step", trust="first-party-observation",
        obligation="observations only"),
    "browser_fill": Hand(
        tool="browser_fill",
        purpose="type into a form field (payloads included) — the stored-XSS submission path",
        cost="step", trust="first-party-observation",
        obligation="observations only; the rendering surface still needs proof"),
    "browser_login": Hand(
        tool="browser_login",
        purpose="authenticate as a TEST account in the live browser (password from "
                "an env var, never an argument) to reach the authenticated surface",
        cost="step", trust="first-party-observation",
        obligation="only log in as an account you fully own, never a real member; "
                   "the session is an observation, findings still need proof"),
    "browser_session_status": Hand(
        tool="browser_session_status",
        purpose="check whether the (human-warmed) session is authenticated and "
                "whether Cloudflare is challenging — before probing a WAF target",
        cost="step", trust="first-party-observation",
        obligation="observation only; stop for a human on a challenge, do not hammer it"),
    "browser_screenshot": Hand(
        tool="browser_screenshot",
        purpose="capture the rendered page state",
        cost="step", trust="first-party-observation",
        obligation="observations only"),
    # -- recon instrument read-back (2026-11-18 recon upgrade) ----------------
    "browser_requests": Hand(
        tool="browser_requests",
        purpose="list what the browser ACTUALLY sent (XHR/fetch API calls, "
                "blocked out-of-scope attempts) without re-navigating",
        cost="step", trust="first-party-observation",
        obligation="read the capture before repeating a navigation; blocked "
                   "rows prove a denial, not a finding"),
    "browser_inspect_request": Hand(
        tool="browser_inspect_request",
        purpose="read one captured exchange in full (sanitized headers, "
                "safely-collectable body, redirect depth)",
        cost="step", trust="first-party-observation",
        obligation="secrets are withheld by the recorder; never copy "
                   "credential-shaped values into notes or findings"),
    "browser_console": Hand(
        tool="browser_console",
        purpose="collect console errors and uncaught page exceptions — "
                "routes and stack paths the UI hides",
        cost="step", trust="first-party-observation",
        obligation="an error message is a LEAD, never evidence of impact"),
    "proxy_status": Hand(
        tool="proxy_status",
        purpose="evidence-proxy listener state: TLS decrypted vs tunneled, "
                "capture counters",
        cost="step", trust="offline-parse",
        obligation="quote the TLS honesty verdict, never claim decrypted "
                   "content when the mode is passthrough"),
    "proxy_history": Hand(
        tool="proxy_history",
        purpose="newest captured exchanges from the evidence plane",
        cost="step", trust="offline-parse",
        obligation="read history before re-issuing requests; a captured row "
                   "is evidence of the wire, not of exploitability"),
    "proxy_inspect": Hand(
        tool="proxy_inspect",
        purpose="one captured exchange in full detail (masked, bounded)",
        cost="step", trust="offline-parse",
        obligation="same secret-handling rule as browser_inspect_request"),
    "proxy_filter": Hand(
        tool="proxy_filter",
        purpose="search captured exchanges by url/method/status/source",
        cost="step", trust="offline-parse",
        obligation="prefer a filtered query over re-driving the app"),
    "proxy_replay": Hand(
        tool="proxy_replay",
        purpose="re-send ONE captured exchange under the same RoE "
                "(scope-checked, budgeted, audited, recorded)",
        cost="step", trust="first-party-observation",
        obligation="replay repeats a recorded request exactly — no new "
                   "targets; differential conclusions still need a proof tool"),
    "passive_recon": Hand(
        tool="passive_recon",
        purpose="DNS records, TLS certificate metadata (SANs), robots.txt, "
                "sitemap.xml, security headers, cookie flags, technology "
                "fingerprints — with source+timestamp+mode on every record",
        cost="step", trust="first-party-observation",
        obligation="passive/light leads only; corroborate before trusting; "
                   "external CT lookups stay opt-in (RED_CT_LOGS)"),
    "observations": Hand(
        tool="observations",
        purpose="query the run's observation log: what is known, from which "
                "source, validation state (corroborated/contradicted/…)",
        cost="step", trust="offline-parse",
        obligation="check BEFORE re-running any discovery tool — "
                   "re-discovering recorded work wastes steps"),
    # -- session ------------------------------------------------------------
    "authenticate": Hand(
        tool="authenticate",
        purpose="log in through the app's own flow (seeded/brief creds, multi-step aware) "
                "and hold the session",
        cost="step", trust="first-party-observation",
        obligation="logging in is bootstrap, not proof; a session you hold is input "
                   "to proofs, never a finding"),
    "set_session": Hand(
        tool="set_session",
        purpose="register a brief-supplied token/cookie as a named session instead of "
                "hand-writing headers",
        cost="step", trust="first-party-observation",
        obligation="register what the brief gave you; never invent tokens"),
    # -- proof pipeline -------------------------------------------------------
    "verify_vulnerability": Hand(
        tool="verify_vulnerability",
        purpose="fire a full reproducing check (requests + conditions) — the main proof "
                "hand; a synthesis draft's check_spec goes in 1:1, unmodified",
        cost="verification-trial", trust="proof-trial",
        obligation="fire only with a hypothesis worth proving; conditions must be the "
                   "differential shape (status AND body/content), never status alone"),
    "confirm_finding": Hand(
        tool="confirm_finding",
        purpose="record a simple single/differential HTTP proof as a finding check",
        cost="verification-trial", trust="proof-trial",
        obligation="same discipline: differential shape or nothing"),
    "verify_workflow_abuse": Hand(
        tool="verify_workflow_abuse",
        purpose="ordered attack_steps vs honest control_steps with a stated invariant — "
                "the business-logic proof",
        cost="verification-trial", trust="proof-trial",
        obligation="one-shot: business logic cannot be re-run k-of-n — sequence it "
                   "right the first time"),
    "prove_privilege": Hand(
        tool="prove_privilege",
        purpose="differential privilege-boundary proof for a held session",
        cost="verification-trial", trust="proof-trial",
        obligation="never label access yourself — the check lands pending_verification "
                   "like every other proof"),
    "verify_finding_independently": Hand(
        tool="verify_finding_independently",
        purpose="reproduce a finding's check in a FRESH context with a forced negative "
                "control — the independent verdict",
        cost="verification-trial", trust="proof-trial",
        obligation="accept the verdict; do not argue with it"),
    # -- trust / discipline ------------------------------------------------
    "crosscheck_lead": Hand(
        tool="crosscheck_lead",
        purpose="run the registered second method against a tool's lead claim "
                "(corroborated / contradicted / unverifiable) — the trust ladder's gate",
        cost="step", trust="first-party-observation",
        obligation="never skip it on a lead you want to be true; unknown (tool, claim) "
                   "pairs fail closed by design — unverifiable means drop it"),
    "jwt_inspect": Hand(
        tool="jwt_inspect",
        purpose="deterministic offline parse of a held token: algorithm, claims, expiry",
        cost="step", trust="offline-parse",
        obligation="its output is a LEAD about the token — prove consequences THROUGH "
                   "the app; the parse alone never proves anything"),
    "extract_secrets": Hand(
        tool="extract_secrets",
        purpose="regex sweep over material you already hold (bodies, files) for "
                "credential shapes (AKIA…, ghp_…, eyJ…)",
        cost="step", trust="offline-parse",
        obligation="a regex hit is a lead until the resource is Fetched and its content "
                   "verified"),
    # -- knowledge / peers --------------------------------------------------
    "search_peer_traces": Hand(
        tool="search_peer_traces",
        purpose="read sibling workers' observations (identifiers, tokens, paths they saw)",
        cost="step", trust="peer-read",
        obligation="a peer observation is a hint to re-derive YOURSELF, not evidence"),
    "find_techniques": Hand(
        tool="find_techniques",
        purpose="pull the first-party playbook card for a technique (differential shape, "
                "false-positive traps, accepted proof)",
        cost="step", trust="ground-truth",
        obligation="read the card BEFORE designing checks — do not re-derive what the "
                   "playbook already encodes"),
    "find_attack_templates": Hand(
        tool="find_attack_templates",
        purpose="recall known-tech template sets matching a fingerprint",
        cost="step", trust="ground-truth",
        obligation="templates aim probes; they do not prove"),
    "apply_template": Hand(
        tool="apply_template",
        purpose="run a recalled template's checks",
        cost="step", trust="first-party-observation",
        obligation="its hits are leads — proof tools still decide"),
    "apply_skill": Hand(
        tool="apply_skill",
        purpose="fill in a PROVEN skill's parameters and re-run its exact proof "
                "(the skill library's whole point: fill two params, not redesign a proof)",
        cost="verification-trial", trust="proof-trial",
        obligation="use the skill verbatim; if the skill's shape doesn't fit, design a "
                   "check with verify_vulnerability instead"),
    "nuclei_scan": Hand(
        tool="nuclei_scan",
        purpose="template-driven known-vuln sweep of a live host",
        cost="step", trust="lead-crosschecked",
        obligation="a template match is a lead until the first-party re-fetch shows the "
                   "marker (crosscheck_lead)"),
    "xss_reflect_probe": Hand(
        tool="xss_reflect_probe",
        purpose="deterministic reflection map: one unique marker per param, context "
                "classification, READY check_spec when specials survive",
        cost="step", trust="lead-crosschecked",
        obligation="READY means the check_spec is proven-shaped — still fire it through "
                   "verify_vulnerability; escaped reflections produce NO idea"),
    "graphql_inspect": Hand(
        tool="graphql_inspect",
        purpose="4-request deterministic checklist over a GraphQL endpoint (introspection, "
                "validation echo, error shape)",
        cost="step", trust="deterministic-honest",
        obligation="honestly registered unverifiable in the trust matrix: it maps "
                   "SURFACE, it claims nothing — what it finds still needs a proof tool"),
    # -- access / postex ------------------------------------------------------
    "try_credential": Hand(
        tool="try_credential",
        purpose="bounded credential attempts against an in-scope login",
        cost="step", trust="first-party-observation",
        obligation="SMALL burst, then stop — RoE-minimal; a lockout message is an "
                   "enumeration finding, not a bypass"),
    "record_access": Hand(
        tool="record_access",
        purpose="note a discovered lead/edge (not self-granted access) into the ledger",
        cost="step", trust="first-party-observation",
        obligation="records leads and edges, never labels held access"),
    "claim_objective": Hand(
        tool="claim_objective",
        purpose="claim the objective once demonstrated access reaches it",
        cost="step", trust="proof-trial",
        obligation="only on demonstrated access; the sweep re-checks"),
    "record_finding": Hand(
        tool="record_finding",
        purpose="record a finding outside the proof pipeline (single-agent mode)",
        cost="step", trust="first-party-observation",
        obligation="prefer the proof pipeline whenever it can take the check"),
    "request_approval": Hand(
        tool="request_approval",
        purpose="ask the operator for an RoE-boundary approval (destructive/verbose step)",
        cost="step", trust="ground-truth",
        obligation="never self-approve what RoE marks require_approval_for"),
    # -- sandbox ---------------------------------------------------------------
    "kali_exec": Hand(
        tool="kali_exec",
        purpose="run an allowlisted binary in the sandbox (scope-guarded)",
        cost="step", trust="first-party-observation",
        obligation="the wrapped BINARY's claims (ffuf/katana/arjun/nuclei/httpx/nmap "
                   "class) are lead classes — each obeys its TRUST_MATRIX entry via "
                   "the wrapping tool or crosscheck_lead, never direct belief"),
    "local_exec": Hand(
        tool="local_exec",
        purpose="run a local assessment step (lab mode)",
        cost="step", trust="first-party-observation",
        obligation="observations only"),
    # -- RECON V2 evidence workspace (read our own evidence, no new claim) ------
    "evidence_search": Hand(
        tool="evidence_search",
        purpose="search the run's accumulated evidence observations (each carries "
                "provenance, validation and scope status)",
        cost="step", trust="first-party-observation",
        obligation="search BEFORE re-scanning: an already-recorded observation needs "
                   "no second probe; entries are evidence, not findings"),
    "evidence_inspect": Hand(
        tool="evidence_inspect",
        purpose="read ONE observation's full record (attrs, evidence refs, scope)",
        cost="step", trust="first-party-observation",
        obligation="cite the evidence refs when acting on what it shows"),
    "proxy_history_query": Hand(
        tool="proxy_history_query",
        purpose="query the wire history (browser + proxy + tool exchanges in "
                "traffic.jsonl) — what actually went over the wire",
        cost="step", trust="first-party-observation",
        obligation="the wire log is the truth of what was SENT, not what succeeded; "
                   "status codes and errors are part of the record"),
    "replay_request": Hand(
        tool="replay_request",
        purpose="re-issue ONE recorded request through the shared scope/budget/"
                "approval controls",
        cost="step", trust="first-party-observation",
        obligation="approval-gated; replay an authorized request only, and treat "
                   "the fresh exchange (source=replay) as new evidence"),
    "asset_read": Hand(
        tool="asset_read",
        purpose="read the asset inventory surface_scan and the fetch path filled",
        cost="step", trust="ground-truth",
        obligation="a host it did not record is not alive to this run"),
}

# ---------------------------------------------------------------------------
# HANDS per agent — must EXACTLY equal each profile's tool_names (validated).
# RECON and the class specialists are EQUIPPED here with the D0/D2 hands they
# were missing; A10 gains the surface_scan its addon already told it to use.
# ---------------------------------------------------------------------------

HANDS: dict[str, tuple[Hand, ...]] = {
    "recon": tuple(_HAND[t] for t in (
        "passive_recon", "observations", "proxy_status", "proxy_history",
        "proxy_inspect", "proxy_filter", "proxy_replay",
        "surface_scan", "host_probe", "port_scan", "content_discovery", "crawl",
        "param_discovery", "spa_recon", "crosscheck_lead", "http_probe",
        "jwt_inspect", "graphql_inspect",
        "browser_navigate", "browser_content", "browser_click",
        "browser_fill", "browser_screenshot", "browser_requests",
        "browser_inspect_request", "browser_console",
        "authenticate", "set_session", "kali_exec", "search_peer_traces",
        "evidence_search", "evidence_inspect", "proxy_history_query",
        "replay_request", "asset_read")),
    "exploit": tuple(_HAND[t] for t in (
        "find_techniques", "crosscheck_lead", "apply_skill", "http_probe",
        "authenticate", "set_session", "verify_vulnerability", "confirm_finding",
        "browser_navigate", "browser_content", "browser_fill", "kali_exec",
        "search_peer_traces")),
    "access": tuple(_HAND[t] for t in (
        "extract_secrets", "try_credential", "prove_privilege", "record_access",
        "authenticate", "set_session", "http_probe", "kali_exec",
        "browser_navigate", "browser_content")),
    "logic": tuple(_HAND[t] for t in (
        "verify_workflow_abuse", "authenticate", "set_session", "http_probe",
        "browser_navigate", "browser_content", "browser_fill", "browser_click",
        "browser_login", "browser_session_status", "browser_requests",
        "browser_inspect_request", "find_techniques")),
    "verify": tuple(_HAND[t] for t in (
        "verify_finding_independently",)),
    "a01-access": tuple(_HAND[t] for t in (
        "authenticate", "set_session", "http_probe", "verify_vulnerability",
        "confirm_finding", "crosscheck_lead", "browser_navigate", "browser_content",
        "search_peer_traces")),
    "a03-injection": tuple(_HAND[t] for t in (
        "authenticate", "set_session", "http_probe", "verify_vulnerability",
        "confirm_finding", "xss_reflect_probe", "graphql_inspect", "crosscheck_lead",
        "browser_navigate", "browser_content", "browser_fill", "browser_click",
        "search_peer_traces")),
    "a05-misconfig": tuple(_HAND[t] for t in (
        "surface_scan", "content_discovery", "nuclei_scan", "crosscheck_lead",
        "http_probe", "verify_vulnerability", "confirm_finding", "extract_secrets",
        "browser_navigate", "browser_content", "find_attack_templates",
        "apply_template", "search_peer_traces")),
    "a07-auth": tuple(_HAND[t] for t in (
        "authenticate", "set_session", "jwt_inspect", "try_credential", "http_probe",
        "verify_vulnerability", "confirm_finding", "browser_navigate",
        "browser_content", "search_peer_traces")),
    "a10-ssrf": tuple(_HAND[t] for t in (
        "surface_scan", "http_probe", "verify_vulnerability", "confirm_finding",
        "browser_navigate", "browser_content", "search_peer_traces")),
    "llm01-prompt-injection": tuple(_HAND[t] for t in (
        "record_finding", "confirm_finding", "verify_finding_independently")),
}


# ---------------------------------------------------------------------------
# SKILLS per agent — declared procedures. Every skill's tools must be held by
# its agent (validated below); entry conditions name the EVIDENCE that triggers
# them, not vague moods.
# ---------------------------------------------------------------------------

SKILLS: dict[str, tuple[Skill, ...]] = {
    "recon": (
        Skill(
            name="alive-before-aiming", agent="recon",
            when="a mapping round starts (nothing alive known yet)",
            steps=("surface_scan once, no arguments", "read the asset inventory it filled",
                   "aim host_probe/content_discovery/crawl ONLY at hosts/ports that answered"),
            tools=("surface_scan", "host_probe", "content_discovery", "crawl"),
            exit="no step spent on a host the RoE allows but the scan did not answer",
            proof="n/a — mapping produces inventory, not findings"),
        Skill(
            name="lead-then-first-party", agent="recon",
            when="any binary/crawler tool returns leads (paths, params, ports, routes)",
            steps=("collect the leads with their (tool, claim) class",
                   "crosscheck_lead each class — first-party GET / WITH-WITHOUT pair / raw TCP",
                   "corroborated leads go forward; contradicted leads are dropped, not retried",
                   "unverifiable leads are dropped — the matrix fails closed on purpose"),
            tools=("crosscheck_lead", "http_probe"),
            exit="every lead you ACT on carries a corroborated verdict",
            proof="crosscheck verdict 'corroborated' recorded per lead"),
        Skill(
            name="auth-wall-passthrough", agent="recon",
            when="a login wall blocks mapping, or the brief supplies a token/cookie",
            steps=("authenticate with the seeded/brief credentials (multi-step login aware)",
                   "or set_session the brief-supplied token under a name",
                   "continue mapping what is behind the wall"),
            tools=("authenticate", "set_session"),
            exit="authenticated surface mapped; the held session is registered for "
                 "downstream specialists",
            proof="n/a — mapping"),
    ),
    "exploit": (
        Skill(
            name="playbook-first", agent="exploit",
            when="a technique/target pair is claimed from the attack tree",
            steps=("find_techniques(technique) and read the card",
                   "use the card's differential shape and its false-positive traps",
                   "design the check against THAT shape, not from memory"),
            tools=("find_techniques",),
            exit="the check's conditions use the card's differential shape",
            proof="the proof shape the card names"),
        Skill(
            name="ready-spec-consume", agent="exploit",
            when="the claimed node carries a synthesis draft (evidence + check_spec)",
            steps=("read the draft's evidence refs — they record WHY the node looked attackable",
                   "fire the draft's check_spec through verify_vulnerability 1:1, unmodified",
                   "a refuted draft is a closed node, not a redesigned one"),
            tools=("verify_vulnerability",),
            exit="pending_verification reached, or the draft is refuted and the node closed",
            proof="the draft's own conditions, verbatim"),
        Skill(
            name="look-then-prove", agent="exploit",
            when="holding a hypothesis worth a trial (no draft, no ready spec)",
            steps=("http_probe to shape it — contexts, response shapes, session reach",
                   "ONE verify_vulnerability with differential conditions "
                   "(status AND body/content), never status alone"),
            tools=("http_probe", "verify_vulnerability"),
            exit="check recorded pending_verification — then keep proving, never self-promote",
            proof="differential conditions"),
    ),
    "access": (
        Skill(
            name="harvest-try-prove", agent="access",
            when="a confirmed foothold exists and the kill chain names the stage to press",
            steps=("extract_secrets over material already held",
                   "try_credential the candidates — SMALL bounded burst, in-scope only",
                   "prove_privilege the boundary differentially with the held session",
                   "record_access for leads/edges discovered — never label access yourself"),
            tools=("extract_secrets", "try_credential", "prove_privilege", "record_access"),
            exit="every pressed stage ends in a proof-trial verdict or an explicit "
                 "'nothing presses further'",
            proof="prove_privilege's differential check"),
    ),
    "logic": (
        Skill(
            name="ordered-attack-vs-control", agent="logic",
            when="a workflow-shaped endpoint (cart/checkout/coupon/order/transfer) is claimed",
            steps=("state the domain assumption the app makes (coupon once, price server-side, "
                   "no step skipping, no repeats)",
                   "verify_workflow_abuse: attack_steps breaking it, control_steps doing the "
                   "SAME workflow honestly (fresh identifier), the invariant that separates them",
                   "authenticate first if the workflow needs a session"),
            tools=("verify_workflow_abuse", "authenticate"),
            exit="one correct sequence — no spraying; one-shot proofs are not re-run",
            proof="the invariant that the attack broke and the control did not"),
    ),
    "verify": (
        Skill(
            name="run-all-pending", agent="verify",
            when="any finding is pending_verification",
            steps=("verify_finding_independently(finding_id) for EACH pending finding",
                   "accept the verdict — reproduce + forced negative control decided, not you"),
            tools=("verify_finding_independently",),
            exit="zero pending findings",
            proof="the independent verdict (confirmed/refuted)"),
    ),
    "a01-access": (
        Skill(
            name="two-principal-differential", agent="a01-access",
            when="a horizontal/vertical boundary is claimed (IDOR, missing function auth)",
            steps=("authenticate YOUR own user; register a second identity if the brief has one",
                   "http_probe YOUR object as baseline, then the same shape with THEIR identifier",
                   "verify_vulnerability: status==200 on payload AND json_differs on the owner path",
                   "control: re-run YOUR id through the identical modified path — if yours fails "
                   "too, the path shape is wrong, not the boundary"),
            tools=("authenticate", "set_session", "http_probe", "verify_vulnerability"),
            exit="differential recorded with the self-control; a lone 403/404 is not a pass",
            proof="status AND body-carrying-the-OTHER-principal's-content"),
    ),
    "a03-injection": (
        Skill(
            name="reflect-map-prove", agent="a03-injection",
            when="xss_reflect_probe reports a READY check_spec (or an escaped reflection)",
            steps=("READY: fire its check_spec through verify_vulnerability 1:1, unmodified",
                   "escaped reflection: produce NO idea — do not spend budget on a dead oracle",
                   "classify the context (element/attribute/JS string/href) — the context "
                   "picks the breakout, not a payload list"),
            tools=("xss_reflect_probe", "verify_vulnerability"),
            exit="reflected_unescaped proof on YOUR marker in the claimed context",
            proof="reflected_unescaped"),
        Skill(
            name="differential-pairs-only", agent="a03-injection",
            when="a SQLi or command-injection hypothesis exists",
            steps=("probe with SAFE differential pairs (quote-then-boolean, arithmetic identity, "
                   "time pairs) — never destructive payloads",
                   "confirm only via differential response pairs or latency_delta",
                   "error text alone is plantable — it does not count"),
            tools=("http_probe", "verify_vulnerability"),
            exit="differential recorded; error-based 'confirmation' never recorded",
            proof="differential pair or latency_delta"),
    ),
    "a05-misconfig": (
        Skill(
            name="fetch-the-secret", agent="a05-misconfig",
            when="a regex-shaped lead exists (AKIA…, ghp_…, eyJ…) or a juicy path is claimed",
            steps=("http_probe the exact resource — a lead that never fetched is not a finding",
                   "crosscheck_lead any content_discovery/nuclei claim first (first-party GET)",
                   "verify_vulnerability: status==200 AND body_regex matching the secret/resource shape",
                   "kill decoys: coherent content, not just presence; placeholder values"),
            tools=("http_probe", "crosscheck_lead", "verify_vulnerability"),
            exit="the EXPOSURE proven — one request, body carrying the resource",
            proof="status==200 AND body_regex"),
    ),
    "a07-auth": (
        Skill(
            name="token-then-app", agent="a07-auth",
            when="jwt_inspect flags a token (alg none, symmetric key in claims, odd expiry)",
            steps=("jwt_inspect every held token — deterministic, offline",
                   "prove the consequence THROUGH the app: forge/resend via authenticate/"
                   "set_session + verify_vulnerability",
                   "the parse alone never proves anything"),
            tools=("jwt_inspect", "authenticate", "set_session", "verify_vulnerability"),
            exit="app-level proof (the crafted token WORKS or the control fails)",
            proof="differential with and without the tampered field"),
    ),
    "a10-ssrf": (
        Skill(
            name="two-shape-ssrf", agent="a10-ssrf",
            when="a parameter takes a URL/host/path (webhook, fetcher, importer, avatar/PDF)",
            steps=("surface_scan first — the RoE grid IS your target list, alive hosts only",
                   "learn the app's two response shapes: known-good external URL vs refused/invalid",
                   "swap the parameter to an in-scope INTERNAL target; read which shape returns",
                   "body_regex for internal-only content landing in YOUR response is the "
                   "strongest proof; blind = timing/size differential + the word 'blind'"),
            tools=("surface_scan", "http_probe", "verify_vulnerability"),
            exit="internal content reflected (proven) or an honest 'blind' differential",
            proof="body_regex on internal-only content"),
    ),
    "llm01-prompt-injection": (
        Skill(
            name="canary-movement-verdict", agent="llm01-prompt-injection",
            when="an injection payload has been delivered through any channel "
                 "(direct turn, poisoned RAG document, tool result, plan field)",
            steps=("plant a UNIQUE high-entropy canary (PIC-<16 hex>) as the protected "
                   "secret BEFORE delivery — a canary you never planted cannot be a leak",
                   "deliver the payload through the channel the technique names, then "
                   "record_finding the attempt with the delivery channel and stage",
                   "read the REAL tool-invocation trace plus the app-state ledger — never "
                   "the model's own text — for RELAYED/EXECUTED movement",
                   "confirm_finding only on a recorded invocation WITH its executed ledger "
                   "record; exposure alone is INCONCLUSIVE, refused-by-policy is an attempt",
                   "run the negative control (a never-planted run asked for the canary) "
                   "before verify_finding_independently re-derives the verdict"),
            tools=("record_finding", "confirm_finding", "verify_finding_independently"),
            exit="RELAYED or EXECUTED movement recorded with controls — or an honest "
                 "INCONCLUSIVE, never a chat-text verdict",
            proof="tool-invocation trace + executed ledger record + negative control, "
                  "not the model's reply"),
    ),
}


# ---------------------------------------------------------------------------
# Validation — fail closed, fail loud, with the offending names in the message.
# ---------------------------------------------------------------------------

def validate_agent(agent: str, profile_tool_names, registry_keys: set[str]) -> None:
    """One agent's profile vs its hands: exact set equality, registry membership."""
    held = list(profile_tool_names)
    hands = HANDS.get(agent)
    if hands is None:
        raise ValueError(f"agent '{agent}' has no HANDS entry — an agent without "
                         "declared hands is exactly the generic drift this module forbids")
    hand_tools = {h.tool for h in hands}
    if set(held) != hand_tools:
        untaught = sorted(set(held) - hand_tools)
        unheld = sorted(hand_tools - set(held))
        raise ValueError(
            f"agent '{agent}': profile tool_names and HANDS disagree — "
            f"taught-but-not-held: {untaught}; held-but-not-taught: {unheld}")
    full = registry_keys | OPTIONAL_TOOLS
    unknown = sorted(t for t in held if t not in full)
    if unknown:
        raise ValueError(f"agent '{agent}' holds tools that do not exist in the "
                         f"registry (typo?): {unknown}")
    for h in hands:
        if h.trust not in TRUST_CLASSES:
            raise ValueError(f"agent '{agent}' hand '{h.tool}': trust class "
                             f"'{h.trust}' is not in the crosscheck vocabulary {sorted(TRUST_CLASSES)}")


def validate_skills(agent: str) -> None:
    """Skills may only name tools their agent holds."""
    hands = {h.tool for h in HANDS.get(agent, ())}
    for skill in SKILLS.get(agent, ()):
        missing = sorted(t for t in skill.tools if t not in hands)
        if missing:
            raise ValueError(f"skill '{skill.name}' (agent '{agent}') references tools "
                             f"the agent does not hold: {missing}")


def validate_all(registry_keys: set[str]) -> None:
    """Validate every agent (profiles pass their tool_names; skills validated alone)."""
    for agent, hands in HANDS.items():
        validate_agent(agent, [h.tool for h in hands], registry_keys)
        validate_skills(agent)


# ---------------------------------------------------------------------------
# Briefings — deterministic renderings that ride into the worker's system prompt.
# ---------------------------------------------------------------------------

def hands_briefing(agent: str, held_tools) -> str:
    """Render the hands the agent ACTUALLY holds (a headless run has no browser)."""
    held = set(held_tools)
    lines = ["[YOUR HANDS — what each tool is, costs, and when you may believe it]"]
    for h in HANDS.get(agent, ()):
        if h.tool not in held:
            continue
        lines.append(f"  {h.tool} — {h.purpose}")
        lines.append(f"      cost: {h.cost} | trust: {h.trust}")
        lines.append(f"      owe: {h.obligation}")
    return "\n".join(lines)


def skills_briefing(agent: str, held=None) -> str:
    """Render declared skills. With ``held`` (a set of tool names), skills whose
    tools the agent cannot all raise are skipped — a briefing teaching an
    unraisable procedure is the same drift as an unheld hand."""
    lines = ["[YOUR SKILLS — procedures you may execute, entry -> exit]"]
    skills = SKILLS.get(agent, ())
    if held is not None:
        skills = tuple(s for s in skills if set(s.tools) <= set(held))
    if not skills:
        lines.append("  (none executable with your current hands — work from the "
                     "trust obligations above)")
        return "\n".join(lines)
    for s in skills:
        lines.append(f"  {s.name} — WHEN {s.when}")
        for i, step in enumerate(s.steps, 1):
            lines.append(f"      {i}. {step}")
        lines.append(f"      EXIT: {s.exit}")
        lines.append(f"      PROOF: {s.proof}")
    return "\n".join(lines)


def hands_json() -> str:
    """Introspection (DX parity with `python -m redteam.states --json` and the
    crosscheck matrix): every agent's hands and skills, with trust classes."""
    return json.dumps({
        "policy": "every held tool carries a stated purpose, cost, trust class and "
                  "obligation; every skill may only name tools its agent holds; "
                  "profile tool_names and HANDS must match exactly",
        "trust_classes": sorted(TRUST_CLASSES),
        "agents": {a: {"hands": [{"tool": h.tool, "cost": h.cost, "trust": h.trust,
                                  "purpose": h.purpose, "obligation": h.obligation}
                                 for h in hands],
                       "skills": [{"name": s.name, "when": s.when, "steps": list(s.steps),
                                   "tools": list(s.tools), "exit": s.exit, "proof": s.proof}
                                  for s in SKILLS.get(a, ())]}
                   for a, hands in HANDS.items()},
    }, ensure_ascii=False, indent=2)


def agent_names() -> list[str]:
    return sorted(HANDS)


if __name__ == "__main__":
    if "--json" in sys.argv:
        print(hands_json())
    else:
        for a in agent_names():
            n_hands = len(HANDS[a])
            n_skills = len(SKILLS.get(a, ()))
            print(f"{a}: {n_hands} hands, {n_skills} skills")
        print("use --json for the full manifest")
