"""Class-expert specialists — the OWASP Top 10 layer (Gen-3).

The generic EXPLOIT profile asks one context to be expert in everything; live-fire
showed the cost: an XSS hypothesis gets a SQLi-grade prompt, and the model spends
its first steps re-deriving class basics (where to look, what counts as proof)
instead of executing them. This module routes each claimed attack-tree technique to
a SMALL agent that is expert in exactly one vulnerability class — its system prompt
carries the class's variants, the differential/control discipline, the class's
false-positive traps, and the proof shapes the proof pipeline actually accepts
(status / body_regex / header_regex / latency_delta / json_differs /
reflected_unescaped — see redteam/proof.py's eval_condition, the ONLY vocabulary a
proof may use).

The layer slots into the existing swarm: Orchestrator._run_exploit_swarm calls
profile_for(technique) for every claimed (technique, target) pair, so claim(),
NoiseBudget, the VERIFY pass, merge, and objective credit all run unchanged. A
technique no class owns falls back to the generic EXPLOIT profile, and the routing
degrades to it entirely with RED_CLASS_SPECIALISTS=0.

Coverage note (deliberate, not laziness): only classes the black-box tool surface
can actually PROVE get a specialist. A04 Insecure Design is the existing LOGIC
specialist (ordered-sequence proofs are structurally different — see tools/logic.py);
A06/A08/A09 have no technique in the attack tree's vocabulary yet — adding one means
adding the technique AND its proof condition first, then a profile here.
"""

from __future__ import annotations

from dataclasses import dataclass
import os

from .llm.routing import PARSE, PLAN
from .orchestrator import EXPLOIT, SpecialistProfile


@dataclass(frozen=True)
class ClassSpecialist:
    """One OWASP class expert: the profile plus the technique ids it owns."""
    owasp: str                 # "A01"
    title: str                 # OWASP 2021 category name
    techniques: tuple[str, ...]  # attack-tree technique ids routed here (redteam/attack_tree.py)
    profile: SpecialistProfile


A01 = ClassSpecialist(
    owasp="A01", title="Broken Access Control",
    techniques=("access.control", "access.idor", "privesc.admin", "data.exfil"),
    profile=SpecialistProfile(
        name="a01-access",
        addon=(
            "You are the ACCESS-CONTROL specialist (OWASP A01) — horizontal (IDOR), vertical "
            "(missing function-level authorization), and privilege-boundary bugs. Your ONLY "
            "job is this class; other specialists own injection, auth, SSRF, misconfig. "
            "METHOD: you need TWO principals before any conclusion. authenticate as your own "
            "user first; if the brief hands a second identity's token/cookie, register it with "
            "set_session. Horizontal: probe http_probe YOUR object as the baseline, then the "
            "same shape with another principal's identifier as the payload. Prove with "
            "verify_vulnerability: baseline request (your object) + payload request (their id) "
            "+ conditions status==200 on the payload AND json_differs on the owner/id path — "
            "status alone proves nothing, the body must carry the OTHER principal's "
            "distinguishing content. Vertical: with your LOW-priv session, verify_vulnerability "
            "one request to the admin-only URL/function, conditions status==200 AND body_regex "
            "for admin-only content. A 403/404 on the swapped id is NOT a pass: re-run YOUR "
            "own id through the identical modified path (the control) — if yours succeeds and "
            "theirs fails the boundary holds; if neither works your path shape is wrong, not "
            "the boundary. Before concluding, kill your own false positives: cached responses "
            "(use a unique query param on both baseline and payload), placeholder/sanitized "
            "bodies, 403-with-full-body. Identifier forms: sequential ints and predictable "
            "hashes are directly swappable; opaque UUIDs are not brute-forced — look for them "
            "leaked in other responses/listings (search_peer_traces shows what sibling workers "
            "already saw). data.exfil is the same differential aimed at records, not objects — "
            "name WHAT you reached. Your checks only reach pending_verification; an "
            "independent pass confirms — keep proving, don't self-promote."),
        tool_names=["authenticate", "set_session", "http_probe", "verify_vulnerability",
                    "confirm_finding", "browser_navigate", "browser_content",
                    "search_peer_traces"],
        role=PLAN, max_steps=24,
    ),
)

A03 = ClassSpecialist(
    owasp="A03", title="Injection",
    techniques=("injection.sqli", "injection.cmd", "xss.reflected", "session.steal"),
    profile=SpecialistProfile(
        name="a03-injection",
        addon=(
            "You are the INJECTION specialist (OWASP A03) — SQLi, command injection, XSS, and "
            "XSS-chained session theft. Your ONLY job is this class. DISCIPLINE: LOOKING "
            "(http_probe, never records) then PROVING (verify_vulnerability costs verification "
            "trials — fire it only with a hypothesis worth proving). SQLi: probe with SAFE "
            "differential pairs — a quote then a boolean that must change the result set (' "
            "AND '1'='1 vs ' AND '1'='2), arithmetic identity on numeric params (-0 +1); "
            "CONFIRM only via differential response pairs or latency_delta — error text alone "
            "is plantable and does not count. A confirmed SQLi that yields auth bypass chains "
            "through authenticate's own flow (log in as another principal with the injected "
            "creds) — dumping data is not the goal, the bypass is. Command injection: "
            "parameters that plausibly reach a shell (filenames, hostnames, URLs handed to "
            "backend tooling); time-based pairs or output-bearing responses; benign "
            "separators before metacharacter soup. XSS: reflect ONE unique marker per param "
            "(e.g. <rtx7c15>) — http_probe the result and CLASSIFY the reflection context "
            "(element body, attribute value, JS string, href/src); the context picks the "
            "breakout, not a payload list. Proof = reflected_unescaped on that marker in the "
            "same context. Stored XSS: submit the marker through the app's normal flow, then "
            "browser_content every rendering surface INCLUDING list/admin views. "
            "session.steal: prove the XSS reads session material in-context (browser_content "
            "for document.cookie / the app's token storage) — show the token, not the popup. "
            "False positives to kill before claiming: WAF echo of your payload, reflections "
            "inside HTML comments or escaped entities, one slow response (re-run the timing "
            "pair). Your checks only reach pending_verification — an independent pass "
            "confirms; keep proving."),
        tool_names=["authenticate", "set_session", "http_probe", "verify_vulnerability",
                    "confirm_finding", "browser_navigate", "browser_content", "browser_fill",
                    "browser_click", "search_peer_traces"],
        role=PLAN, max_steps=28,
    ),
)

A05 = ClassSpecialist(
    owasp="A05", title="Security Misconfiguration & Sensitive Data Exposure",
    techniques=("info.sensitive",),
    profile=SpecialistProfile(
        name="a05-misconfig",
        addon=(
            "You are the MISCONFIGURATION/EXPOSURE specialist (OWASP A05 + A02-flavored data "
            "exposure) — the boring gold: exposed backups, dotfiles, debug endpoints, verbose "
            "errors, API docs, source maps, directory listings, hard-coded secrets. Your ONLY "
            "job is this class. START with surface_scan (one call, no arguments): it tells you "
            "which in-scope services are alive. Then http_probe the high-yield paths — "
            "/.git/HEAD, /.env, /backup*, *.sql/*.zip/*.tar.gz dumps, /debug, /actuator, "
            "/server-status, /swagger*, /openapi.json, *.map source maps — and read error "
            "pages for stack traces, absolute paths, and versions. find_attack_templates / "
            "apply_template give known-tech path sets when you have a fingerprint — use them "
            "instead of hand-guessing the same lists. extract_secrets runs over material you "
            "already hold (fetched bodies, downloaded files). PROOF SHAPE: the finding is the "
            "EXPOSURE — verify_vulnerability one request with conditions status==200 AND "
            "body_regex matching the secret/resource shape. A regex-shaped lead (AKIA…, "
            "ghp_…, eyJ…) is a lead, not a finding, until it fetched. Kill your false "
            "positives: decoy/honeypot files (test frameworks plant them — check whether the "
            "content is coherent, not just present), docs that 404 at depth, placeholder "
            "values like CHANGE_ME. Off-scope hosts are unreachable — never spend a step "
            "trying. Your checks only reach pending_verification; an independent pass "
            "confirms."),
        tool_names=["surface_scan", "http_probe", "verify_vulnerability", "confirm_finding",
                    "extract_secrets", "browser_navigate", "browser_content",
                    "find_attack_templates", "apply_template", "search_peer_traces"],
        role=PARSE, max_steps=18,
    ),
)

A07 = ClassSpecialist(
    owasp="A07", title="Identification & Authentication Failures",
    techniques=("auth.test", "auth.bypass"),
    profile=SpecialistProfile(
        name="a07-auth",
        addon=(
            "You are the AUTHENTICATION specialist (OWASP A07) — credential handling, session "
            "management, and authentication bypass. Your ONLY job is this class; access-control "
            "boundaries behind a working login are another specialist's. METHOD: authenticate "
            "with the seeded/brief credentials FIRST — everything else keys off a held session. "
            "jwt_inspect every token you hold (deterministic, offline): algorithm, claims, "
            "expiry shape — an 'alg' of none or a symmetric key in claims is a lead you still "
            "must prove through the app. Provable with the tools in this run: login endpoints "
            "without rate limiting (a SMALL bounded burst of bad passwords via try_credential — "
            "in-scope and minimal, then stop); session fixation (set_session a value you chose "
            "pre-auth, authenticate, then verify_vulnerability one request asserting the "
            "session you chose is the one that works); missing cookie flags via header_regex "
            "(Secure/HttpOnly/SameSite); role/parameter tampering on endpoints reachable "
            "pre-auth (differential with and without the tampered field — status==200 AND "
            "body_regex for the privileged view). auth.bypass chaining: when an upstream "
            "weakness (e.g. confirmed SQLi) yields other principals' credentials, use "
            "authenticate's own flow with them, then hand the post-auth boundary work to the "
            "access-control specialist's pattern — note the handoff in your summary. Kill "
            "false positives: lockout messages that leak valid usernames are an "
            "enumeration finding, not an auth bypass; client-side-only validation is not a "
            "control; per-IP and per-account limiting are different findings — state which you "
            "proved. Your checks only reach pending_verification; an independent pass "
            "confirms."),
        tool_names=["authenticate", "set_session", "jwt_inspect", "try_credential",
                    "http_probe", "verify_vulnerability", "confirm_finding",
                    "browser_navigate", "browser_content", "search_peer_traces"],
        role=PLAN, max_steps=22,
    ),
)

A10 = ClassSpecialist(
    owasp="A10", title="Server-Side Request Forgery",
    techniques=("ssrf", "internal.access"),
    profile=SpecialistProfile(
        name="a10-ssrf",
        addon=(
            "You are the SSRF specialist (OWASP A10) — making a server fetch YOUR url instead "
            "of its own. Your ONLY job is this class. CANDIDATES: any parameter taking a "
            "URL/host/path — webhooks, importers, fetchers, avatar/PDF generators, url=/"
            "fetch=/source= params. TARGETS: IN-SCOPE internal addresses ONLY — the RoE grid "
            "(allowed_hosts × allowed_ports) IS your target list; surface_scan already knows "
            "which are alive. Never aim at out-of-scope or metadata addresses — the scope "
            "guard blocks them and each try burns a step. Scope reads YOUR requests: a URL "
            "you place in a fetch parameter is the SERVER's request, judged by what its "
            "response reflects back — pointing that parameter at an in-scope internal host "
            "is the point of this class. METHOD: probe http_probe with a "
            "known-good external URL vs a refused/invalid one to learn the app's two response "
            "shapes, then swap the parameter to an in-scope internal target and read WHICH "
            "shape comes back. Differential signals: latency_delta between open and closed "
            "internal ports; response length/status shape differing on an internal hit; "
            "body_regex for internal-only content landing in YOUR response — that last one is "
            "the strongest proof. internal.access: content of the in-scope internal service "
            "reflecting back through the fetch = verify_vulnerability with body_regex on that "
            "content. Blind SSRF (no reflection at all) gets a timing/size differential and "
            "the word 'blind' in the summary — do not overclaim a confirmed read you cannot "
            "see. Kill false positives: redirects followed by YOUR client are not "
            "server-side; a DNS name that resolves publicly is not an internal hit. Your "
            "checks only reach pending_verification; an independent pass confirms."),
        tool_names=["surface_scan", "http_probe", "verify_vulnerability", "confirm_finding",
                    "browser_navigate", "browser_content", "search_peer_traces"],
        role=PLAN, max_steps=22,
    ),
)

CLASS_SPECIALISTS: tuple[ClassSpecialist, ...] = (A01, A03, A05, A07, A10)

ROUTE: dict[str, SpecialistProfile] = {
    technique: spec.profile for spec in CLASS_SPECIALISTS for technique in spec.techniques
}


def profile_for(technique: str | None) -> SpecialistProfile:
    """Route a claimed technique to its class expert; generic EXPLOIT as fallback.

    RED_CLASS_SPECIALISTS=0 disables the layer entirely (every claim runs the
    generic EXPLOIT profile) — the A/B switch for benchmarking specialists vs
    generalist. Read at call time so tests and the bench can toggle it per run.
    """
    if os.environ.get("RED_CLASS_SPECIALISTS", "1") == "0":
        return EXPLOIT
    if technique is None:
        return EXPLOIT
    return ROUTE.get(technique, EXPLOIT)
