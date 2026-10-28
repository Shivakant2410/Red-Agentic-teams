"""Distill APP-SHAPE patterns from a run's KnowledgeGraph + audit log before they're
discarded at run end — the piece ExperienceStore's vuln-class Lesson recall has no
equivalent for (see memory.py's briefing()). Deterministic, like reflect_on_run: these
are facts read off what actually happened this run, never an LLM's guess at a pattern.

Patterns are generic descriptions, not raw secrets or target-identifying detail (no
hostnames/URLs/credentials) — the point is "what SHAPE did this app have," reusable on a
completely different target, not "what did THIS target have."
"""

from __future__ import annotations

import json
import re
from urllib.parse import urlsplit


def reflect_app_patterns(graph, audit_events: list[dict]) -> list[tuple[str, list[str]]]:
    """Returns [(description, tags), ...] — generic, reusable facts about the app's
    shape, derived from this run's graph/audit log. Never raw hostnames/secrets."""
    patterns: list[tuple[str, list[str]]] = []

    if graph is not None:
        patterns.extend(_login_flow_patterns(graph))
        patterns.extend(_endpoint_naming_patterns(graph))

    patterns.extend(_credential_patterns(audit_events))
    return patterns


def _login_flow_patterns(graph) -> list[tuple[str, list[str]]]:
    """A two-step login (submit username alone, THEN password on a second request keyed
    by the username) is a real app-shape fact worth remembering — it's exactly what
    tripped up a run that only tried single-request logins (see Phase 5 notes)."""
    from ..knowledge import ENDPOINT
    out = []
    paths = [urlsplit(n.key).path for n in graph.nodes(ENDPOINT)]
    # A path with a {username}-shaped segment following a plain POST-only login path is
    # the signature of a two-step flow (e.g. /password/<username> after a bare / POST).
    has_param_path = any(re.search(r"/[a-z_]+/[\w.-]+/?$", p) for p in paths
                         if not p.rstrip("/").endswith(tuple(["login", "logout", "dashboard"])))
    if has_param_path:
        out.append((
            "Some apps use a TWO-STEP login: a first POST with only the username, which "
            "redirects to a second page/endpoint parameterized by that username (e.g. "
            "/password/<username>) where the password is actually submitted. A single "
            "combined username+password POST will 404 or no-op on these — check for a "
            "redirect or a second form after the first submit before giving up on login.",
            ["auth-flow", "login"],
        ))
    return out


def _endpoint_naming_patterns(graph) -> list[tuple[str, list[str]]]:
    """Sequential numeric-ID resource paths (the IDOR shape) vs. UUID/slug-based ones —
    worth flagging because it changes whether ID enumeration is even worth trying."""
    from ..knowledge import ENDPOINT
    out = []
    numeric_id_paths = 0
    for n in graph.nodes(ENDPOINT):
        path = urlsplit(n.key).path
        if re.search(r"/\d{1,8}(/|$)", path):
            numeric_id_paths += 1
    if numeric_id_paths >= 2:
        out.append((
            "This app's resource paths include small sequential numeric IDs (e.g. "
            "/resource/<n>). When a check later shows missing ownership validation, "
            "sequential IDs make enumeration cheap — prioritize trying nearby/adjacent "
            "IDs (not just id-1/id+1 but also round numbers) once authenticated.",
            ["idor", "endpoint-shape"],
        ))
    return out


def _credential_patterns(audit_events: list[dict]) -> list[tuple[str, list[str]]]:
    """If login guessing burned many turns before anything authenticated, that is itself
    a reusable lesson: check for seeded demo/test credentials in page source/docs/robots
    BEFORE brute-guessing usernames."""
    out = []
    failed_then_ok = False
    fail_count = 0
    for e in audit_events:
        ev = e.get("event", "")
        if ev == "authenticate.failed":
            fail_count += 1
        elif ev == "authenticate.ok" and fail_count >= 3:
            failed_then_ok = True
            break
    if failed_then_ok:
        out.append((
            f"Login guessing burned {fail_count}+ failed attempts before one succeeded "
            "this run. Benchmark/demo apps often seed an obvious test account (test/test, "
            "demo/demo, admin/admin) rather than requiring real enumeration — check page "
            "source, /robots.txt, README-style routes, or a visible signup flow for a "
            "seeded account BEFORE guessing usernames one at a time.",
            ["auth", "hygiene"],
        ))
    return out
