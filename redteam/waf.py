"""WAF / anti-bot block detection — so the agent STOPS scanning and SWITCHES.

The failure this fixes: a target behind Cloudflare (or similar) answers curl /
httpx / raw HTTP with a challenge page ("Just a moment…", HTTP 403/503 + a
cf-mitigated / cf-chl marker). A scanner-minded agent reads that as a normal
failed request and RETRIES THE SAME WAY — burning tokens, learning nothing,
never getting past the wall. The remedy a human knows instantly: a real browser
passes Cloudflare's passive challenge, so switch to the browser tools.

detect_waf_block(text, status) returns a short, ACTIONABLE note when the
response looks like a WAF/anti-bot block, else "". Tool layers attach that note
to their result so the model sees "you are blocked by Cloudflare — use
browser_navigate / browser_session_status, which pass it" instead of raw block
bytes it will just retry against.
"""
from __future__ import annotations

import re

# Markers that appear in Cloudflare / common anti-bot challenge responses.
_CF_MARKERS = (
    "just a moment",
    "checking your browser",
    "cf-chl",                 # cf challenge token
    "cf_chl",
    "challenge-platform",
    "cf-mitigated",
    "attention required",     # CF 1020 block page
    "enable javascript and cookies to continue",
    "__cf_bm",                # CF bot-management cookie
    "cloudflare",
    "akamai",                 # other common WAFs
    "incapsula",
    "perimeterx",
    "datadome",
)

# A WAF block is far more likely on these statuses; a 200 with a marker is the
# interstitial, a 403/503/429 with a marker is an outright block.
_BLOCK_STATUSES = {401, 403, 406, 429, 503}


def detect_waf_block(text: str | None, status: int | None = None) -> str:
    """Return an actionable remediation note if `text`/`status` looks like a
    WAF/anti-bot challenge, else "". Cheap substring scan, safe on any input."""
    body = (text or "").lower()
    hit = next((m for m in _CF_MARKERS if m in body), "")
    # A challenge interstitial ("just a moment") or a block status with any
    # marker both count; a bare block status with no marker is left alone (could
    # be a legitimate 403 the agent should reason about normally).
    challenge = ("just a moment" in body or "checking your browser" in body
                 or "challenge-platform" in body)
    blocked = hit and (challenge or (status in _BLOCK_STATUSES))
    if not blocked:
        return ""
    waf = "Cloudflare" if any(m in body for m in
                              ("cf-chl", "cf_chl", "challenge-platform",
                               "cf-mitigated", "__cf_bm", "cloudflare",
                               "just a moment")) else "a WAF/anti-bot service"
    return (
        f"WAF_BLOCK: this response is a {waf} challenge/block, not real content. "
        f"Retrying curl/httpx/raw HTTP the same way will keep being blocked — do "
        f"NOT repeat it. A real browser passes {waf}'s passive challenge: switch "
        f"to browser_navigate (and browser_session_status to check if the session "
        f"is already warmed/authenticated). If the browser ALSO hits an interactive "
        f"CAPTCHA/Turnstile, stop and report that a human must warm the session — "
        f"do not keep hammering it."
    )


def looks_like_waf(text: str | None, status: int | None = None) -> bool:
    return bool(detect_waf_block(text, status))
