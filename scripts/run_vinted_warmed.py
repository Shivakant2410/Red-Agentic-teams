"""Launch a warmed-session Vinted run — the human-in-the-loop handoff, end to end.

Precondition (you, the authorized researcher, do this FIRST):
    export RED_BROWSER_PROFILE="$HOME/.red-agentic/vinted-profile"
    export RED_BROWSER_REAL_CHROME=1
    python scripts/warm_browser_session.py https://www.vinted.com/
    # solve Cloudflare, accept cookies, log in with your @bugcrowdninja.com, press Enter

Then launch the run (reuses that SAME profile, already authenticated):
    export OPENROUTER_API_KEY=...            # already in your .env
    python scripts/run_vinted_warmed.py

Why this launcher instead of the dashboard: a warmed Cloudflare session only
survives if the agent's browser uses the SAME real-Chrome profile WITHOUT the
evidence proxy (the proxy changes the TLS fingerprint and Cloudflare re-
challenges). The dashboard launch path uses the proxy + sandbox defaults. This
sets no_sandbox + no_evidence_proxy + browser-not-through-proxy and forces the
real-Chrome profile, so the agent inherits the human-warmed session.

It honours the Vinted program: browser-only (no Kali scanners), low rate
(engagement.vinted.yaml caps rps=1, 400 total), https-only, www.vinted.com only.
"""
from __future__ import annotations

import os
import sys
import datetime as _dt
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
ENGAGEMENT = str(REPO / "config" / "engagement.vinted.yaml")
OBJECTIVE = (
    "Perform an authorized web-application assessment of www.vinted.com as an "
    "AUTHENTICATED test user (the session is already warmed). Reason about THIS "
    "marketplace's domain — actors (buyer/seller), objects they own (listings, "
    "offers, orders, bundles, balance), and the money/ownership/state-transition "
    "flows between them. Form attack theses about business-logic and access-"
    "control flaws with financial or account-takeover impact, and probe them at a "
    "human trickle. Only ever act on objects YOU own; never touch a real member's "
    "data. Confirm every candidate with a second independent method before "
    "treating it as a finding — no generic scanner output."
)


def main() -> int:
    # 1. Force the real-Chrome, human-warmed profile for the agent's browser.
    os.environ.setdefault("RED_BROWSER_REAL_CHROME", "1")
    profile = os.environ.get("RED_BROWSER_PROFILE")
    if not profile:
        print("[run] RED_BROWSER_PROFILE is not set. Set it to the SAME path you")
        print("[run] warmed with scripts/warm_browser_session.py, then re-run.")
        return 2
    if not os.environ.get("OPENROUTER_API_KEY"):
        print("[run] OPENROUTER_API_KEY not set (source your .env first).")
        return 2
    print(f"[run] using warmed profile: {profile}")

    # 2. Verify the warmed session BEFORE spending a run: open the profile and
    #    check we're authenticated and not sitting on a Cloudflare challenge.
    try:
        from playwright.sync_api import sync_playwright
        with sync_playwright() as pw:
            ctx = pw.chromium.launch_persistent_context(
                profile, headless=True, channel=os.environ.get("RED_BROWSER_CHANNEL", "chrome"),
                args=["--disable-blink-features=AutomationControlled",
                      "--no-first-run", "--no-default-browser-check"])
            page = ctx.pages[0] if ctx.pages else ctx.new_page()
            page.goto("https://www.vinted.com/", wait_until="domcontentloaded", timeout=45000)
            page.wait_for_timeout(3000)
            title = page.title()
            challenged = "just a moment" in title.lower()
            body = page.content()
            # crude logged-in signal: a logout/account control or member link
            authed = ("logout" in body.lower() or "/member/" in body.lower()
                      or "wardrobe" in body.lower())
            ctx.close()
        print(f"[run] warm check: title={title!r} challenged={challenged} authed~={authed}")
        if challenged:
            print("[run] Cloudflare is still challenging this profile. Re-warm it")
            print("[run] (scripts/warm_browser_session.py) and try again.")
            return 3
        if not authed:
            print("[run] WARNING: could not confirm an authenticated session. The run")
            print("[run] will still map the public surface; re-warm + log in for the")
            print("[run] authenticated reasoning. Continuing in 3s... (Ctrl-C to abort)")
            try:
                import time
                time.sleep(3)
            except KeyboardInterrupt:
                return 1
    except Exception as exc:  # noqa: BLE001
        print(f"[run] warm check skipped ({exc}); continuing to launch.")

    # 3. Launch the run — browser-only, no sandbox, no proxy (preserve the warmed
    #    TLS fingerprint), events on so the dashboard/watcher can follow it.
    from redteam.run import RunOptions, execute_run
    from redteam.events import EventBus

    stamp = _dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    out = REPO / "runs" / f"{stamp}-vinted-warmed"
    out.mkdir(parents=True, exist_ok=True)
    bus = EventBus(run_id=out.name, sink_path=out / "events.jsonl")

    print(f"[run] launching -> {out.name}")
    print("[run] watch it in the dashboard, or tail runs/<id>/audit.log.jsonl")
    summary = execute_run(RunOptions(
        engagement_path=ENGAGEMENT,
        objective=OBJECTIVE,
        out_dir=out,
        events=bus,                # event stream for the dashboard / watcher
        multi_agent=True,          # full orchestrator (recon -> theses -> exploit/logic)
        max_steps=40,
        no_sandbox=True,           # browser-only; Kali scanners off (program rule)
        no_evidence_proxy=True,    # no proxy: keep the warmed Cloudflare session intact
        browser_through_proxy=False,
        yes_to_all=False,          # production: approvals stay interactive
        quiet=False,
        on_text=lambda t: print(t, "\n"),
    ))
    print(f"[run] done. run dir: {out}")
    print(f"[run] theses: {out / 'thesis.jsonl'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
