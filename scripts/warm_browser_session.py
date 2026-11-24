"""Warm an authenticated browser session for the human-in-the-loop handoff.

Cloudflare's interactive challenge (Turnstile) and a site's login form cannot be
solved by automation — and hammering them trips the automated-defenses that
bug-bounty policies forbid. So a HUMAN solves the challenge and logs in ONCE,
here, in the same persistent Chrome profile the agent will later reuse. The
agent then starts already authenticated and does its autonomous recon/probing
against that warmed session, never having to beat Cloudflare itself.

Usage (you, the authorized researcher, run this):

    # point the agent and this script at the SAME profile dir
    export RED_BROWSER_PROFILE="$HOME/.red-agentic/target-profile"
    python scripts/warm_browser_session.py https://target.example/

A real Chrome window opens. Solve any Cloudflare challenge, accept cookies, and
log in with your test account (e.g. your @bugcrowdninja.com). When the page
shows you authenticated, press Enter in this terminal. The cookies persist in
the profile dir; launch the agent run with the same RED_BROWSER_PROFILE (and
RED_BROWSER_REAL_CHROME=1) and it will reuse this logged-in session.

This script NEVER asks for or stores your password — you type it into the real
browser yourself, exactly as you would normally.
"""
from __future__ import annotations

import os
import sys
import tempfile


def main() -> int:
    start_url = sys.argv[1] if len(sys.argv) > 1 else "https://target.example/"
    profile = os.environ.get("RED_BROWSER_PROFILE")
    if not profile:
        profile = os.path.join(tempfile.gettempdir(), "red-agentic-browser-profile")
        print(f"[warm] RED_BROWSER_PROFILE not set; using {profile}")
        print("[warm] Set RED_BROWSER_PROFILE to the SAME path for the agent run,")
        print("[warm] or the agent won't reuse this session.")
    print(f"[warm] profile dir: {profile}")

    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        print("[warm] playwright not installed: pip install playwright && "
              "python -m playwright install chrome", file=sys.stderr)
        return 2

    channel = os.environ.get("RED_BROWSER_CHANNEL", "chrome")
    ua = os.environ.get(
        "RED_BROWSER_UA",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    )
    with sync_playwright() as pw:
        ctx = pw.chromium.launch_persistent_context(
            profile,
            headless=False,            # the human needs to see and interact
            channel=channel,
            args=["--disable-blink-features=AutomationControlled",
                  "--no-first-run", "--no-default-browser-check"],
            user_agent=ua, locale="en-US",
            viewport={"width": 1366, "height": 900},
        )
        ctx.add_init_script(
            "Object.defineProperty(navigator,'webdriver',{get:()=>undefined});")
        page = ctx.pages[0] if ctx.pages else ctx.new_page()
        page.goto(start_url, wait_until="domcontentloaded", timeout=60000)
        print("\n" + "=" * 68)
        print("A Chrome window is open. In it:")
        print("  1. Solve any Cloudflare 'Just a moment' / Turnstile challenge")
        print("  2. Accept the cookie banner")
        print("  3. Log in with your TEST account (never a real member)")
        print("  4. Confirm you see the authenticated UI")
        print("Then come back here and press Enter to save the session.")
        print("=" * 68)
        try:
            input("[warm] press Enter when logged in... ")
        except EOFError:
            print("[warm] no interactive stdin; leaving the window open 180s.")
            page.wait_for_timeout(180_000)
        try:
            print(f"[warm] current URL: {page.url}")
            print(f"[warm] title: {page.title()!r}")
            cookies = ctx.cookies()
            print(f"[warm] {len(cookies)} cookies saved to the profile.")
        except Exception as exc:  # noqa: BLE001
            print(f"[warm] note: {exc}")
        ctx.close()
    print("[warm] session saved. Launch the agent with the SAME "
          "RED_BROWSER_PROFILE and RED_BROWSER_REAL_CHROME=1.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
