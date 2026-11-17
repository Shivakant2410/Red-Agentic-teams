#!/usr/bin/env python3
"""Debug probe: what does first-party recon + extract_secrets see on a lab target?"""
import os
import subprocess
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))
import requests  # noqa: E402
from redteam.bench.targets import LAB_FETCHER, LAB_TRACKR  # noqa: E402
from scripts.live_offensive_run import build_ctx, wait_alive, write_engagement  # noqa: E402
from redteam.config import load_engagement  # noqa: E402
from redteam.offensive import OffensiveEngine  # noqa: E402
from redteam.tools import build_registry  # noqa: E402


def probe(target, port_slug):
    run_dir = REPO / "runs" / "debug" / port_slug
    run_dir.mkdir(parents=True, exist_ok=True)
    write_engagement(target, run_dir / "engagement.yaml")
    eng = load_engagement(str(run_dir / "engagement.yaml"))
    proc = subprocess.Popen(target.cmd, cwd=str(REPO),
                            env={**os.environ, **(target.env or {})},
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        assert wait_alive(target.base_url), "target down"
        ctx = build_ctx(eng, run_dir)
        tools = build_registry(enable_sandbox=False, enable_browser=False)
        eng_obj = eng
        engine = OffensiveEngine(eng_obj, tools=tools, ctx=ctx, log=print)
        engine._base_override = target.base_url
        engine._base = target.base_url.rstrip("/")
        recon = engine._round_recon()
        print("PATHS:", recon["paths"])
        print("PARAMS:", recon["params"])
        for lead in engine._leads:
            print(f"  lead {lead.trust:<12} {lead.crosscheck:<12} {lead.method:<5} "
                  f"{lead.url} param={lead.param!r} src={lead.source_tool}")
        # extract_secrets over the openapi/robots material we hold
        for lead in engine._leads:
            if lead.note and ("openapi" in lead.url or "robots" in lead.url
                              or "debug" in lead.url):
                res = tools["extract_secrets"].run(ctx, text=lead.note[:20000],
                                                   context=lead.url)
                print(f"SECRETS({lead.url}):", res[:400])
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()


if __name__ == "__main__":
    probe(LAB_TRACKR, "trackr")
    print("=" * 60)
    probe(LAB_FETCHER, "fetcher")
