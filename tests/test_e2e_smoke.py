"""End-to-end smoke test of the real stack, with no LLM calls.

Every bug the first live runs hit was invisible to the unit tests: CRLF in the sandbox
entrypoint, IPv6 entries fed to iptables, a missing non-root user, nmap's privilege
setup under no-new-privileges, a log-read race, Chromium not installed, Playwright used
across threads, and passive recon stalling on unroutable container IPs. This drives the
real lab container, Kali sandbox, firewall and browser the way a benchmark run does.

Opt-in (needs Docker and the redteam-kali image): RUN_E2E=1 pytest tests/test_e2e_smoke.py
"""

from __future__ import annotations

import dataclasses
import os
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor

import pytest

pytestmark = pytest.mark.skipif(os.environ.get("RUN_E2E") != "1",
                                reason="end-to-end smoke test; set RUN_E2E=1 (needs Docker)")

from redteam.bench import runner  # noqa: E402
from redteam.bench.targets import get_target  # noqa: E402
from redteam.config import load_engagement  # noqa: E402
from redteam.knowledge import KnowledgeGraph  # noqa: E402
from redteam.ratelimit import RateLimiter  # noqa: E402
from redteam.recon.passive import run_passive_recon  # noqa: E402
from redteam.sandbox.docker_kali import KaliSandbox  # noqa: E402
from redteam.scope import ScopeGuard  # noqa: E402
from redteam.tools.browser import BrowserController  # noqa: E402

CONTAINER = "bench-e2e-smoke"
OUT_OF_SCOPE = "1.1.1.1"


class _Audit:
    def __init__(self):
        self.events = []

    def record(self, event, **fields):
        self.events.append({"event": event, **fields})


@pytest.fixture(scope="module")
def lab(tmp_path_factory):
    """The vulnerable lab profile, joined to the sandbox network like a benchmark run."""
    target = get_target("lab-authz-broken")
    subprocess.run(target.docker_build(), check=True, capture_output=True)
    subprocess.run(["docker", "rm", "-f", CONTAINER], capture_output=True)
    subprocess.run(target.docker_run(CONTAINER), check=True, capture_output=True)
    try:
        runner._ensure_network()
        subprocess.run(["docker", "network", "connect", runner.REDTEAM_NETWORK, CONTAINER],
                       check=True, capture_output=True)
        ip = runner._container_ip_on_network(CONTAINER)
        assert runner._wait_for(f"http://localhost:{target.host_port}/health", timeout=60)
        eng_path = tmp_path_factory.mktemp("e2e") / "engagement.yaml"
        runner._write_engagement(target, eng_path, ip)
        eng = load_engagement(eng_path)
        eng = dataclasses.replace(eng, sandbox=dataclasses.replace(
            eng.sandbox, container_name="redteam-kali-e2e"))
        yield target, ip, eng
    finally:
        subprocess.run(["docker", "rm", "-f", CONTAINER], capture_output=True)


@pytest.fixture(scope="module")
def sandbox(lab):
    _, _, eng = lab
    audit = _Audit()
    sb = KaliSandbox(eng, audit=audit)
    sb.start()   # raises unless the firewall printed ready AND the canary probe proved the block
    try:
        yield sb, audit
    finally:
        sb.stop()


def test_egress_selftest_ran_and_proved_the_block(sandbox):
    _, audit = sandbox
    selftest = [e for e in audit.events if e["event"] == "sandbox.egress_selftest"]
    assert selftest and selftest[0]["reached"] is False


def test_tools_run_as_the_non_root_operator(sandbox):
    sb, _ = sandbox
    assert sb.exec("id -un").stdout.strip() == "operator"


def test_in_scope_reachable_out_of_scope_blocked(lab, sandbox):
    target, ip, _ = lab
    sb, _ = sandbox
    url = f"http://{ip}:{target.container_port}/health"
    assert sb.exec(f"curl -s -o /dev/null -w '%{{http_code}}' -m 5 {url}").stdout.strip() == "200"
    out = sb.exec(f"curl -s -o /dev/null -w '%{{http_code}}' --connect-timeout 3 "
                  f"http://{OUT_OF_SCOPE}/ || echo BLOCKED").stdout
    assert "BLOCKED" in out


def test_ipv6_is_locked_down_too(sandbox):
    sb, _ = sandbox
    rules = subprocess.run(["docker", "exec", "-u", "root", sb._cfg.container_name,
                            "ip6tables", "-S", "OUTPUT"], capture_output=True, text=True).stdout
    assert "-P OUTPUT DROP" in rules


def test_nmap_runs_unprivileged(lab, sandbox):
    target, ip, _ = lab
    sb, _ = sandbox
    out = sb.exec(f"nmap -Pn -p {target.container_port} {ip}", timeout=90)
    assert f"{target.container_port}/tcp open" in out.stdout, out.stderr


def test_passive_recon_does_not_stall_on_unroutable_addresses(lab):
    _, _, eng = lab
    started = time.monotonic()
    run_passive_recon(eng, KnowledgeGraph())
    # 22 of the 24 candidate bases are unreachable from the host; each must cost one
    # connect attempt, not one per path (that was ~11 minutes).
    assert time.monotonic() - started < 150


def test_browser_works_from_swarm_worker_threads(lab, tmp_path):
    target, _, eng = lab
    browser = BrowserController(ScopeGuard(eng), RateLimiter(100, 1000), _Audit(), tmp_path)
    url = f"http://localhost:{target.host_port}/health"
    try:
        with ThreadPoolExecutor(max_workers=3) as pool:
            results = list(pool.map(lambda _: browser.navigate(url), range(3)))
        assert all(r["status"] == 200 for r in results)
    finally:
        browser.close()
