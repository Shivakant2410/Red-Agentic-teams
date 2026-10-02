# Red-Team Agent — Kali sandbox + Playwright, driven by OpenRouter

An agentic red-team assistant for **authorized** web-application / API security testing.
Instead of a handful of narrow tools, the agent gets two full execution surfaces:

- **A Kali Linux sandbox in Docker** — the whole offensive toolset (nmap, ffuf, sqlmap,
  nikto, gobuster, curl, …) available via `kali_exec`.
- **Playwright browser automation** — a real headless browser for anything that needs a
  DOM and JavaScript.

The model backend is **OpenRouter**, rotating across **free** models by availability.

> **Authorized use only.** Run this only against systems you own or have **written
> permission** to test (a signed SOW/engagement, or a bug-bounty program within its
> published scope), or an isolated lab. The engagement file is your authorization
> boundary.

## How "give it all of Kali" stays safe

When the agent can run arbitrary tools, you can't enforce scope by inspecting commands.
So scope is enforced at the **network layer**:

- **Sandbox egress firewall** — the Kali container runs `default-DROP` on OUTPUT. Only
  IPs/CIDRs derived from the RoE (`redteam/sandbox/egress.py`) are reachable; the
  entrypoint installs the rules before any tool runs and the container **refuses to
  start** if it can't (fail closed). Off-scope hosts are simply unreachable. On top of
  that, `KaliSandbox.start()` runs an **egress self-test**: it probes a destination that
  should never be in scope (TEST-NET-1) and tears the sandbox down if that probe
  succeeds, rather than trusting the entrypoint's "ready" log line alone — a log line
  only proves the script ran, not that the firewall rules actually took effect.
- **No self-unlocking** — tools run as a non-root user, the container drops all
  capabilities except `NET_ADMIN`/`NET_RAW`, sets `no-new-privileges`, and `kali_exec`
  refuses commands that touch iptables/ipset/routing/`sudo`/namespaces.
- **Browser scope interception** — every request the browser makes (page + every
  subresource) is checked against the scope guard; out-of-scope requests are aborted.
- **Approval gates** — destructive/DoS-shaped commands require an interactive human "yes".
- **Rate limit + request budget**, **append-only JSONL audit log**, and an
  **engagement window** the agent won't run outside of.

## Layout

```text
redteam/
  config.py          RoE + LLM (OpenRouter) + sandbox settings, validated
  scope.py           ScopeGuard — SSRF-aware target boundary
  ratelimit.py       Token-bucket limiter + request budget
  audit.py           Append-only JSONL audit log
  findings.py        Finding model + JSON store
  report.py          Markdown report
  agent.py           OpenAI-style tool-use loop (owned explicitly)
  cli.py             Entrypoint: preflight, sandbox/browser lifecycle, approvals
  llm/openrouter.py  Free-model discovery + rotation/fallback
  memory.py          ExperienceStore — persistent cross-run tradecraft lessons
  memory_backend/    Optional HelixDB (graph+vector) backend for memory.py — semantic
                      recall instead of tag matching, plus AppPattern (app-shape facts,
                      not just vuln-class technique). See its __init__.py docstring for
                      the current persistence caveat (--semantic-memory in cli.py).
  sandbox/
    Dockerfile       Kali rolling + tools + firewall deps
    entrypoint.sh    Installs the egress allowlist, then idles (fail closed)
    egress.py        RoE scope -> allowed CIDRs
    docker_kali.py   Build/start/exec/stop the container
  tools/
    kali.py          kali_exec (firewall-tamper + destructive guards)
    browser.py       browser_navigate/content/click/fill/screenshot
    workflow.py      record_finding, request_approval
config/engagement.example.yaml
tests/                test_scope.py, test_egress.py
```

## Setup

```bash
pip install -e .                        # requests, pyyaml, playwright
python -m playwright install chromium   # one-time, for the browser tools
export OPENROUTER_API_KEY=sk-or-...      # your OpenRouter key
cp config/engagement.example.yaml config/engagement.yaml   # edit to your signed scope
# Docker must be installed and running for the Kali sandbox.
```

## Run

```bash
python -m redteam.cli \
  --engagement config/engagement.yaml \
  --objective "Map the API surface and test authentication and access controls" \
  --out runs/acme-2026-09-26
```

First run builds the Kali image (large, one-time). You confirm scope at the preflight
prompt and approve sensitive actions as they come up. Outputs land in `--out`:
`report.md`, `findings.json`, `audit.log.jsonl`, `screenshots/`.

Flags: `--no-sandbox`, `--no-browser`, `--yes-to-all` (isolated labs only), `--multi-agent`
(orchestrator + specialist swarm), `--semantic-memory` (optional, needs
`pip install -e .[semantic-memory]` + Docker — see below).

## Semantic memory (optional)

`memory.py`'s `ExperienceStore` persists cross-run tradecraft (which CWE classes proved
out, which proof oracles work) as flat JSON by default, recalled by tag/keyword overlap.
`--semantic-memory` swaps in a HelixDB (graph+vector) backend instead: lessons are
recalled by *meaning*, not shared vocabulary ("broken object reference" now matches a
lesson phrased around "IDOR"), and a second kind of fact — **app-shape patterns**
("this app uses a two-step login," "sequential numeric IDs, worth enumerating") — gets
distilled from each run's knowledge graph so a brand-new target isn't started blind, the
same way vuln-proving lessons already aren't.

```bash
pip install -e .[semantic-memory]
python -m redteam.cli ... --semantic-memory
```

This starts a local HelixDB container for the run (same lifecycle pattern as the Kali
sandbox) and runs a small local embedding model (`all-MiniLM-L6-v2`, no API/network
dependency, consistent with the free-tier-only design elsewhere in this project).

**Known limitation:** the official `ghcr.io/helixdb/helixdb:v0.0.3` image did not persist
data to a mounted Docker volume across container restarts in testing — writes made in one
container's lifetime are gone after it restarts, regardless of mount path or settle time
before stopping. This upgrades recall *quality* within a run's uptime; it is not yet
durable *across* runs the way the plain-JSON path is. Treat `--semantic-memory` as a
within-session upgrade until that's root-caused (`memory_backend/helix_backend.py` has
the full note). The default (no flag) path is unaffected and remains fully persistent.

## Tests

```bash
pytest -q
```

## Notes & limits

- **Wildcard scope + sandbox:** the egress firewall opens by IP/CIDR and can't
  pre-resolve `*.example.com`. To reach wildcard subdomains from Kali tools, also list
  the covering CIDR in `scope.allowed_hosts`. The browser tool handles wildcards fine
  (it checks each request's host by name).
- **Free models vary:** not every free model supports tool calling; the router filters
  for `supported_parameters: tools` and rotates on rate-limits/outages. Availability of
  free models changes constantly — that's why discovery is live, not hardcoded.
- Add a tool by implementing `schema()` + `run(ctx, ...)` in `redteam/tools/` and
  registering it in `build_registry`.
