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
  start** if it can't (fail closed). Off-scope hosts are simply unreachable.
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

Flags: `--no-sandbox`, `--no-browser`, `--yes-to-all` (isolated labs only).

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
