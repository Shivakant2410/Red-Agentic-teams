# Kali Toolbox — manual build & integration guide

You are building the sandbox image **on your own machine, with Docker**. This
folder is the manual for that: how to build the image, how the engine plugs
into it, what each tool contributes, and how to verify the security model
actually engaged before any tool fires.

```
toolbox/
├── README.md          <- you are here: build + integrate + verify
├── skills.md          <- what the engine does WITHOUT binaries (skills, first-party tools)
└── tools/             <- one page per binary: purpose, install, verify,
    ├── nmap.md           the exact command contract the engine builds,
    ├── httpx.md          scoped examples, and what degrades when absent
    ├── ffuf.md
    ├── katana.md
    ├── arjun.md
    ├── nuclei.md
    ├── catalog-only.md  <- gobuster / whatweb / nikto / wafw00f / sqlmap
    └── core-packages.md <- what the base layer must contain and why
```

## 1. The security model — read this before you build

The image is not "kali with tools". The engine drives it under these
invariants, and every one of them is verified at startup:

1. **Default-DROP egress.** `entrypoint.sh` installs an iptables OUTPUT
   policy that drops everything except: loopback, established/related, DNS to
   the configured resolvers, and the RoE allowlist (injected as
   `ALLOWED_CIDRS`). If the rules cannot be installed, the container EXITS
   non-zero (exit 90) — it never runs wide open.
2. **The canary.** After start, the engine tries to reach `192.0.2.1`
   (TEST-NET-1 — reserved for documentation, never legitimately in scope).
   If that packet gets through, the firewall did not apply, and the engine
   **refuses to run any tool** — fail closed, not a warning.
3. **Least privilege.** The container runs with `--cap-add=NET_ADMIN` (only
   the entrypoint's firewall install needs it), everything else dropped, plus
   `NET_RAW` for nmap/ping, `no-new-privileges`, memory/CPU/pids caps. Tool
   commands run as the non-root **`operator`** user, who cannot alter the
   firewall rules.
4. **No runtime downloads — by design.** Because egress is default-DROP, the
   running container cannot fetch packages. Adding a tool = rebuilding the
   image layer on the HOST network (section 4). This keeps provisioning
   traffic permanently separate from test traffic.
5. **Guardrails on the shell.** `kali_exec` refuses commands that would tamper
   with the firewall/network namespace or escalate privileges; destructive or
   DoS-shaped commands require explicit human approval. Everything is audited.

## 2. Prerequisites

- Docker (any recent version; the engine shells out to the `docker` CLI, no
  Python docker dependency)
- ~6 GB free disk (kali-linux-headless is large)
- Network access for the BUILD (host-side — kali repos)
- The repository checked out; paths below assume its root

## 3. Build the base image

```bash
cd <repo-root>
docker build -t redteam-kali:latest -f redteam/sandbox/Dockerfile redteam/sandbox/
```

Build context MUST be `redteam/sandbox/` (the Dockerfile COPYs
`entrypoint.sh` from it). Base layer contents and their load-bearing roles:
see `tools/core-packages.md` (`seclists` is in there now — the engine's
`content_discovery` refuses to run without it).

## 4. Adding tools — the EXTRA_TOOLS layer

Two equivalent ways; both bake tools at BUILD time (host network):

**a) Let the engine do it (recommended).** List catalog tool NAMES in the
engagement file — the engine rebuilds with exactly those packages and reuses
a cached layer per toolset:

```yaml
# engagement.yaml
sandbox:
  enable: true
  image: redteam-kali:latest
  extra_tools: [nmap, arjun, ffuf, katana, httpx, nuclei]
```

`KaliSandbox.ensure_tools()` (called by `run.py` before start) builds a tag
like `redteam-kali:tools-1a2b3c4d` — content-addressed from the sorted
package list, so the same toolset never rebuilds.

**b) Do it by hand:**

```bash
docker build -t redteam-kali:latest \
  -f redteam/sandbox/Dockerfile \
  --build-arg EXTRA_TOOLS="nmap arjun ffuf katana httpx nuclei" \
  redteam/sandbox/
```

Valid names = the catalog in `redteam/sandbox/provision.py` (`CATALOG`):
`nmap arjun ffuf gobuster nuclei whatweb nikto wafw00f sqlmap` — plus any
other kali package if you build manually (e.g. `katana`, `httpx`, which are
not in the catalog yet). Unknown names passed through the engine's
`ensure_tools` are filtered out with the catalog as the whitelist.

## 5. Wire the engine to the image — full engagement block

```yaml
sandbox:
  enable: true                  # false = sandbox-less mode (toolbox venv fallback)
  image: redteam-kali:latest    # or the tools-<hash> tag from a manual build
  dockerfile: redteam/sandbox/Dockerfile
  network_name: redteam-net     # created automatically if missing
  dns: ["1.1.1.1"]              # the ONLY resolvers the firewall allows
  command_timeout: 300          # per kali_exec, seconds
  container_name: redteam-kali-run
  memory: 2g
  cpus: "2"
  extra_tools: []               # catalog names -> EXTRA_TOOLS layer
```

On `run.py` start you should see, in order:

```
Tool layer: nmap, arjun -> redteam-kali:tools-xxxxxxxx   (only if extra_tools)
Starting Kali sandbox (this can take a while on first build)...
Sandbox egress allows: <RoE CIDRs>
Egress self-test: PASS (confirmed an out-of-scope destination is unreachable)
```

If the self-test line says anything else, STOP — the sandbox refused to run
tools and the run continues sandbox-less (honest degradation, `kali_exec`
disabled).

## 6. Verify the sandbox by hand (5 commands)

```bash
# 1. firewall really applied (entrypoint ran as root)
docker logs redteam-kali-run | tail -5          # expect "egress locked: N allowed..."

# 2. you are the unprivileged user
docker exec -u operator redteam-kali-run id     # uid=1000 operator

# 3. tools present
docker exec -u operator redteam-kali-run \
  sh -c 'nmap --version | head -1; ffuf -V 2>/dev/null; arjun -h >/dev/null 2>&1 && echo arjun OK'

# 4. in-scope reach works (lab on your host: use the docker bridge gateway IP)
docker exec -u operator redteam-kali-run \
  curl -s -m 5 -o /dev/null -w '%{http_code}\n' http://<BRIDGE-GW>:8897/

# 5. out-of-scope is IMPOSSIBLE (this must FAIL / time out)
docker exec -u operator redteam-kali-run \
  curl -s -m 3 http://192.0.2.1/ || echo BLOCKED-OK
```

The engine performs (4) and (5) automatically at every start — the canary is
not optional and cannot be skipped.

## 7. How the agent gets tools "based on requirement"

| Situation | Path |
|---|---|
| Sandbox running, tool present | `kali_exec` / `param_discovery` / `port_scan` just run it |
| Sandbox running, tool missing | `tool_provision` reports the honest truth: rebuild required (egress blocks runtime installs). Add the name to `extra_tools`, restart |
| No docker (sandbox-less) | `tool_provision` installs into the project venv `.tools/venv` (pip channel; apt only as root); every binary consumer resolves PATH → venv |
| You, manually | the `docker build --build-arg EXTRA_TOOLS=...` command in section 4 |

Resolution order everywhere: **sandbox → PATH → .tools/venv → in-house
fallback**. Provisioning places binaries only; execution always goes through
the RoE-checked tools. `resolve()` — the lookup the engine uses mid-run —
never downloads anything.

## 8. Troubleshooting

| Symptom | Meaning / fix |
|---|---|
| container exits 90 immediately | iptables unusable — the image was launched without `--cap-add=NET_ADMIN` (only the engine's `docker run` knows the full cap set; don't hand-run the container, use the engine) |
| `EGRESS SELF-TEST FAILED` | the firewall did not apply despite "ready" — kernel lacks iptables support or a runtime quirk; the engine already refused to continue. Do NOT work around it; fix the runtime |
| `sandbox did not confirm egress lockdown` | entrypoint never printed ready — check `docker logs` for the FATAL line |
| build fails at `kali-linux-headless` | kali repo flake or disk full; retry the build (apt cache layers are cheap) |
| `content_discovery` refuses, mentions seclists | image built without `seclists` — rebuild with the current Dockerfile (it is in the base layer now) |
| tool X "not in the running sandbox image" | expected — bake it via `extra_tools` / EXTRA_TOOLS and restart; the message says exactly this |
| DNS resolves but nothing connects | the target's IP/CIDR is not in the RoE allowlist — the firewall is working; widen the RoE, not the firewall |
| everything times out at start | `docker network create redteam-net` failed or a stale container name is stuck: `docker rm -f redteam-kali-run` |

## 9. What the image does NOT need

Everything in `skills.md` — the skill library, first-party probes, the whole
proof pipeline — runs with zero binaries. A bare base image passes the full
matrix (15 TP / 1 FP / 0 FN); the toolbox adds richer LEADS (service
fingerprints, hidden params, JS-crawled endpoints), not correctness.
