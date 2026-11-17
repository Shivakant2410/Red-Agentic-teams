# Core image packages

These arrive with the BASE image (`redteam/sandbox/Dockerfile` — kali-rolling +
`kali-linux-headless` + the pieces below). You do not install them one by one;
this page documents WHY each is in the base layer, because removing one breaks
a specific engine capability.

| Package | Why it is in the base image |
|---|---|
| `kali-linux-headless` | the broad offensive toolset meta-package most `kali_exec` commands assume (curl, python3 tooling, openssl, sqlmap, hydra, etc. ship via this) |
| `iptables`, `ipset`, `iproute2` | the egress firewall itself — `/usr/local/bin/entrypoint.sh` refuses to start (exit 90) without them. NEVER remove |
| `dnsutils` | `dig`/`nslookup` for scoped DNS checks; also the sanity probe for the DNS allowlist (port 53 to `DNS_SERVERS` only) |
| `ca-certificates` | TLS verification for https in-scope targets; the evidence-proxy CA is installed into this store (`update-ca-certificates`) when the proxy plane is up |
| `curl`, `wget` | the egress self-test canary (`curl` against TEST-NET-1 must FAIL) and generic fetches inside `kali_exec` |
| `git` | some tooling (nuclei template updates, tool repos) assumes git |
| `python3` | several engine hand-offs parse/verify inside the container; python3 also backs pip-installed catalog tools |
| `jq` | the standard `kali_exec` idiom `... \| jq .` for trimming JSON output before it crosses into the context |
| `seclists` | REQUIRED by the engine's `content_discovery` tool — `_WORDLISTS` in `redteam/tools/webdiscover.py` points at `/usr/share/seclists/Discovery/Web-Content/{common.txt,raft-small-words.txt,api/api-endpoints.txt}`. Without this package ffuf runs are refused with a clear error |

## The rule the base layer encodes

Everything the SANDBOX ITSELF needs to boot and enforce scope (iptables family,
curl for the canary, DNS tools) is baked at build time — because once the
container is running, its egress is default-DROP and **it cannot download
anything**. That is not a limitation to work around; it is the design. Anything
you want to add later goes through the EXTRA_TOOLS layer (a rebuild on the host
network) — see the top-level README, section "Adding tools".
