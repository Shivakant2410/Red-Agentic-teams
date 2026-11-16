# nmap

Network mapper — the engine's ONLY network-layer sense, and the reason
`portscan` produces real service fingerprints instead of "port is open".

## Why the engine needs it

Two consumers, one contract:

| Consumer | File | What it feeds |
|---|---|---|
| engine recon round `_workflow_portscan` | `redteam/offensive.py` | discovered services → `_services` → the exploit round's service-discovery workflow |
| agent tool `port_scan` | `redteam/tools/hostprobe.py` | HOST/SERVICE/TECHNOLOGY nodes folded into the knowledge graph (planner, bandit buckets, priors read them) |

The port list is **RoE-derived** (`engagement.allowed_ports` minus the known
base port, hard-capped at 16 extra ports in the workflow) — nmap never decides
what to scan. The host must pass the ScopeGuard.

## Install

Kali package (the only channel): `apt-get install -y nmap`. In the toolbox
catalog (`redteam/sandbox/provision.py`) it is `kali_pkg="nmap"`, no pip
distribution — if you build the image without it, the engine silently falls
back to the stdlib **TCP connect scan** (open/closed only, no service names).

## Verify

```bash
docker exec -u operator redteam-kali-run nmap --version
# Nmap version 7.x
```

## Command contract — do not break these flags

`redteam/portscan.py` (`nmap_scan`) builds:

```
nmap -Pn -sV --version-light -oX - -p <PORTS> <HOST>
```

`redteam/tools/hostprobe.py` (`_build_nmap_command`) builds:

```
nmap -Pn -sV --version-light -T3 --open -oX - [-p <PORTSPEC>] <HOST> [--top-ports N]
```

Why each flag is load-bearing:

- `-Pn` — scoped lab hosts may drop ICMP; treat-as-alive is correct here (the
  host is already RoE-authorized)
- `-sV --version-light` — service fingerprints, deliberately NOT `-sC`/`--script`:
  no NSE script sweeping against an in-scope app without an operator decision
- `-T3` — no timing aggression; politeness is a rate-limit decision, not a scan flag
- `--open` — only reachable things cross into the context
- `-oX -` — **XML to stdout**; the parser reads `portid` + `state[state=open]`
  + `service[name,product,version,extrainfo]`. Any output change that is not
  XML-on-stdout silently degrades to the connect-scan fallback

## Scoped example

```bash
# inside the sandbox (or any host allowed by RoE)
nmap -Pn -sV --version-light -T3 --open -oX - -p 8897,80,443 127.0.0.1
```

## When it is absent

`nmap_scan()` returns `None` → `portscan.scan()` falls back to
`tcp_connect_scan` and reports `"open/connect"` for each open port. The matrix
stays deterministic; you just lose product/version strings.
