# httpx

ProjectDiscovery's HTTP prober — content-level probe of ONE in-scope URL:
title, status, length, tech detect, redirect location, IP.

## Why the engine needs it

The agent tool `host_probe` (`redteam/tools/hostprobe.py`) — a LEAD
generator. It complements `surface_scan` (which only knocks on the RoE
allowlist itself and never widens scope): httpx reveals what a host actually
SERVES, and the results fold into the graph as HOST/TECHNOLOGY leads the
planner reads.

The engine's fingerprinting sense (`observe()` sensors) works from held
responses and costs nothing; httpx is the agent-directed, one-URL deep probe.

## Install

Kali package: `apt-get install -y httpx` (EXTRA_TOOLS layer or base list).
Catalog: `kali_pkg="httpx"`, no pip distribution.

## Verify

```bash
httpx -version
```

## Command contract — do not break these flags

```
httpx -u <URL> -json -silent -no-color -status-code -content-length \
      -title -tech-detect -location -ip -timeout <T>
```

- `-json -silent -no-color` — machine-parseable stdout, one JSON object per
  probe (`_parse_httpx` reads one lead per line)
- the field flags (`-status-code -title -tech-detect ...`) exist because the
  parser expects those keys; removing one empties that lead field
- `-timeout` clamped to 1–30 s by the engine

## Scoped example

```bash
httpx -u http://127.0.0.1:8897 -json -silent -no-color -status-code \
      -content-length -title -tech-detect -location -ip -timeout 8
```

## When it is absent

`host_probe` raises the standard clear error naming `tool_provision`.
`surface_scan` (first-party, no binary) continues to cover the allowlist.
