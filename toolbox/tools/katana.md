# katana

JS-aware web crawler (ProjectDiscovery) — follows links and parses JavaScript
to surface endpoints a plain wordlist pass cannot see.

## Why the engine needs it

The agent tool `crawl` (`redteam/tools/webdiscover.py`) — a LEAD generator.
Discovered URLs fold into the graph (`_fold_endpoints`) as endpoint leads with
their serving origin. Same doctrine as ffuf: a crawled endpoint is a to-do —
probe with `http_probe` and verify before recording anything.

Katana matters most on SPA-heavy targets where routes live in JS bundles; the
pure-Python `spa_recon` tool covers the bootstrap-mock angle, katana covers
the link/graph angle.

## Install

Kali package: `apt-get install -y katana` (EXTRA_TOOLS layer or base list).
Catalog: `kali_pkg="katana"`. Note: katana is NOT yet in the toolbox catalog's
default set — add it to `sandbox.extra_tools` by name to have the layer build it.

## Verify

```bash
katana -version 2>/dev/null || katana -h 2>&1 | head -1
```

## Command contract — do not break these flags

```
katana -u <URL> -jsonl -silent -fs rdn -d <DEPTH> -c <CONC> -rl <RATE> -timeout <T>
```

- `-jsonl` — line-delimited JSON; the parser consumes one lead per line
- `-silent` — no banner noise on stdout
- `-fs rdn` — field-scope filter (`rdn` = relative domain names, the default
  crawl scope); keep it exactly as the engine emits it
- `-d` depth clamped to 5, `-c` concurrency to 10, `-rl` rate to 200 by the
  engine before the command is built — politeness stays engine-owned

## Scoped example

```bash
katana -u http://127.0.0.1:8897/ -jsonl -silent -fs rdn -d 3 -c 10 -rl 50 -timeout 5
```

## When it is absent

`crawl` raises the standard clear error (naming `tool_provision`). The recon
round's link extraction (in-house, from held HTML responses) still feeds the
graph — katana adds the JS-following layer on top.
