# nuclei

ProjectDiscovery's template-based vulnerability scanner — the engine's only
third-party CHECK-database consumer.

## Why the engine needs it

The agent tool `nuclei_scan` (`redteam/tools/nuclei.py`) — explicitly a LEAD
generator, and the discipline is written into its own docstring: **a nuclei
match is where verification STARTS, not where it ends**. Matches become leads
that must survive the proof pipeline (`verify_vulnerability` /
`verify_finding_independently`) before anything is recorded. Nuclei output is
never folded into findings directly.

Templates: the `templates` argument is either a comma list of tag words
(`-tags`) or concrete template paths (`-t`, must exist on disk — bake them or
`docker cp` them; the egress firewall blocks runtime downloads).

## Install

Kali package: `apt-get install -y nuclei` (EXTRA_TOOLS layer or base list).
Catalog: `kali_pkg="nuclei"`, no pip. Template bundles are a separate decision
(see "Templates" above) — the binary alone ships without the full corpus.

## Verify

```bash
nuclei -version
```

## Command contract — do not break these flags

```
nuclei -u <URL> -silent -json -rl <RATE> -c <CONC> -timeout <T> [-severity S] [-tags ... | -t path ...]
```

- `-json` — one JSON object per match on stdout; the parser consumes lines
- `-rl` rate limit is clamped engine-side before build — third-party scanners
  do NOT set their own pace against an in-scope app
- `-silent` — matches only, no banner

## Scoped example

```bash
nuclei -u http://127.0.0.1:8897/ -silent -json -rl 50 -c 10 -timeout 5 -severity medium,high
```

## When it is absent

`nuclei_scan` raises the standard clear error (naming `tool_provision`) or
needs the image. The engine's proof pipeline does not depend on nuclei — it is
an idea source, not a gate.
