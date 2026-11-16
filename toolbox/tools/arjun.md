# arjun

Hidden-parameter discovery — finds parameter names an app accepts but does not
surface. Parameters are LEADS, never findings.

## Why the engine needs it

The agent tool `param_discovery` (`redteam/tools/webdiscover.py`) runs it
against ONE in-scope URL. Its output (candidate parameter names) rides the
lead payload into **verification hints** — the authorization matrix,
reflection checks, mass-assignment probes. A parameter name alone proves
nothing; the engine will not record a finding from it.

## Install — two CLI generations, both supported

| Channel | Package | CLI generation |
|---|---|---|
| apt (Kali image layer) | `arjun` (arjun 1.x) | `-oJ`, `-rate`, `--stable`, `-T` |
| pip (sandbox-less toolbox) | `arjun` (arjun 2.x) | `-o`, `-t`, `-d`, `--rate-limit` |

The engine AUTO-DETECTS the generation once per process (`_arjun_style()` in
webdiscover.py, discriminator: `--rate-limit` in `-h` output ⇒ pip 2.x). You
can have either installed; do not expect flags from one to work on the other.

## Verify

```bash
arjun -h 2>&1 | grep -o -- "-oJ\|--rate-limit" | head -1
# -oJ          -> kali 1.x
# --rate-limit -> pip 2.x
```

## Command contract — do not break these flags

Kali 1.x path (JSON file via `-oJ`):

```
arjun -u <URL> -oJ /tmp/arjun_out.json -rate <RATE> -t 5 --stable -T <T> >/dev/null 2>&1 ; cat /tmp/arjun_out.json
```

pip 2.x path (real shell semantics; only the target is quoted):

```
arjun -u <URL> -o /tmp/arjun_out.json -t 5 -d 0.25 >/dev/null 2>&1 ; cat /tmp/arjun_out.json 2>/dev/null ; true
```

Parser (`_parse_arjun`) accepts both output shapes: `{"params": [...]}` and
the batch mode `{url: {"params": [...]}}`. Note pip-2.x writes the JSON file
ONLY when parameters are found — no file means zero leads, which is a valid,
honest result.

## Scoped example

```bash
arjun -u http://127.0.0.1:8897/api/generate -o /tmp/arjun_out.json -t 5 -d 0.25
```

## When it is absent

`param_discovery` raises a clear error naming `tool_provision` (sandbox-less)
or runs inside the sandbox if the image has it. No in-house reimplementation —
parameter discovery without arjun is simply not offered, rather than faked.
