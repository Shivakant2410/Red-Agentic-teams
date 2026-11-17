# ffuf

Fast web fuzzer — the engine's structured content discovery against ONE
in-scope base URL.

## Why the engine needs it

The agent tool `content_discovery` (`redteam/tools/webdiscover.py`) is a
**LEAD generator**: discovered paths fold into the knowledge graph as
ENDPOINT leads and gate candidates. They are to-dos, not findings — the note
in the tool's own output says so, and `http_probe` + verification must happen
before anything is recorded.

The engine's own recon round ALSO runs an in-house wordlist pass
(`_workflow_content_discovery`, ~52 paths, pure Python) — ffuf is the
agent-directed deeper pass with the SecLists corpora.

## Wordlists — the hard dependency

`_WORDLISTS` in webdiscover.py pins absolute paths:

| key | path |
|---|---|
| `common` | `/usr/share/seclists/Discovery/Web-Content/common.txt` |
| `raft-small` | `/usr/share/seclists/Discovery/Web-Content/raft-small-words.txt` |
| `api-endpoints` | `/usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt` |

⇒ **`seclists` must be in the image** (it now is, in the base layer). If you
build a bare kali without it, ffuf runs are refused before they start.

## Install

Kali package: `apt-get install -y ffuf` (part of the EXTRA_TOOLS layer or add
it to the base `apt-get install` list). Catalog: `kali_pkg="ffuf"`, no pip.

## Verify

```bash
ffuf -V
```

## Command contract — do not break these flags

```
ffuf -u <URL>FUZZ -w <WORDLIST_PATH> -json -s -ac -rate <RATE> -t <CONC> -timeout <T> -of json
```

- `-json -s` and `-of json` — the parser reads ffuf's JSON results; anything
  non-JSON on stdout yields zero leads
- `-ac` — auto-calibration filters noise, keeps leads honest
- `-rate` / `-t` are clamped by the engine (`_MAX_RATE 200`, `_MAX_CONCURRENCY 30`)
  — politeness is enforced engine-side, not delegated to the binary
- `FUZZ` is appended to the target URL by the engine; targets pass the
  ScopeGuard before the command is ever built

## Scoped example

```bash
ffuf -u http://127.0.0.1:8897/FUZZ \
     -w /usr/share/seclists/Discovery/Web-Content/common.txt \
     -json -s -ac -rate 50 -t 10 -timeout 5 -of json
```

## When it is absent

`content_discovery` raises a clear error naming `tool_provision` (sandbox-less)
or needs the sandbox image. The engine's own Python wordlist pass still runs —
discovery degrades, it does not break.
