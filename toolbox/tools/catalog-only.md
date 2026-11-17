# gobuster, whatweb, nikto, wafw00f, sqlmap — catalog-only tools

These five are in the toolbox catalog (`redteam/sandbox/provision.py`) and can
be provisioned/invoked through `kali_exec` today, but the engine has NO
dedicated structured consumer for them yet (no parser, no lead contract, no
workflow wiring). That means:

- `tool_provision` knows their names and install channels
- `kali_exec` can run them inside the sandbox (scope enforced by the egress
  firewall; destructive patterns need approval)
- nothing parses their output into the graph automatically — YOU read it

| Tool | Kali pkg | pip | Verify | What it would add |
|---|---|---|---|---|
| gobuster | `gobuster` | — | `gobuster version` | directory/vhost/DNS brute force — alternative to ffuf, same wordlist discipline |
| whatweb | `whatweb` | — | `whatweb --version` | technology fingerprinting beyond the engine's in-house `observe()` sensors |
| nikto | `nikto` | — | `nikto -Version` | broad web-server checks — treat every hit as a lead, never a finding |
| wafw00f | `wafw00f` | `wafw00f` | `wafw00f -V` | WAF fingerprinting — informs the opsec/quiet-mode decisions |
| sqlmap | `sqlmap` | `sqlmap` | `sqlmap --version` | SQL-injection exploration — **requires operator approval** for any intrusive level; engine doctrine prefers first-party reflection proofs |

## Install

Via the EXTRA_TOOLS image layer (recommended — the layer is cached per
toolset):

```bash
docker build -t redteam-kali:latest -f redteam/sandbox/Dockerfile \
    --build-arg EXTRA_TOOLS="gobuster whatweb nikto wafw00f sqlmap" \
    redteam/sandbox/
```

or pip channels in the sandbox-less toolbox (`scripts/tool_provision.py
ensure --tool wafw00f` etc. — wafw00f and sqlmap have PyPI distributions).

## Verify all five at once

```bash
for t in gobuster whatweb nikto wafw00f sqlmap; do
  docker exec -u operator redteam-kali-run \
    sh -c "command -v $t >/dev/null && echo $t OK || echo $t MISSING"
done
```

## Doctrine reminder

Everything these tools output is **lead material**. The engine records a
finding only through the proof pipeline; a nikto/sqlmap match that has not
been reproduced and verified first-party does not enter the report.
