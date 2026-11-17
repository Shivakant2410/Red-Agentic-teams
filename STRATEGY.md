# Gen-2 attack doctrine — the strategy, stated

This engine does not run a vulnerability checklist. The strategy is
**triangulate → falsify → prove → chain**, and every phase below is that same
loop applied to a different kind of material. Anything that cannot name its
material, its prediction, and its kill condition does not get executed.

## 1. Recon = material acquisition (what we HOLD)

Every sense is first-party where possible and passive where it cannot be:

| Sense | Module | Touches the app? | Feeds |
|---|---|---|---|
| Crawl, robots/openapi, links | `_round_recon` | yes (scoped) | paths, params, app name |
| Wordlist content discovery (~52 paths) | `_workflow_content_discovery` | yes (scoped) | leads, gates, files |
| Tech fingerprinting | `observe()` sensors | no (parses held responses) | `technologies` |
| AI-infra shapes | `observe()` sensors | no (parses held responses) | `ai_surface`, `ai_models` |
| Service banners + api indexes | `observe()` sensors | no | `api_paths` |
| **Port scan (nmap → connect-scan fallback)** | `portscan.py` | yes (TCP connect, RoE ports only) | `_services` → service discovery |
| **Kali toolbox (provisioned arjun/nmap/…)** | `sandbox/provision.py` + `tool_provision` | binaries only; execution via scoped tools | resolved binaries for param_discovery / port_scan |
| crt.sh / DNS / cert SAN | `osint.py` | **never** (passive) | inventory candidates |

Rule: OSINT and fingerprints never cost an attack packet; active discovery
never exceeds RoE ports/hosts; **every fetch — including fetches of
port-scan-discovered services — passes the ScopeGuard and the rate limiter.**
Provisioning is requirement-driven but **traffic-separated**: the Kali image
layer builds on the host network (the container's default-DROP egress must
stay that way), the sandbox-less mode installs into a project venv, and
`resolve()` — the lookup the engine calls mid-run — never downloads.

## 2. Exploit = signal-combination falsification (not payloads)

Bets are minted when **≥2 independent signal classes triangulate a
condition** — never from one observable:

- cookie-issued × auth-gate → cookie-forge (CWE-284)
- token-shape × realm-gates → bearer-pivot
- two principals × id-observed → cross-principal-read (CWE-639)
- ai-infra × documented invoke → ai-infra-abuse (CWE-306)
- portscan service × sensitive-shape body → exposed-service-data (CWE-200)

Each bet is a **falsifiable hypothesis**: a prediction ("forged cookie is
accepted, real token alone is not"), an estimated request budget
(`HORIZON_EST` — bets that cannot finish are deferred, not spent), and a kill
condition ("401/403 consistent → real API check"). A kill is not a failure;
killed branches re-activate when their material grows (`REACTIVATE_ON`).

## 3. Proof = the pipeline owns the verdict

The engine never declares a bug. `verify_vulnerability` replays the probe
k-of-n with a **negative control** (a sibling request that must behave
differently) and records the finding with the requests + conditions that
decided it. The engine's own triage (`_preobserve`) only decides WHERE to
spend the proof budget, never WHETHER a bug exists.

## 4. Post-exploitation = postcondition-driven chaining (not a sweep)

After the first verify pass with confirmations, `_round_postexploit` writes
the **postcondition ledger** (`state.confirmed_kinds`) — what the exploits
actually yielded — and the brain mints the next moves FROM those yields:

- CWE-306 confirmed (owned model gateway) → **R9 ai-prompt-leak**: extraction
  prompts against the asset we now hold; config-shaped output = CWE-200.
- harvested tokens → R6 re-aims them at every realm the signals revealed
  (the issuing surface is not the authority surface).
- new principals → reactivation of cross-principal/workflow branches.

Admission is double-gated: a post-exploit bet must cite a CONFIRMED
postcondition AND evidenced paths. Nothing is generic; every follow-up is
chained from material this run holds in its hands.

## 5. Objective = the kill chain decides what matters

`killchain.py` stages the run (reconnaissance → … → exfiltration) and
`recommend()` asks the operator's question — *given what we hold and where
the objective is, which tactic advances?* — so a vulnerability matters only
insofar as it yields a credential, a session, a host, or the objective.

## The one-line summary

**Recon acquires material; the brain triangulates material into falsifiable
bets; the proof pipeline rules on them; post-exploitation mines the confirmed
bets' outputs into new bets — and the scope guard gates every packet on the
way.**
