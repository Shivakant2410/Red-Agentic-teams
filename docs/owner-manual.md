# Owner manual — run the platform natively (no Docker, no hosted API key)

This is the exact setup for manual end-to-end testing on a 32 GB RAM laptop.
The default workflow uses **local Ollama** — no OpenAI/Z.ai/Gemini/OpenRouter
key is required. Docker is optional and never needed.

Windows PowerShell commands are listed first; Linux/macOS equivalents follow in
each step.

---

## 1. Requirements

| Component | Version | Check |
|---|---|---|
| Python | ≥ 3.10 (3.12 recommended) | `python --version` |
| Node.js | ≥ 20 (or Bun ≥ 1.1) | `node --version` |
| Ollama | any recent build | `ollama --version` |
| RAM | 32 GB comfortable; 16 GB works with a 7–8 B model | — |

## 2. Install the Python package

PowerShell:

```powershell
cd C:\path\to\Red-Agentic-teams
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e .
```

Linux/macOS:

```bash
cd /path/to/Red-Agentic-teams
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

The sandbox egress firewall and ScopeGuard run in-process; nothing else to install.

## 3. Install and start Ollama

1. Install from <https://ollama.com/download> (Windows installer, macOS app,
   Linux `curl -fsSL https://ollama.com/install.sh | sh`).
2. Start it (the desktop app usually starts it automatically):

PowerShell:

```powershell
ollama serve
```

3. Pull a **tool-capable** model (this is the recommended default):

```powershell
ollama pull qwen2.5:7b-instruct
```

Alternatives that pass tool-calling preflight in practice: `qwen2.5:14b-instruct`,
`llama3.1:8b`, `llama3.2:3b`, `mistral-nemo`. Avoid plain "reasoning-only" or
chat-only builds — they fail the preflight honestly (see step 6).

4. List installed models (the dashboard shows the same list):

```powershell
ollama list
```

## 4. Build the dashboard

The FastAPI server serves the dashboard as a static export from
`dashboard/out` at `/`. Build it once after checkout:

PowerShell:

```powershell
cd dashboard
npm install
npm run build
cd ..
```

Linux/macOS: same commands (`npm install && npm run build`), or
`bun install && bun run build` if you use Bun.

## 5. Start the backend (API + dashboard in one process)

PowerShell:

```powershell
python -m redteam.server --host 127.0.0.1 --port 8000 --runs-root runs
```

Linux/macOS: identical.

Open <http://127.0.0.1:8000/> — the dashboard loads from the same process.

## 6. Create an authorized engagement and launch (URL-first)

1. In **LAUNCH ASSESSMENT**, enter the **target URL** (e.g.
   `https://demo.testfire.net`, or `http://127.0.0.1:8901` for a local lab).
2. Enter the **objective**, e.g.
   "Assess the authorized web application for security weaknesses and provide
   independently verified findings."
3. Fill **Authorization**: authorized-by name, ticket/reference, window
   (start/end dates), and tick the confirmation box. For a loopback/lab target
   enable "local / private lab target" — without it the launch is refused
   (fail-closed, same rule ScopeGuard enforces per request).
4. Review the **scope summary** shown before launch: it lists the exact
   host:port in scope, the intensity dial, and states that everything else —
   including redirects and discovered hosts — is re-checked against this scope
   on every request.
5. Pick the **model provider**. `Ollama (local, no key)` is the default. The
   panel probes Ollama for real:
   - connected → "Ollama connected — N models available" and the **model**
     selector fills with your installed models (a usable one is preselected);
   - not running → "Ollama is not running. Start Ollama and retry."
   - no models → "Ollama is running, but no models are installed. Pull a
     supported model first."
6. **Preflight** runs automatically once a model is selected (and can be
   re-run): it verifies reachability, model presence, and — with a harmless
   synthetic call — that the model can actually emit a parseable tool call.
   A model that fails shows:
   "The selected model did not pass tool-calling preflight. Select another
   model." — launch stays blocked until a passing model is selected.
7. Choose the mode (**Classic** run or **Adaptive mission**) and press
   **LAUNCH RUN / LAUNCH MISSION**. You are redirected to the run page
   (`/runs?id=…`) with live events, task/phase progress, tool calls and
   results, discovered assets, pending approvals, findings (pending vs
   confirmed), and the final report link.

Engagement files are generated server-side into the run directory
(`runs/<run_id>/engagement.yaml` + `authorization.json`) and validated by the
same loader the CLI uses — you never write YAML by hand.

## 7. Inspect evidence and reports

- Run page → **REPORT** button (`/api/runs/<run_id>/report`, markdown).
- Per-run artifacts on disk: `runs/<run_id>/` — `events.jsonl` (the durable
  telemetry), `traffic.jsonl` (request/response evidence), `findings.json`,
  `mission.json` + `mission_journal.jsonl` (missions), `authorization.json`.
- Only findings promoted by the independent verifier (k-of-n differential with
  negative control) are `confirmed`; everything else stays
  `pending_verification`/`tentative` and is shown as such.

## 8. Stop a run safely

Run page → **STOP** (two-step confirm) — writes a kill-file the engine checks;
the agent finishes its current step and halts with an honest stop reason.

## 9. Campaign validation (local, reproducible, no Docker)

The bundled deterministic vulnerable lab (`lab/campaign_lab.py`, pure Python)
hosts five scenario families: SQL injection (S-INJ), broken authorization /
IDOR (S-AUTHZ), business-logic coupon stacking (S-BIZ), multi-step chain
traversal→token→takeover→flag (S-CHAIN), and evidence-driven replanning
(S-REPLAN), plus an out-of-scope egress denial control (S-EGRESS).

Self-test of the lab itself (no model needed):

```powershell
bash scripts/test_campaign_lab.sh     # 32/32 PASS expected
```

Real-model campaign (Ollama):

```powershell
bash scripts/run_campaign.sh S-INJ mission
bash scripts/run_campaign.sh S-AUTHZ mission
```

The script probes Ollama, auto-picks an installed tool-capable model, runs the
preflight (blocking on failure), launches the run, and prints where evidence
landed (`runs/campaigns/<run-id>/` — `campaign_score.json` ground-truth
scoring + `loop_trace.md`). Scoring is independent of the agent: it reads the
recorded traffic and checks the actual exploit artifacts.

Public-target smoke test (`https://demo.testfire.net`): launch it from the
dashboard with intensity `low`, a narrow single-host scope (that is what the
URL-first flow generates), and the objective limited to non-destructive
checks. Never brute-force, dump data, or run unrestricted active scans against
the public instance; if authorization for an active test cannot be
established, do not execute it. Report public-target results separately from
local-lab validation.

## 10. Troubleshooting

| Symptom | Meaning / fix |
|---|---|
| "Ollama is not running. Start Ollama and retry." | The backend probed `http://127.0.0.1:11434/api/tags` and got no answer. Start `ollama serve`; use the "ollama endpoint" field for a remote host. |
| "no models are installed" | `ollama pull qwen2.5:7b-instruct`, then press RE-PROBE. |
| "did not pass tool-calling preflight" | The model cannot emit tool calls. Pull `qwen2.5:7b-instruct` / `llama3.1:8b` and select it. |
| Launch refused: "authorization confirmation is required" / "authorized_by is required" | Fill the authorization section — this is the fail-closed RoE path, not a bug. |
| "target … is a loopback host — enable allow private ranges" | Local-lab target: tick "local / private lab target" in the authorization section. |
| "scope self-targeting: the control plane binds …" | Your target host:port overlaps the API server itself. Use a different port for the backend (`--port`). |
| Run detail shows "RUN NOT FOUND" | The run id predates the current `--runs-root`; check the overview list. |
| Dashboard shows old form | Rebuild: `cd dashboard && npm run build`, restart the server (it serves `dashboard/out`). |

## 11. What runs where (authorities, unchanged)

- Scope: `ScopeGuard` + the generated RoE — every request, redirects included.
- Attack-task selection: `AttackTree` (missions claim from its frontier).
- Task/claim authority: `MissionScheduler`.
- Findings: `FindingStore`; only the independent verifier promotes to
  `confirmed` — specialist narration never does.
- Telemetry: `events.jsonl` is the single source of truth for the dashboard.
