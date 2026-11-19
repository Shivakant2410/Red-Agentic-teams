#!/usr/bin/env bash
# Builder 04 owner-facing campaign smoke run — NATIVE, no Docker, no hosted
# API key. Starts the local vulnerable lab, verifies Ollama is actually up,
# picks an installed tool-capable model, launches Classic or Adaptive Mission,
# and prints where the evidence landed.
#
# Usage:
#   bash scripts/run_campaign.sh S-INJ mission
#   bash scripts/run_campaign.sh S-AUTHZ classic
#   bash scripts/run_campaign.sh S-CHAIN mission qwen2.5:14b-instruct
set -euo pipefail
SC="${1:-}"
DRIVER="${2:-}"
MODEL="${3:-}"
cd "$(dirname "$0")/.."

if [ -z "$SC" ] || [ -z "$DRIVER" ]; then
  echo "usage: bash scripts/run_campaign.sh <scenario> <driver> [model]"
  echo "  scenario: S-EGRESS S-INJ S-AUTHZ S-BIZ S-CHAIN S-REPLAN"
  echo "  driver:   mission (adaptive) | classic"
  exit 2
fi

# 1. Ollama must REALLY be running (a configured URL is not proof).
echo "[campaign] probing Ollama..."
TAGS=$(curl -sf --max-time 5 http://127.0.0.1:11434/api/tags) || {
  echo "BLOCKER: Ollama is not running. Start Ollama and retry."
  echo "  Linux/macOS:  ollama serve"
  echo "  Windows (PS): ollama serve   (or start the Ollama app)"
  exit 2
}
MODELS=$(python3 -c "
import json,sys
try:
    d=json.loads('''$TAGS''')
except Exception:
    sys.exit(3)
names=[m.get('name') for m in d.get('models',[]) if m.get('name')]
print('\n'.join(names))
" ) || { echo "BLOCKER: Ollama returned an unreadable model list."; exit 2; }
if [ -z "$MODELS" ]; then
  echo "BLOCKER: Ollama is running, but no models are installed. Pull a supported model first:"
  echo "  ollama pull qwen2.5:7b-instruct"
  exit 2
fi
if [ -z "$MODEL" ]; then
  MODEL=$(printf '%s\n' "$MODELS" | python3 -c "
import sys
hints=('qwen3','qwen2.5','qwen2','llama3.3','llama3.2','llama3.1','mistral-nemo','mistral-small','mistral','glm4','command-r','phi4')
models=[l.strip() for l in sys.stdin if l.strip()]
pick=next((m for m in models if any(h in m.lower() for h in hints)), models[0] if models else '')
print(pick)")
  echo "[campaign] auto-selected model: $MODEL (installed: $(printf '%s ' $MODELS))"
else
  echo "[campaign] operator-selected model: $MODEL"
fi

echo "[campaign] preflight: does '$MODEL' really drive tools?"
python3 - "$MODEL" <<'PY'
import sys
sys.path.insert(0, ".")
from redteam.llm.preflight import run_preflight
model = sys.argv[1]
r = run_preflight("ollama", model=model, timeout=90)
for c in r.checks:
    print(f"  {'PASS' if c.ok else 'FAIL'}  {c.check}: {c.detail}")
if not r.ok:
    print(f"BLOCKER: {model} did not pass tool-calling preflight. Select another model:")
    print("  ollama pull qwen2.5:7b-instruct   # or llama3.1:8b / mistral-nemo")
    sys.exit(2)
print("[campaign] preflight READY")
PY

echo "[campaign] launching $SC / $DRIVER with ollama/$MODEL ..."
python3 scripts/campaign_runner.py --scenario "$SC" --driver "$DRIVER" \
  --provider ollama --model "$MODEL"
RC=$?
echo "[campaign] done (rc=$RC). Evidence: runs/campaigns/<run-id>/"
echo "  score: campaign_score.json · trace: loop_trace.md · traffic: traffic.jsonl"
exit $RC
