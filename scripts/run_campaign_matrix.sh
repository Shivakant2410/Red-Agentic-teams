#!/usr/bin/env bash
# Sequential Builder 04 campaign matrix — dual-provider era
# (OpenRouter primary + z-ai GLM fallback; see campaign_runner.py).
# Quota-disciplined priority order: cheap control first, core evidence next.
# Usage: bash run_campaign_matrix.sh <phase-tag> [scenario:driver ...]
set -u
cd /home/z/my-project/repo
TAG="${1:?phase tag e.g. baseline}"
shift || true
RUNS=("$@")
if [ ${#RUNS[@]} -eq 0 ]; then
  RUNS=(S-EGRESS:mission S-AUTHZ:mission S-CHAIN:mission S-REPLAN:mission \
        S-INJ:mission S-BIZ:mission S-INJ:classic S-AUTHZ:classic)
fi
mkdir -p runs/campaigns
LOG=runs/campaigns/matrix-${TAG}.log
echo "campaign matrix ${TAG} — $(date)" | tee "$LOG"
for pair in "${RUNS[@]}"; do
  sc="${pair%%:*}"; dr="${pair##*:}"
  echo "=== START $sc/$dr $(date +%H:%M:%S)" | tee -a "$LOG"
  python3 scripts/campaign_runner.py --scenario "$sc" --driver "$dr" --tag "$TAG" \
    >> "$LOG" 2>&1
  echo "=== END $sc/$dr rc=$? $(date +%H:%M:%S)" | tee -a "$LOG"
  sleep 60  # provider cooldown between campaigns
done
grep -E "^=== END|verdict=" "$LOG"
