#!/usr/bin/env bash
# Push Phase C1 (collective intelligence foundation) and open its PR.
# Usage: REDTEAM_TOKEN=ghp_xxx bash scripts/push_c1.sh
#
# Workflow rules (standing): code goes branch -> PR, NEVER merged by this script;
# the token is used transiently here and must be REVOKED by the operator right after.
set -euo pipefail

REPO_URL="https://github.com/Shivakant2410/Red-Agentic-teams.git"
BRANCH="phase-c1-collective-intelligence"
BASE="phase-b5-strategy-memory"

TOKEN="${REDTEAM_TOKEN:-${1:-}}"
if [ -z "$TOKEN" ]; then
  echo "ERROR: provide a fresh token: REDTEAM_TOKEN=ghp_xxx bash scripts/push_c1.sh" >&2
  exit 1
fi

cd "$(dirname "$0")/.."   # repo root

echo "== branch =="
git rev-parse --abbrev-ref HEAD | grep -q "^$BRANCH$" || {
  echo "ERROR: expected to be on $BRANCH" >&2; exit 1; }
git status --porcelain | grep -q . && {
  echo "ERROR: working tree not clean — commit first" >&2; exit 1; }

AUTH_REPO="https://x-access-token:${TOKEN}@github.com/Shivakant2410/Red-Agentic-teams.git"

echo "== push $BRANCH (base: $BASE) =="
git push "$AUTH_REPO" "$BRANCH"

echo "== open PR ($BRANCH -> $BASE) =="
PR_BODY_FILE="pr_body_c1.md"
python3 - "$PR_BODY_FILE" <<'PYEOF' > /tmp/pr_body_c1.json
import json, sys
print(json.dumps({"title": "Phase C1: collective intelligence foundation - hypothesis registry, research forum, relationships, event replay",
                  "head": "phase-c1-collective-intelligence",
                  "base": "phase-b5-strategy-memory",
                  "body": open(sys.argv[1], encoding="utf-8").read()}))
PYEOF
curl -s -X POST \
  -H "Authorization: Bearer $TOKEN" \
  -H "Accept: application/vnd.github+json" \
  https://api.github.com/repos/Shivakant2410/Red-Agentic-teams/pulls \
  -d @/tmp/pr_body_c1.json | python3 -c "
import json, sys
r = json.load(sys.stdin)
if 'number' in r:
    print(f\"PR #{r['number']}: {r['html_url']} (state={r['state']}, mergeable={r.get('mergeable')})\")
else:
    print('PR response:', json.dumps(r)[:400])
"

rm -f /tmp/pr_body_c1.json
echo ""
echo "== done. NO merge was performed — review and merge in the UI. =="
echo "   Merge order: B2(#2) -> B3(#4) -> B4(#5) -> B5(#6) -> C1(this PR)."
echo "   REVOKE THE TOKEN NOW."
