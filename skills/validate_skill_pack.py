"""Validate the category-folder skill catalog against the repo's own machinery.

Layout consumed:

    categories/<folder>/<slug>.json   — one Skill object per file
    mocks.json                        — name -> {vuln:{req:[status,body,elapsed,headers]},
                                                benign:{...}}

Gates:
  G1 schema     — load via redteam.skills.SkillLibrary (Skill(**row) is strict:
                  any extra/missing key or wrong type breaks the load).
  G2 structure  — params == placeholders discovered in url/body; substitute() fills
                  every placeholder; every condition is one of the 6 DSL types with
                  the required keys and references only existing request names;
                  the attack request is named "payload" (negative-control hook).
  G3 falsifiability — all conditions must PASS on the vulnerable mock set, and the
                  repo's own run_negative_control must NOT falsify on the benign set
                  (i.e. a benign control request fails at least one condition).

Usage:  python3 validate_skill_pack.py [/path/to/Red-Agentic-teams]
        (arg wins; else env RAT_REPO; else the repo root one level up when the
        pack lives inside Red-Agentic-teams as skills/)
"""
from __future__ import annotations

import json
import os
import re
import sys
import tempfile
from pathlib import Path

REPO = (sys.argv[1] if len(sys.argv) > 1
        else os.environ.get("RAT_REPO")
        or str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, REPO)

from redteam.skills import SkillLibrary, substitute          # noqa: E402
from redteam.proof import eval_condition                     # noqa: E402
from redteam.falsify import run_negative_control             # noqa: E402

BASE = Path(__file__).resolve().parent
CATS = BASE / "categories"
MOCKS = json.loads((BASE / "mocks.json").read_text(encoding="utf-8"))

VALID_CONDITIONS = {
    "status": {"request", "equals"},
    "body_regex": {"request", "pattern"},
    "header_regex": {"request", "pattern"},
    "latency_delta": {"request_a", "request_b", "min_delta"},
    "json_differs": {"request_a", "request_b", "json_path"},
    "reflected_unescaped": {"request", "token"},
}

DUMMY = {"probe_url": "https://t.invalid/echo", "baseline_url": "https://t.invalid/obj/1",
         "payload_url": "https://t.invalid/obj/2", "base_url": "https://t.invalid",
         "pollute_url": "https://t.invalid/merge", "reveal_url": "https://t.invalid/err",
         "authorize_url": "https://t.invalid/oauth/authorize",
         "client_id": "cid123", "legit_token": "eyJlegit", "forged_token": "eyJforged",
         "role_name": "app-server-role",
         # Batch B (AI shelves): llm_mock convention params — see AUTHORING.md §2.5
         "chat_url": "https://t.invalid/v1/chat/completions",
         "prompt_canary": "XCANARY7f3a9d",
         "attacker_url": "https://collab.invalid/u",
         "mcp_url": "https://t.invalid/mcp/tools",
         "jailbreak_trigger": "KBSIG-CLASSIC-TRIGGER"}

failures: list[str] = []
total = 0
shelves: dict[str, list[dict]] = {}
for fdir in sorted(CATS.iterdir()):
    if fdir.is_dir():
        shelves[fdir.name] = [json.loads(jf.read_text(encoding="utf-8"))
                              for jf in sorted(fdir.glob("*.json"))]

names_seen: set[str] = set()
ids_seen: set[str] = set()

for folder in sorted(shelves):
    loaded_counts = []
    for jf in sorted((CATS / folder).glob("*.json")):
        row = json.loads(jf.read_text(encoding="utf-8"))
        label = f"{folder}/{jf.stem}"
        if row["name"] in names_seen:
            failures.append(f"{label}: G1 FAIL — duplicate skill name {row['name']!r}")
        names_seen.add(row["name"])
        if row["id"] in ids_seen:
            failures.append(f"{label}: G1 FAIL — duplicate id {row['id']!r}")
        ids_seen.add(row["id"])

        # --- G1: schema gate — the repo's own strict loader -------------------
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as tf:
            json.dump([row], tf)
            tmp_path = tf.name
        try:
            lib = SkillLibrary(tmp_path)
            got = lib.summary()["skills"]
        finally:
            import os
            os.unlink(tmp_path)
        if got != 1:
            failures.append(f"{label}: G1 FAIL — SkillLibrary loaded {got}/1 "
                            f"(schema mismatch: {row['name']!r})")
            continue
        total += 1

        s = lib.all()[0]
        if s.id != row["id"] or len(s.id) != 12:
            failures.append(f"{label}: G1 FAIL — id lost/malformed through loader")
        if len(s.requests) != len(row["requests"]):
            failures.append(f"{label}: G2 FAIL — request names lost through loader")

        # --- G2: structure gate ----------------------------------------------
        missing_params = [p for p in s.params if p not in DUMMY]
        if missing_params:
            failures.append(f"{label}: G2 FAIL — unknown params {missing_params} "
                            f"(validator DUMMY dict needs them)")
            continue
        concrete = substitute(s.requests, {p: DUMMY[p] for p in s.params})
        for name, spec in concrete.items():
            blob = json.dumps(spec)
            if re.search(r"\{\{\w+\}\}", blob):
                failures.append(f"{label}: G2 FAIL — unresolved parameter placeholder in {name}")
            if not spec.get("url"):
                failures.append(f"{label}: G2 FAIL — request {name} has no url")
        if "payload" not in s.requests:
            failures.append(f"{label}: G2 FAIL — no 'payload' request (negative-control hook dead)")
        for c in s.conditions:
            t = c.get("type")
            if t not in VALID_CONDITIONS:
                failures.append(f"{label}: G2 FAIL — unknown condition type {t!r}")
                continue
            missing = VALID_CONDITIONS[t] - set(c)
            if missing:
                failures.append(f"{label}: G2 FAIL — condition {t} missing {missing}")
            ref = c.get("request") or c.get("request_a") or c.get("request_b")
            if ref not in s.requests:
                failures.append(f"{label}: G2 FAIL — condition refs unknown request {ref!r}")
            if t == "status" and not isinstance(c["equals"], int):
                failures.append(f"{label}: G2 FAIL — status equals not int")

        # --- G3: falsifiability gate ------------------------------------------
        mocks = MOCKS.get(s.name)
        if mocks is None:
            failures.append(f"{label}: G3 FAIL — no mock set (validator incomplete)")
            continue
        vuln_fail = [c for c in s.conditions if not eval_condition(c, mocks["vuln"])[0]]
        if vuln_fail:
            failures.append(f"{label}: G3 FAIL — proof does not hold on vulnerable mock: {vuln_fail}")
        fns = {name: (lambda r: (lambda: r))(mocks["benign"][name]) for name in s.requests}
        fal = run_negative_control(fns, s.conditions, fns["payload"], "payload")
        if fal.falsified:
            failures.append(f"{label}: G3 FAIL — benign control SATISFIES the conditions "
                            f"(would be auto-falsified by the platform)")

print()
print(f"catalog: {total} skills across {len(shelves)} shelves")
if failures:
    print(f"VALIDATION FAILED — {len(failures)} issue(s):")
    for f in failures:
        print("  -", f)
    sys.exit(1)
print("ALL GATES PASS — schema exact · structure coherent · proofs hold · benign controls "
      "falsify-proof")
