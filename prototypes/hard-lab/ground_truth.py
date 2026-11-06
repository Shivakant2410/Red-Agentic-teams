"""ground_truth.py — scorer for meridian-vault (Phase D).

Keys mirror GROUND_TRUTH.md exactly. The target app imports nothing from
here; the scorer classifies FINDING dicts from the engines' artifacts.

A seed HIT requires invariant + endpoint/mechanism agreement. A decoy match
is a FALSE POSITIVE. Refuted findings never count as hits.
"""

SEEDS = {
    "S1": {"name": "voucher claim quota race", "invariant": "I5",
           "ids": ("FW-QUOTA-RACE",),
           "keywords": ("quota", "vouchers/claim"),
           "severity": "high"},
    "S2": {"name": "settle-after-cancel payout", "invariant": "I1",
           "ids": ("FW-SETTLED-CANCEL",),
           "keywords": ("payouts/{id}/cancel", "settle"),
           "severity": "critical"},
    "S3": {"name": "async settlement TOCTOU", "invariant": "I4",
           "ids": ("FW-TOCTOU-SETTLE",),
           "keywords": ("negative", "settle", "payouts"),
           "severity": "critical"},
    "S4": {"name": "asymmetric rounding drift", "invariant": "I4",
           "ids": ("FW-ROUND-DRIFT",),
           "keywords": ("resize", "drift", "cycle"),
           "severity": "medium"},
    "S5": {"name": "cancel dedupe keyed by reason", "invariant": "I1",
           "ids": ("FW-CANCEL-REASON",),
           "keywords": ("reason", "vaults/{id}/cancel"),
           "severity": "critical"},
    "S6": {"name": "terminal-state reopen", "invariant": "I2",
           "ids": ("FW-TERMINAL-RESIZE",),
           "keywords": ("canceled", "resize"),
           "severity": "high"},
    "S7": {"name": "cross-tenant leak + confused deputy", "invariant": "I3",
           "ids": ("FW-AUDIT-LEAK", "FW-DEPUTY-CREDIT"),
           "keywords": ("audit", "caller", "leak"),
           "severity": "critical"},
    "S8": {"name": "account existence oracle (LOW)", "invariant": "I3",
           "ids": (), "keywords": ("enumerat", "oracle", "accounts"),
           "severity": "low"},
}

DECOYS = {
    "D1": {"name": "/.env sample file", "keywords": (".env",)},
    "D2": {"name": "payout retry verb (safe)", "keywords": ("retry",)},
    "D3": {"name": "negative amounts (validated)",
           "keywords": ("negative", "negative-amount", "negative qty")},
    "D4": {"name": "account read IDOR claim (read is 403-enforced)",
           "keywords": ("accounts/{id}", "idor")},
}


def _text(fd):
    import json
    parts = [str(fd.get("id", "")), str(fd.get("title", "")),
             str(fd.get("endpoint", "")), str(fd.get("invariant", ""))]
    parts.append(json.dumps(fd.get("evidence", []), default=str)[:4000])
    return " ".join(parts).lower()


def classify(fd, status="candidate"):
    """Return (seed_ids, decoy_ids) for one finding dict."""
    t = _text(fd)
    seeds, decoys = [], []
    for sid, spec in SEEDS.items():
        hit = any(i and i.lower() in t for i in spec["ids"]) or \
            all(k.lower() in t for k in spec["keywords"])
        if hit:
            seeds.append(sid)
    for did, spec in DECOYS.items():
        if any(k.lower() in t for k in spec["keywords"]):
            decoys.append(did)
    # D3 collision guard: S3's "negative" keyword is about the SETTLE debit,
    # not negative input amounts; require it to be about input validation.
    if "D3" in decoys and "S3" in seeds:
        decoys.remove("D3")
    if status == "refuted":
        seeds = []
    return seeds, decoys


def score_runs(run_docs):
    """run_docs: list of (run_label, findings_doc) — findings_doc is the
    parsed findings.json of a run (swarm or statefuzz shape)."""
    hits = {}          # seed -> [{run, finding_id, status, provenance}]
    fps = {}           # decoy -> [{run, finding_id, title}]
    other = []
    for label, doc in run_docs:
        for f in doc.get("findings", []):
            fd = f.get("finding", f)
            status = f.get("status", "candidate") if "finding" in f \
                else fd.get("status", "candidate")
            prov = f.get("provenance", [fd.get("source", "?")]) \
                if "finding" in f else ["statefuzz"]
            seeds, decoys = classify(fd, status)
            for s in seeds:
                hits.setdefault(s, []).append(
                    {"run": label, "finding_id": fd.get("id"),
                     "title": fd.get("title"), "status": status,
                     "severity": fd.get("severity"),
                     "provenance": prov})
            for d in decoys:
                if not seeds:      # a decoy claim never double-counts
                    fps.setdefault(d, []).append(
                        {"run": label, "finding_id": fd.get("id"),
                         "title": fd.get("title"), "status": status})
            if not seeds and not decoys:
                other.append({"run": label, "finding_id": fd.get("id"),
                              "title": fd.get("title"), "status": status,
                              "invariant": fd.get("invariant")})
    return {"hits": hits, "false_positives": fps, "unmatched": other}
