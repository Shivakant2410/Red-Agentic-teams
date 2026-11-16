"""dvlba_ground_truth.py — scorer for dvlba-shop (the Phase B/C baseline lab).

Keys mirror target/seeds.py (B1..B8) exactly. The `ids` are the finding IDs
the engines actually emitted in the executed Phase C runs (results/run1/
findings.json) — measured identifiers, not invented ones. The scorer
classifies FINDING dicts from either engine's artifacts; a seed HIT requires
the finding id or the mechanism vocabulary. Refuted findings never count.
"""
import json

SEEDS = {
    "B1": {"name": "coupon stack, uncapped", "invariant": "I1/I4",
           "ids": ("SW-STACK",), "keywords": ("stack", "coupon/apply"),
           "severity": "high"},
    "B2": {"name": "single-use redeem race", "invariant": "I5",
           "ids": ("SW-RACE",), "keywords": ("race", "redeem"),
           "severity": "critical"},
    "B3": {"name": "checkout/init replay", "invariant": "I2",
           "ids": ("SF-CKOUT-REPLAY",),
           "keywords": ("checkout/init is replayable",),
           "severity": "high"},
    "B4": {"name": "negative-quantity credit", "invariant": "I4",
           "ids": ("SF-NEG-QTY",),
           "keywords": ("negative-quantity", "negative qty"),
           "severity": "high"},
    "B5": {"name": "order read IDOR", "invariant": "I3",
           "ids": ("SW-IDOR",), "keywords": ("idor",),
           "severity": "medium"},
    "B6": {"name": "refund cross-user / replayable", "invariant": "I1/I3",
           "ids": ("SW-REF-X", "SW-REF-R"), "keywords": ("refund",),
           "severity": "critical"},
    "B7": {"name": "ship without payment", "invariant": "I2",
           "ids": ("SF-SHIP-UNPAID",), "keywords": ("ship", "unpaid"),
           "severity": "high"},
    "B8": {"name": "async refund double-credit (deferred)", "invariant": "I1",
           "ids": ("SW-ASYNC",), "keywords": ("double-credit", "async"),
           "severity": "critical"},
}

DECOYS = {}          # dvlba-shop ships no decoys (honest: none were seeded)


def _text(fd):
    parts = [str(fd.get("id", "")), str(fd.get("title", "")),
             str(fd.get("endpoint", "")), str(fd.get("invariant", ""))]
    parts.append(json.dumps(fd.get("evidence", []), default=str)[:4000])
    return " ".join(parts).lower()


def classify(fd, status="candidate"):
    """Return (seed_ids, decoy_ids) for one finding dict."""
    t = _text(fd)
    seeds = []
    for sid, spec in SEEDS.items():
        hit = any(i and i.lower() in t for i in spec["ids"]) or \
            all(k.lower() in t for k in spec["keywords"])
        if hit:
            seeds.append(sid)
    if status == "refuted":
        seeds = []
    return seeds, []


def score_runs(run_docs):
    """run_docs: list of (run_label, findings_doc) — swarm or statefuzz shape."""
    hits, fps, other = {}, {}, []
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
                     "severity": fd.get("severity"), "provenance": prov})
            for d in decoys:
                if not seeds:
                    fps.setdefault(d, []).append(
                        {"run": label, "finding_id": fd.get("id"),
                         "title": fd.get("title"), "status": status})
            if not seeds and not decoys:
                other.append({"run": label, "finding_id": fd.get("id"),
                              "title": fd.get("title"), "status": status,
                              "invariant": fd.get("invariant")})
    return {"hits": hits, "false_positives": fps, "unmatched": other}
