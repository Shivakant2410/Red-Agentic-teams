"""Public exploit intelligence -> warm-started bandit priors (EPSS / KEV / nuclei).

The cold-start problem: every new arm in BanditStore begins at Beta(1,1) — maximum
ignorance — so each engagement pays for failed, DETECTABLE probes to re-derive
knowledge that is already public. Log4Shell-class bugs pop unpatched targets almost
every time; an exotic format-string bug almost never does. That knowledge lives in two
free, machine-readable feeds:

  - EPSS (Exploit Prediction Scoring System, FIRST.org) — a daily ML output: the
    probability (0.0-1.0) that a CVE is exploited in the wild within 30 days. The
    distribution is brutally skewed (median CVE ~0.0001, Log4Shell ~0.97), and that
    skew IS the signal.
  - KEV (CISA Known Exploited Vulnerabilities) — the "confirmed exploited in the
    wild" catalog; each entry carries CWE metadata, which is the bridge from CVE
    space into this repo's technique taxonomy (attack_tree.CWE_TO_TECHNIQUE).
  - nuclei templates (projectdiscovery/nuclei-templates) — each template's
    info.classification carries cve-id/cwe-id, so a local templates checkout can
    extend the corpus beyond KEV (cwe_cves_from_templates).

THE MOVE: a Beta posterior accepts pseudo-counts. For technique class T with
population exploitability p, seed virgin arms as

    Beta(1 + strength*p, 1 + strength*(1-p))     instead of     Beta(1, 1)

i.e. "behave as if we had already observed `strength` probes at the population rate."
Thompson sampling then probes where public intelligence says yield is — cutting the
failed probes an engagement spends learning what the internet already knows — while
local evidence overrides within ~2*strength real trials (data always wins).

CONTRACTS (enforced in bandit.py, restated here because they are the whole safety story):
  - EPSS is a POPULATION base rate, not the probability THIS target is vulnerable.
    The prior shapes where we probe FIRST; the bandit's posterior (this target's
    actual yield) is what we conclude from. Never sort by EPSS greedily.
  - Priors are LOCAL: export_state() broadcasts observed evidence only, so two peers
    that seeded the same snapshot never double-count it through federation.
  - Refresh path: fetch_feeds() re-pulls both feeds (operator-side, NOT
    target-linked traffic) and re-seeding is idempotent — snapshots carry their
    fetch date so an engagement can state exactly which intel warmed it up.
"""

from __future__ import annotations

import datetime as _dt
import json
import re
import time
import urllib.request
from pathlib import Path

# Bundled snapshots (fetched by scripts/fetch_intel.py at repo-build time; refresh
# with fetch_feeds() whenever the operator wants current data).
INTEL_DIR = Path(__file__).resolve().parent / "intel"
EPSS_URL = "https://api.first.org/data/v1/epss"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
# CISA's own GitHub mirror — authoritative and identical content, but reachable from
# datacenter ranges (cisa.gov sits behind Akamai, which 403s cloud IPs outright).
KEV_MIRROR_URL = ("https://raw.githubusercontent.com/cisagov/kev-data/"
                  "refs/heads/develop/known_exploited_vulnerabilities.json")

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)

# Technique classes where a public-intel prior is allowed to steer probes in EITHER
# direction — i.e. where EPSS (population mass-scan attractiveness) ≈ engagement yield.
# These are signature-scannable bug classes: injection, injection, SSRF, traversal,
# deserialization, upload, appliance-class authn/access bypasses.
#
# Deliberately ABSENT: hand-crafted logic classes. KEV's IDOR-labeled CVEs carry an
# EPSS of ~0.009 — bots don't mass-scan per-object logic bugs, but IDOR confirms
# constantly on numeric-id endpoints in real engagements. Letting the feed suppress
# that technique would starve our best gambit on the very shape it wins on. A class
# outside this set simply gets no prior (Beta(1,1)) and keeps the tree's static
# priority — absence of intel must never masquerade as negative intel.
EPSS_YIELD_CLASSES = frozenset({
    "CWE-22", "CWE-23",          # path traversal / relative path
    "CWE-77", "CWE-78",          # command injection (args / direct)
    "CWE-79",                     # xss
    "CWE-89",                     # sql injection
    "CWE-94",                     # code injection
    "CWE-98",                     # file inclusion
    "CWE-284",                    # access control (appliance-class)
    "CWE-287", "CWE-288",        # authn bypass / alternative authn
    "CWE-434",                    # unrestricted file upload
    "CWE-502", "CWE-917",        # deserialization / JNDI (Log4Shell-class)
    "CWE-918",                    # ssrf
})


def _http_json(url: str, timeout: float) -> dict:
    req = urllib.request.Request(url, headers={"User-Agent": "red-agentic-teams-priors/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8", errors="replace"))


def _write_snapshot(path: Path, source: str, rows: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    doc = {"_meta": {"fetched": _dt.datetime.now(_dt.timezone.utc).isoformat(),
                     "source": source, "count": len(rows)},
           **rows}
    path.write_text(json.dumps(doc, indent=0, sort_keys=True), encoding="utf-8")


def _read_snapshot(path: str | Path) -> dict:
    try:
        doc = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return doc if isinstance(doc, dict) else {}


# -- feed loading (tolerant: intel feeds and mirrors rot; skip junk, never raise) ----

def load_epss(path: str | Path) -> dict[str, float]:
    """Parse an EPSS snapshot: {cve: probability}. FIRST's v1 API returns rows
    {"cve": "CVE-...", "epss": "0.97..."} (probability as a STRING); we accept both.
    Malformed rows and the _meta block are skipped — an intel file is untrusted
    input, same isolation contract as a peer payload."""
    doc = _read_snapshot(path)
    out: dict[str, float] = {}
    for key, row in doc.items():
        if key == "_meta":
            continue
        try:
            cve = str(key).upper()
            p = float(row if not isinstance(row, dict) else row.get("epss"))
        except (TypeError, ValueError):
            continue
        if _CVE_RE.fullmatch(cve) and 0.0 <= p <= 1.0:
            out[cve] = p
    return out


def load_kev(path: str | Path) -> dict[str, list[str]]:
    """Parse a KEV snapshot: {cve: [CWE-..., ...]}. Accepts both our slim snapshot
    format and the raw CISA feed shape ({"vulnerabilities": [{"cveID", "cwes"}]})."""
    doc = _read_snapshot(path)
    rows = doc.get("vulnerabilities")
    if isinstance(rows, list):                       # raw CISA feed shape
        out: dict[str, list[str]] = {}
        for entry in rows:
            if not isinstance(entry, dict):
                continue
            cve = str(entry.get("cveID") or entry.get("cve") or "").upper()
            if _CVE_RE.fullmatch(cve):
                out[cve] = _norm_cwes(entry.get("cwes") or entry.get("cweIDs")
                                      or entry.get("cweIds") or [])
        return out
    out = {}
    for key, row in doc.items():
        if key == "_meta":
            continue
        cve = str(key).upper()
        if _CVE_RE.fullmatch(cve) and isinstance(row, list):
            out[cve] = _norm_cwes(row)
    return out


def _norm_cwes(cwes) -> list[str]:
    if isinstance(cwes, str):
        cwes = [cwes]
    return sorted({str(c).upper() for c in (cwes or [])
                   if str(c).upper().startswith("CWE-")})


def invert_kev(kev: dict[str, list[str]]) -> dict[str, set[str]]:
    """KEV is cve -> cwes; the aggregation below wants the transpose: cwe -> cves."""
    out: dict[str, set[str]] = {}
    for cve, cwes in (kev or {}).items():
        for cwe in cwes:
            out.setdefault(cwe, set()).add(cve)
    return out


# -- feed refresh (operator-side, never target-linked) ---------------------------------

def fetch_feeds(out_dir: str | Path = INTEL_DIR, timeout: float = 30.0,
                batch: int = 100) -> tuple[Path, Path]:
    """Refresh the bundled snapshots: pull the full KEV catalog, then EPSS scores for
    every KEV CVE (the high-signal intersection; batched, politely paced). Raises on
    total failure — the caller decides whether a run proceeds cold (bandit.py treats
    a missing provider as exactly the legacy behavior)."""
    out = Path(out_dir)
    kev_doc, kev_source = {}, ""
    for url in (KEV_URL, KEV_MIRROR_URL):
        try:
            kev_doc, kev_source = _http_json(url, timeout), url
            break
        except Exception:
            continue                       # cisa.gov 403s datacenter ranges; mirror next
    kev_rows = kev_doc.get("vulnerabilities") or []
    kev: dict[str, list[str]] = {}
    for entry in kev_rows:
        if not isinstance(entry, dict):
            continue
        # Feed schema is camelCase (cveID); older mirrors used cve/cwes/cweIDs.
        cve = str(entry.get("cveID") or entry.get("cve") or "").upper()
        if not _CVE_RE.fullmatch(cve):
            continue
        cwes = entry.get("cwes") or entry.get("cweIDs") or entry.get("cweIds") or []
        if isinstance(cwes, str):
            cwes = [cwes]
        kev[cve] = sorted({str(c).upper() for c in cwes if str(c).upper().startswith("CWE-")})

    epss: dict[str, float] = {}
    targets = sorted(kev)
    for i in range(0, len(targets), max(int(batch), 1)):
        chunk = targets[i:i + max(int(batch), 1)]
        try:
            data = _http_json(f"{EPSS_URL}?cve={','.join(chunk)}", timeout).get("data") or []
        except Exception:
            continue                       # one failed batch loses one batch, not the feed
        for row in data:
            try:
                epss[str(row["cve"]).upper()] = float(row["epss"])
            except (KeyError, TypeError, ValueError):
                continue
        time.sleep(0.25)

    if not kev:
        raise RuntimeError("KEV fetch produced no usable entries; refusing to overwrite "
                           "snapshots with an empty feed")
    kev_path, epss_path = out / "kev_snapshot.json", out / "epss_snapshot.json"
    _write_snapshot(kev_path, kev_source or KEV_URL, kev)
    _write_snapshot(epss_path, EPSS_URL, epss)
    return kev_path, epss_path


# -- nuclei templates as an additional corpus ------------------------------------------

def cwe_cves_from_templates(directory: str | Path) -> dict[str, set[str]]:
    """Walk a nuclei-templates checkout and collect {cwe: {cve, ...}} from template
    metadata: info.classification.cve-id / cwe-id when present, plus a CVE regex
    fallback over the template id / filename (nuclei ids CVE-YYYY-NNNNN by
    convention). Tolerant of the corpus's infinite variety: unreadable or
    metadata-less templates are skipped — this is a prior source, not a parser gate."""
    import yaml
    out: dict[str, set[str]] = {}
    for path in sorted(Path(directory).rglob("*.yaml")):
        try:
            doc = yaml.safe_load(path.read_text(encoding="utf-8", errors="ignore"))
        except Exception:
            continue
        if not isinstance(doc, dict):
            continue
        text = f"{doc.get('id') or ''} {path.stem}"
        cves: set[str] = set(m.group(0).upper() for m in _CVE_RE.finditer(text))
        info = doc.get("info") or {}
        cls = info.get("classification") or {}
        raw_cves = cls.get("cve-id") or []
        if isinstance(raw_cves, str):
            raw_cves = [raw_cves]
        for c in raw_cves:
            m = _CVE_RE.fullmatch(str(c).upper())
            if m:
                cves.add(m.group(0))
        raw_cwes = cls.get("cwe-id") or []
        if isinstance(raw_cwes, str):
            raw_cwes = [raw_cwes]
        cwes = sorted({str(c).upper() for c in raw_cwes if str(c).upper().startswith("CWE-")})
        if not cves or not cwes:
            continue
        for cwe in cwes:
            out.setdefault(cwe, set()).update(cves)
    return out


# -- aggregation: per-technique-class priors --------------------------------------------

def class_priors(cwe_cves: dict[str, set[str]], epss: dict[str, float], *,
                 top_k: int = 5, strength: float = 12.0, cap: float = 0.95) \
        -> dict[str, tuple[float, float]]:
    """Collapse CVE-level intel into one (p, strength) per CWE class.

    p = mean of the class's top-K EPSS scores — the "known kill chain" statistic. The
    class's most-exploited instances are the ones a target's stack plausibly carries,
    and a plain mean would be dragged to zero by the long tail of never-exploited
    CVEs that dominates every class. Capped at 0.95: no public feed gets to claim
    certainty about a class we have not probed. Classes with no EPSS-visible KEV
    members get NO prior (Beta(1,1), exactly the legacy cold start) — inventing a
    prior from absence would be hallucinated confidence.
    """
    out: dict[str, tuple[float, float]] = {}
    for cwe, cves in (cwe_cves or {}).items():
        scores = sorted((epss[c] for c in cves if c in epss), reverse=True)[:max(int(top_k), 1)]
        if not scores:
            continue
        p = min(cap, sum(scores) / len(scores))
        out[str(cwe).upper()] = (p, float(strength))
    return out


def make_provider(cwe_priors: dict[str, tuple[float, float]],
                  cwe_to_technique: dict[str, str] | None = None,
                  allow: frozenset | set | None = EPSS_YIELD_CLASSES):
    """Build a BanditStore prior provider from {cwe: (p, strength)}.

    `allow` is the operational policy gate (default EPSS_YIELD_CLASSES): a technique
    class may only be steered by public intel where EPSS ≈ engagement yield. Pass
    allow=None to steer every class from the raw feed. A technique may cover several
    CWE classes (info.sensitive <- CWE-200/22/98): the MOST-exploited allowed class
    dominates the first-probe decision, and the source tag names it so the audit log
    shows exactly which intel shaped the opening moves."""
    from .attack_tree import CWE_TO_TECHNIQUE as _default_map
    mapping = cwe_to_technique or _default_map
    by_technique: dict[str, list[tuple[str, float, float]]] = {}
    for cwe, (p, s) in (cwe_priors or {}).items():
        cwe = str(cwe).upper()
        if allow is not None and cwe not in allow:
            continue
        tid = mapping.get(cwe)
        if tid:
            by_technique.setdefault(tid, []).append((cwe, float(p), float(s)))

    def provider(technique: str):
        members = by_technique.get(technique)
        if not members:
            return None
        cwe, p, s = max(members, key=lambda m: m[1])
        return p, s, f"epss+kev:{cwe}"

    return provider


def builtin_prior_provider(intel_dir: str | Path = INTEL_DIR):
    """Provider from the bundled snapshots, or None when they are absent/corrupt —
    a run without intel cold-starts exactly like the legacy behavior, never fails."""
    kev_path, epss_path = Path(intel_dir) / "kev_snapshot.json", Path(intel_dir) / "epss_snapshot.json"
    if not (kev_path.exists() and epss_path.exists()):
        return None
    priors = class_priors(invert_kev(load_kev(kev_path)), load_epss(epss_path))
    if not priors:
        return None
    return make_provider(priors)
