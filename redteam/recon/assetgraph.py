"""The competitive-intel asset graph: "what are they secretly building?"

(docs/offense-arsenal.md §2.3, Week 1 of the offense build)

An inventory is a list; a graph answers chain questions. But the FIRST question a
red team — or a competitor, which is the same question — asks is narrower and
sharper: what is this org building right now that it has not announced? Five signal
families, all mined by code we own (one HTTP GET or one regex family per source —
no SDK, no new dependency):

  1. CERTIFICATE-TRANSPARENCY FRESHNESS. CT logs are append-only and public; a cert
     for `apollo-api.stg.acme.com` issued last week is a launch in flight, weeks
     before any announcement. We parse the crt.sh JSON shape ourselves
     (`ct_entries`) and diff on issuance recency (`fresh_ct_names`).
  2. CODENAME TRIANGULATION. Distinctive labels — against an infrastructure
     stoplist — pulled from hostnames, CT names, and JS flag keys. One source =
     noise; N independent sources = a project. `secret_builds()` ranks by
     independent-source count: the corroboration upgrade knowledge.py applies per
     node, lifted to the project level.
  3. CODENAME-SEEDED PERMUTATION. For each candidate codename, project its
     environment fanout (`apollo-dev / apollo-stg / apollo-uat / apollo-admin`) and
     DNS-verify. altdns seeds from a wordlist; we seed from names the target itself
     leaked — smaller candidate sets, denser hits.
  4. VERSION-AHEAD-OF-LIVE. The bundle references `/api/v3` while only `/api/v1` is
     live ⇒ a `precedes` edge. The not-yet-live version IS the roadmap; existence
     (401/403) confirms without content.
  5. FEATURE-FLAG LEAKS + STAGING MIRRORS. Flag-SDK markers and beta_*/experiment_*
     keys in JS name unreleased features; a codename spanning a prod host and an
     env-marked host yields `mirrors` — staging is where the secret build runs first.

Discipline: every network touch flows through caller-provided callables (ct_fetch /
resolve / fetch) that the tool layer scope-checks; this module is pure graph +
signal math, testable with fixtures and zero network. The graph records LEADS —
findings come only from the proof pipeline.
"""

from __future__ import annotations

import datetime as _dt
import json
import re
import threading
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urljoin, urlparse

# ---------------------------------------------------------------------------
# Node kinds and edge relations (typed graph — the whole point).

HOST = "host"
IP = "ip"
CERT = "cert"
CODENAME = "codename"
FLAG = "flag"
PROVIDER = "provider"

ANNOUNCES = "announces"    # cert --> host (CT issuance)
PROJECTS = "projects"      # codename --> host (DNS-verified permutation)
RESOLVES_TO = "resolves_to"  # host --> ip
REFERENCES = "references"  # flag --> codename (JS bundle leak)
PRECEDES = "precedes"      # live api version --> unreleased version (roadmap)
MIRRORS = "mirrors"        # staging host --> prod host (same codename)

# ---------------------------------------------------------------------------
# Label vocabulary: what is generic infrastructure vs. what is a NAME.
# A codename is a label the org chose because it means something to THEM —
# `apollo`, `krypton`, `velvet`. `www`, `api`, `stg` mean something to everyone.

ENV_MARKERS = frozenset({
    "dev", "development", "stg", "staging", "stage", "test", "testing",
    "qa", "uat", "preprod", "pre", "prod", "production", "beta", "alpha",
    "demo", "sandbox", "internal", "intranet", "corp", "edge",
})

INFRA_STOPWORDS = frozenset({
    "www", "api", "app", "web", "webapp", "mail", "smtp", "imap", "pop", "cdn",
    "static", "assets", "media", "img", "images", "files", "download",
    "downloads", "docs", "doc", "blog", "shop", "store", "status", "support",
    "portal", "sso", "auth", "oauth", "login", "vpn", "admin", "administrator",
    "gw", "gateway", "proxy", "cache", "ns1", "ns2", "dns", "mx", "mx1", "mx2",
    "remote", "jira", "confluence", "git", "gitlab", "github", "ci", "jenkins",
    "teamcity", "my", "new", "old", "backup", "landing", "marketing", "go",
    "link", "links", "data", "db", "sql", "mysql", "postgres", "redis", "kafka",
    "elastic", "kibana", "grafana", "prometheus", "monitor", "monitoring",
    "logs", "log", "cloud", "aws", "azure", "gcp", "v2", "v3", "v1",
})

_SPLIT_RE = re.compile(r"[^a-z0-9]+")
_MIN_LABEL = 3   # shorter labels are noise (country codes, "io", "app")

# Public suffixes must never surface as "codenames" — without this, the TLD of
# every hostname becomes a phantom project. Naive by design (no PSL download);
# covers the suffixes real targets actually use.
PUBLIC_SUFFIXES = frozenset({
    "com", "net", "org", "io", "co", "dev", "app", "ai", "gov", "edu",
    "ac", "uk", "us", "de", "fr", "cn", "jp", "in", "au", "ca", "br",
    "eu", "info", "xyz", "me", "tv", "ch", "se", "no", "nl", "es", "it",
    # RFC 2606 / mDNS reserved — show up in tests and lab fixtures constantly
    "test", "example", "invalid", "localhost", "local",
})


def codename_labels(hostname: str, base_domain: str = "") -> list[str]:
    """Distinctive (codename-candidate) labels in a hostname, generic parts dropped.

    `apollo-api.stg.acme.com` (base acme.com) -> ["apollo"]: the env marker `stg`
    and the infra word `api` are stripped, the compound label is split, what
    remains is a NAME. Pure function."""
    h = hostname.lower().strip(".")
    base = base_domain.lower().strip(".")
    if base and h.endswith("." + base):
        h = h[: -(len(base) + 1)]
    elif base and h == base:
        return []
    out: list[str] = []
    for label in h.split("."):
        if not label or label in ENV_MARKERS or label in INFRA_STOPWORDS \
                or label in PUBLIC_SUFFIXES:
            continue
        if label.isdigit():
            continue
        for part in _SPLIT_RE.split(label):
            if len(part) < _MIN_LABEL or part.isdigit():
                continue
            if part in ENV_MARKERS or part in INFRA_STOPWORDS \
                    or part in PUBLIC_SUFFIXES:
                continue
            if part not in out:
                out.append(part)
    return out


def host_env(hostname: str) -> str | None:
    """The environment marker in a hostname, or None (treated as prod).
    `apollo-stg.acme.com` -> "stg". First marker wins (hosts carry one env).
    Public suffixes are skipped: the `.dev` and `.test` TLDs are NOT environments."""
    for label in hostname.lower().strip(".").split("."):
        if label in PUBLIC_SUFFIXES:
            continue
        if label in ENV_MARKERS:
            return label
        for part in _SPLIT_RE.split(label):
            if part in ENV_MARKERS:
                return part
    return None


# ---------------------------------------------------------------------------
# CT log parsing (crt.sh JSON shape) + freshness diffing.

_CT_DATE_FORMATS = ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d")


def _parse_ct_date(raw) -> _dt.datetime | None:
    if not isinstance(raw, str) or not raw.strip():
        return None
    s = raw.strip().replace("Z", "").split(".")[0]
    for fmt in _CT_DATE_FORMATS:
        try:
            # CT ledger timestamps are UTC; attach the zone so freshness math
            # against aware `now` never hits naive/aware subtraction errors
            return _dt.datetime.strptime(s, fmt).replace(tzinfo=_dt.timezone.utc)
        except ValueError:
            continue
    return None


def ct_entries(payload: str | bytes) -> list[dict]:
    """Normalize the crt.sh JSON shape (a list of rows, `name_value` possibly
    newline-separated SANs) into {"names", "not_before", "issuer"} dicts.
    Tolerant: junk rows skipped, malformed dates yield None (row still usable
    for names, just never 'fresh'). An intel feed is untrusted input."""
    try:
        doc = json.loads(payload)
    except (json.JSONDecodeError, ValueError, TypeError):
        return []
    if isinstance(doc, dict):
        doc = doc.get("results") or []
    if not isinstance(doc, list):
        return []
    out: list[dict] = []
    for row in doc[:5000]:
        if not isinstance(row, dict):
            continue
        raw_names = row.get("name_value") or row.get("common_name") or ""
        names = [n.strip().lower() for n in str(raw_names).splitlines() if n.strip()]
        if not names:
            continue
        out.append({"names": names,
                    "not_before": _parse_ct_date(row.get("not_before")),
                    "issuer": str(row.get("issuer_name") or "")[:120]})
    return out


def fresh_ct_names(entries: list[dict], now: _dt.datetime,
                   window_days: int = 45) -> dict[str, _dt.datetime]:
    """Names whose newest cert is younger than the window -> earliest such date.

    This is the temporal diff that makes CT a launch-prediction signal instead
    of a subdomain dump: EVERY name was in the log once; only recent issuance
    says "something is being built and wired up NOW"."""
    fresh: dict[str, _dt.datetime] = {}
    for e in entries:
        nb = e.get("not_before")
        if nb is None:
            continue
        age_days = (now - nb).total_seconds() / 86400.0
        if not (0 <= age_days <= window_days):
            continue
        for name in e["names"]:
            if name not in fresh or nb < fresh[name]:
                fresh[name] = nb
    return fresh


# ---------------------------------------------------------------------------
# Codename-seeded permutation (altdns, but seeded by leaked names not wordlists).

PERMUTE_ENVS = ("dev", "stg", "uat", "qa", "beta", "demo", "internal", "admin",
                "api", "app")
PERMUTE_JOINERS = ("-", ".")


def permute_hostnames(codename: str, cap: int = 48) -> list[str]:
    """Environment fanout candidates for one codename: {c}{j}{env} and {env}{j}{c}.
    Bounded and deterministic — a permutation list is a probe budget, not a toy."""
    c = codename.lower().strip()
    if not c or len(c) > 40:
        return []
    out: list[str] = []
    seen: set[str] = set()
    for env in PERMUTE_ENVS:
        for j in PERMUTE_JOINERS:
            for cand in (f"{c}{j}{env}", f"{env}{j}{c}"):
                if cand not in seen:
                    seen.add(cand)
                    out.append(cand)
    return out[:max(0, int(cap))]


# ---------------------------------------------------------------------------
# JS bundle mining: flag SDKs, flag keys, API versions, internal hosts.

_FLAG_PROVIDERS = ("statsig", "launchdarkly", "unleash", "flagsmith", "configcat",
                   "growthbook", "optimizely", "split.io", "openfeature", "flagd",
                   "featureflags", "feature_flags")
_PROVIDER_RE = re.compile("|".join(re.escape(p) for p in _FLAG_PROVIDERS),
                          re.IGNORECASE)
_FLAG_KEY_RE = re.compile(
    r"\b(?:beta|alpha|experiment|feature|flag|canary|ff)[-_]"
    r"([a-z][a-z0-9]{2,30}(?:[-_][a-z0-9]+)*)\b", re.IGNORECASE)
_API_VERSION_RE = re.compile(r"[\"'/]api/v(\d+)(?:[\"'/\\]|$)")
_HOSTNAME_RE = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.){2,}[a-z]{2,}\b")
_SRC_RE = re.compile(r"""src\s*=\s*["']([^"']+\.js(?:\?[^"']*)?)["']""",
                     re.IGNORECASE)


def mine_js(text: str, base_domain: str = "") -> dict:
    """Signal-mine one JS/HTML body. Everything returned is a LEAD:
      providers       — flag SDK markers (an org with flags ships unreleased work)
      flag_codenames  — distinctive labels out of beta_*/experiment_* keys
      api_versions    — /api/vN references (version-ahead-of-live inputs)
      internal_hosts  — org hostnames mentioned that carry env/internal markers
      script_urls     — same-origin .js assets worth fetching next (relative OK)
    Hostname mentions are filtered to the org's own domain — third-party domains
    in a bundle (CDNs, analytics) are noise, not intel."""
    text = text or ""
    base = (base_domain or "").lower().strip(".")
    providers = sorted({m.group(0).lower().rstrip(".") for m in _PROVIDER_RE.finditer(text)})

    flag_codenames: list[str] = []
    for m in _FLAG_KEY_RE.finditer(text):
        for part in _SPLIT_RE.split(m.group(1).lower()):
            if len(part) >= _MIN_LABEL and not part.isdigit() \
                    and part not in ENV_MARKERS and part not in INFRA_STOPWORDS \
                    and part not in flag_codenames:
                flag_codenames.append(part)

    api_versions = sorted({int(v) for v in _API_VERSION_RE.findall(text)})

    internal_hosts: list[str] = []
    for m in _HOSTNAME_RE.finditer(text.lower()):
        host = m.group(0).rstrip(".")
        if base and not host.endswith("." + base):
            continue                     # third-party domain — noise, not intel
        if host_env(host) or any(p in host.split(".") for p in ("internal", "intranet")):
            if host not in internal_hosts:
                internal_hosts.append(host)

    script_urls: list[str] = []
    for m in _SRC_RE.finditer(text):
        u = m.group(1)
        if u.startswith("//"):
            u = "https:" + u
        script_urls.append(u)
    if base:
        # third-party scripts are noise (and would be scope-blocked at fetch
        # time anyway) — keep relative/own-org assets only
        script_urls = [u for u in script_urls
                       if not u.startswith("http")
                       or (urlparse(u).hostname or "").endswith("." + base)]
    return {"providers": providers, "flag_codenames": flag_codenames,
            "api_versions": api_versions, "internal_hosts": internal_hosts[:24],
            "script_urls": script_urls[:24]}


# ---------------------------------------------------------------------------
# Version-ahead-of-live inference.

_VSEG_RE = re.compile(r"v\d+")


def version_families(paths) -> dict[str, set[int]]:
    """{path-family-prefix -> {versions seen}} over URL paths. Pure function.
    Normalizes full URLs (scheme+host stripped) so BOTH input shapes — graph
    endpoint keys (`https://h/api/v1/users`) and JS references (`/api/v1/`) —
    land in the SAME family; otherwise the diff compares apples to hosts."""
    fams: dict[str, set[int]] = {}
    for p in paths or ():
        s = str(p).lower()
        if "://" in s:
            rest = s.split("://", 1)[1]
            s = "/" + rest.split("/", 1)[1] if "/" in rest else "/"
        segs = s.split("?")[0].split("/")
        for i, seg in enumerate(segs):
            if _VSEG_RE.fullmatch(seg):
                family = "/".join(segs[:i])
                fams.setdefault(family, set()).add(int(seg[1:]))
                break
    return fams


def infer_version_edges(live_paths, referenced_paths) -> list[dict]:
    """Referenced version > max live version of the same family = roadmap.

    Returns [{"family", "live_max", "unreleased", "edge"}] where edge is
    (src_node_id, dst_node_id) for the `precedes` link — None when nothing live
    exists to anchor it (a family with zero live versions is still reported)."""
    live = version_families(live_paths)
    ref = version_families(referenced_paths)
    out: list[dict] = []
    for family in sorted(ref):
        unreleased = sorted(v for v in ref[family] if v > max(live.get(family, {0})))
        if not unreleased:
            continue
        live_max = max(live.get(family, {0}))
        for v in unreleased:
            src = f"endpoint:{family}/v{live_max}" if live_max else None
            dst = f"endpoint:{family}/v{v}"
            out.append({"family": family, "live_max": live_max,
                        "unreleased": v,
                        "edge": (src, dst) if src else None})
    return out


# ---------------------------------------------------------------------------
# Staging-mirror inference.

def infer_mirror_edges(hosts: list[str], base_domain: str = "") -> list[tuple[str, str]]:
    """(staging_host, prod_host) pairs sharing a codename. Pure function.
    `apollo-stg.acme.com` mirrors `apollo.acme.com`; `stg-apollo` mirrors `apollo`."""
    by_codename: dict[str, dict[str, list[str]]] = {}
    for h in hosts or ():
        h = str(h).lower().strip(".")
        env = host_env(h)
        labels = codename_labels(h, base_domain)
        if not labels:
            continue
        cn = labels[0]
        side = "stage" if env else "prod"
        by_codename.setdefault(cn, {"stage": [], "prod": []})[side].append(h)
    out: list[tuple[str, str]] = []
    for cn, sides in by_codename.items():
        for s in sides["stage"]:
            for p in sides["prod"]:
                if s != p and (s, p) not in out:
                    out.append((s, p))
    return out


# ---------------------------------------------------------------------------
# The store.

@dataclass
class AgNode:
    kind: str
    key: str
    attrs: dict = field(default_factory=dict)
    sources: list[str] = field(default_factory=list)   # independent signal families
    first_seen: str = field(default_factory=lambda: _dt.datetime.now(_dt.timezone.utc).isoformat())

    @property
    def id(self) -> str:
        return f"{self.kind}:{self.key}"


class AssetGraph:
    """Thread-safe, persisted typed graph for one run (same discipline as
    AssetInventory: atomic saves, one RLock, never breaks a run over a save)."""

    def __init__(self, path: str | Path | None = None):
        self._path = Path(path) if path else None
        self._lock = threading.RLock()
        self._nodes: dict[str, AgNode] = {}
        self._edges: list[dict] = []
        self._edge_keys: set[tuple[str, str, str]] = set()
        self._load()

    # -- persistence ---------------------------------------------------------

    def _load(self) -> None:
        if self._path is None:
            return
        try:
            raw = json.loads(self._path.read_text(encoding="utf-8"))
            if not isinstance(raw, dict):
                return
            for n in raw.get("nodes", []) or []:
                if isinstance(n, dict) and "kind" in n and "key" in n:
                    node = AgNode(kind=n["kind"], key=n["key"],
                                  attrs=n.get("attrs") or {},
                                  sources=n.get("sources") or [])
                    self._nodes[node.id] = node
            for e in raw.get("edges", []) or []:
                if isinstance(e, dict):
                    k = (e.get("src"), e.get("rel"), e.get("dst"))
                    if all(k) and k not in self._edge_keys:
                        self._edge_keys.add(k)
                        self._edges.append(e)
        except (FileNotFoundError, json.JSONDecodeError, OSError, ValueError):
            pass

    def _save_locked(self) -> None:
        if self._path is None:
            return
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            doc = {"nodes": [{"kind": n.kind, "key": n.key, "attrs": n.attrs,
                              "sources": n.sources, "first_seen": n.first_seen}
                             for n in self._nodes.values()],
                   "edges": self._edges}
            tmp = self._path.with_suffix(".json.tmp")
            tmp.write_text(json.dumps(doc, indent=1, ensure_ascii=False),
                           encoding="utf-8")
            tmp.replace(self._path)
        except Exception:
            pass  # evidence best-effort; never break the run over a save

    # -- writers -------------------------------------------------------------

    def add_node(self, kind: str, key: str, attrs: dict | None = None,
                 source: str = "") -> AgNode:
        """Add or merge. Re-observing merges attrs and records the INDEPENDENT
        source — this is where triangulation is bookkept (sources list)."""
        with self._lock:
            nid = f"{kind}:{key}"
            node = self._nodes.get(nid)
            if node is None:
                node = AgNode(kind=kind, key=str(key), attrs=dict(attrs or {}))
                self._nodes[nid] = node
            else:
                node.attrs.update(attrs or {})
            if source and source not in node.sources:
                node.sources.append(source)
            self._save_locked()
            return node

    def add_edge(self, src_id: str, rel: str, dst_id: str, source: str = "") -> bool:
        """Typed edge; only between nodes that exist; deduped. Returns False for
        dangling refs (callers decide whether that loses evidence)."""
        with self._lock:
            if src_id not in self._nodes or dst_id not in self._nodes \
                    or src_id == dst_id:
                return False
            k = (src_id, rel, dst_id)
            if k in self._edge_keys:
                return True
            self._edge_keys.add(k)
            self._edges.append({"src": src_id, "rel": rel, "dst": dst_id,
                                "source": source,
                                "first_seen": _dt.datetime.now(_dt.timezone.utc).isoformat()})
            self._save_locked()
            return True

    # -- readers -------------------------------------------------------------

    def nodes(self, kind: str | None = None) -> list[AgNode]:
        with self._lock:
            return [n for n in self._nodes.values() if kind is None or n.kind == kind]

    def edges(self, rel: str | None = None) -> list[dict]:
        with self._lock:
            return [e for e in self._edges if rel is None or e["rel"] == rel]

    def node(self, node_id: str) -> AgNode | None:
        with self._lock:
            return self._nodes.get(node_id)

    def summary(self) -> dict:
        with self._lock:
            kinds: dict[str, int] = {}
            rels: dict[str, int] = {}
            for n in self._nodes.values():
                kinds[n.kind] = kinds.get(n.kind, 0) + 1
            for e in self._edges:
                rels[e["rel"]] = rels.get(e["rel"], 0) + 1
            return {"nodes": len(self._nodes), "edges": len(self._edges),
                    "by_kind": kinds, "by_relation": rels}


# ---------------------------------------------------------------------------
# Triangulation: the ranked "secret builds" report.

VERDICTS = ((3, "in-development (strong)"), (2, "in-development (likely)"))


def secret_builds(agraph: AssetGraph) -> list[dict]:
    """Rank codename nodes by INDEPENDENT signal-source count — the project-level
    corroboration verdict. Evidence chains ride along: hosts (projects/announces),
    flags, first-seen. A codename with one source is a watchlist line, never a
    claim. Pure graph query."""
    builds: list[dict] = []
    for node in agraph.nodes(CODENAME):
        n = len(node.sources)
        verdict = "watchlist"
        for threshold, label in VERDICTS:
            if n >= threshold:
                verdict = label
                break
        hosts: list[str] = []
        for e in agraph.edges(PROJECTS):
            if e["src"] == node.id:
                hosts.append(str(agraph.node(e["dst"]).key if agraph.node(e["dst"]) else e["dst"]))
        flags = [e["src"] for e in agraph.edges(REFERENCES) if e["dst"] == node.id]
        builds.append({
            "codename": node.key,
            "corroboration": n,
            "sources": sorted(node.sources),
            "verdict": verdict,
            "hosts": hosts[:16],
            "flags": [str(agraph.node(f).key) if agraph.node(f) else f
                      for f in flags[:8]],
            "first_seen": node.first_seen,
            "detail": {k: v for k, v in node.attrs.items()
                       if k in ("ct_issued", "resolved_ip", "found_in", "note")},
        })
    builds.sort(key=lambda b: (-b["corroboration"], b["codename"]))
    return builds


# ---------------------------------------------------------------------------
# Orchestrator: wire the five signal families into one pass.

def run_asset_radar(engagement, agraph: AssetGraph, *, graph=None,
                    inventory=None, audit=None, base_domain: str = "",
                    ct_fetch=None, resolve=None, fetch=None, js_bodies=None,
                    window_days: int = 45, permute_budget: int = 24,
                    max_codenames_dns: int = 8) -> dict:
    """One radar pass. Every network touch is injected:
      ct_fetch(domain) -> crt.sh JSON text   (operator-side; None skips CT)
      resolve(host)    -> ip | None          (None skips DNS permutation)
      fetch(url)       -> (status, body, headers)   (scope-checked; JS mining)
      js_bodies        -> {url: text}        (pre-fetched bodies, zero requests)
    Returns the report dict; writes nodes/edges into `agraph` and, when `graph`
    (knowledge graph) is given, new host leads as HOST nodes there too."""
    now = _dt.datetime.now(_dt.timezone.utc)

    # -- org domain: operator override, else naive registrable suffix of scope
    base = (base_domain or "").lower().strip(".")
    if not base:
        for h in getattr(engagement, "allowed_hosts", []) or []:
            h = h.strip()
            if h.startswith("*.") or "/" in h:
                continue
            labels = h.split(".")
            if len(labels) >= 2:
                base = ".".join(labels[-2:])
                break
    known_hosts = {h.lower() for h in (inventory.known_hosts() if inventory else [])}
    if graph is not None:
        known_hosts |= {n.key.lower() for n in graph.nodes("host")}

    report: dict = {"base_domain": base, "ct_new_hosts": 0, "dns_probed": 0,
                    "dns_resolved": 0, "flags": 0, "internal_hosts": 0,
                    "unreleased_api": [], "mirrors": 0}

    # -- 1. CT freshness -----------------------------------------------------
    if ct_fetch and base:
        try:
            entries = ct_entries(ct_fetch(base))
        except Exception as exc:      # the ledger is flaky/rate-limited; CT is
            entries = []              # optional intel, never a run-killer
            report["ct_error"] = str(exc)[:120]
        for name, issued in sorted(fresh_ct_names(entries, now, window_days).items()):
            is_new = name not in known_hosts
            node = agraph.add_node(HOST, name, attrs={"ct_issued": issued.isoformat()},
                                   source="ct")
            if is_new:
                report["ct_new_hosts"] += 1
            if graph is not None and is_new:
                graph.observe("host", name, attrs={"ct_issued": issued.isoformat()},
                              source="asset_radar")
            for cn in codename_labels(name, base):
                agraph.add_node(CODENAME, cn, source="ct")
                agraph.add_edge(f"{CODENAME}:{cn}", PROJECTS, node.id, source="ct")
            cert = agraph.add_node(CERT, f"{name}|{issued.strftime('%Y%m%d')}",
                                   attrs={"issued": issued.isoformat()}, source="ct")
            agraph.add_edge(cert.id, ANNOUNCES, node.id, source="ct")

    # -- 2. JS mining --------------------------------------------------------
    bodies: dict[str, str] = {}
    if js_bodies:
        bodies.update(js_bodies)
    elif fetch and base:
        for h in sorted(getattr(engagement, "allowed_hosts", []) or [])[:3]:
            h = h.strip()
            if h.startswith("*.") or "/" in h:
                continue
            try:
                status, body, _hd = fetch(f"https://{h}/")
                if status and 200 <= status < 300:
                    bodies[f"https://{h}/"] = body or ""
            except Exception:
                continue
    seen_scripts: set[str] = set()
    referenced_paths: list[str] = []
    for url, text in bodies.items():
        if not text:
            continue
        mined = mine_js(text, base)
        for p in mined["flag_codenames"]:
            agraph.add_node(CODENAME, p, attrs={"found_in": url}, source="js")
        for flag in mined["flag_codenames"]:
            fnode = agraph.add_node(FLAG, flag, attrs={"found_in": url}, source="js")
            agraph.add_edge(fnode.id, REFERENCES, f"{CODENAME}:{flag}", source="js")
        for prov in mined["providers"]:
            agraph.add_node(PROVIDER, prov, source="js")
        report["flags"] += len(mined["flag_codenames"])
        for host in mined["internal_hosts"]:
            hnode = agraph.add_node(HOST, host, attrs={"mentioned_in": url},
                                    source="js")
            if host not in known_hosts:
                report["internal_hosts"] += 1
            for cn in codename_labels(host, base):
                agraph.add_node(CODENAME, cn, source="js")
                agraph.add_edge(f"{CODENAME}:{cn}", PROJECTS, hnode.id, source="js")
        referenced_paths.extend(f"/api/v{v}/" for v in mined["api_versions"])
        if fetch is None:            # pre-fed bodies only; nothing more to fetch
            continue
        for script in mined["script_urls"]:
            abs_u = script if script.startswith("http") else urljoin(url, script)
            if abs_u in seen_scripts or len(seen_scripts) >= 24:
                continue
            seen_scripts.add(abs_u)
            try:
                status, body, _hd = fetch(abs_u)
                if status and 200 <= status < 300 and body:
                    m2 = mine_js(body, base)
                    for p in m2["flag_codenames"]:
                        agraph.add_node(CODENAME, p, attrs={"found_in": abs_u},
                                        source="js")
                    for flag in m2["flag_codenames"]:
                        fnode = agraph.add_node(FLAG, flag, attrs={"found_in": abs_u},
                                                source="js")
                        agraph.add_edge(fnode.id, REFERENCES, f"{CODENAME}:{flag}",
                                        source="js")
                    referenced_paths.extend(f"/api/v{v}/" for v in m2["api_versions"])
            except Exception:
                continue

    # -- 3. Version-ahead-of-live -------------------------------------------
    live_paths: list[str] = []
    if graph is not None:
        live_paths = [n.key for n in graph.nodes("endpoint")]  # URLs normalized in version_families
    unreleased = infer_version_edges(live_paths, referenced_paths)
    for item in unreleased:
        if item["edge"]:
            src, dst = item["edge"]
            agraph.add_node("endpoint", dst.split("endpoint:", 1)[-1],
                            attrs={"status": "referenced-not-live"}, source="radar")
            if agraph.node(src) is None:
                agraph.add_node("endpoint", src.split("endpoint:", 1)[-1],
                                attrs={"status": "live-max"}, source="radar")
            agraph.add_edge(src, PRECEDES, dst, source="radar")
    report["unreleased_api"] = [{"family": i["family"], "live_max": i["live_max"],
                                 "unreleased": i["unreleased"]} for i in unreleased]

    # -- 4. Codename-seeded DNS permutation ----------------------------------
    if resolve is not None:
        ranked = [b["codename"] for b in secret_builds(agraph)]
        for cn in ranked[:max(0, int(max_codenames_dns))]:
            for cand in permute_hostnames(cn)[:max(0, int(permute_budget))]:
                if cand in known_hosts or f"{cand}.{base}" in known_hosts:
                    continue
                fqdn = f"{cand}.{base}" if base else cand
                report["dns_probed"] += 1
                try:
                    ip = resolve(fqdn)
                except Exception:
                    ip = None
                if not ip:
                    continue
                report["dns_resolved"] += 1
                hnode = agraph.add_node(HOST, fqdn, attrs={"resolved_ip": str(ip)},
                                        source="dns")
                agraph.add_node(CODENAME, cn, source="dns")
                agraph.add_edge(f"{CODENAME}:{cn}", PROJECTS, hnode.id, source="dns")
                inode = agraph.add_node(IP, str(ip), source="dns")
                agraph.add_edge(hnode.id, RESOLVES_TO, inode.id, source="dns")

    # -- 5. Staging mirrors ---------------------------------------------------
    all_hosts = [n.key for n in agraph.nodes(HOST)]
    all_hosts += [str(h).lower() for h in (inventory.known_hosts() if inventory else [])]
    for stage, prod in infer_mirror_edges(all_hosts, base):
        s = agraph.add_node(HOST, stage, source="radar")
        p = agraph.add_node(HOST, prod, source="radar")
        if agraph.add_edge(s.id, MIRRORS, p.id, source="radar"):
            report["mirrors"] += 1

    report["builds"] = secret_builds(agraph)
    report["graph"] = agraph.summary()
    if audit is not None:
        audit.record("recon.asset_radar", base_domain=base,
                     ct_new_hosts=report["ct_new_hosts"],
                     dns_resolved=report["dns_resolved"],
                     builds=len(report["builds"]),
                     mirrors=report["mirrors"])
    return report
