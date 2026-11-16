"""RECON state specialist. Minimal skill surface (M8): raw HTTP fetch + path
probe only. Techniques are bandit-ordered from its own memory namespace
(E1) — dead-end techniques learned in a previous run are skipped outright
(posterior < 0.4 with >= 1 trial), which is the demo-visible improvement.

M5 (offensive core, RESEARCH-M5 §1–2): the discovery ladder is the
bug-bounty tradecraft stack, target-derived FIRST and generic SECOND —
  mine_asset_strings  LinkFinder-style: endpoint-shaped strings harvested
                      from the index page and its asset references (the
                      declared surface only shows what the doc admits).
  derive_probe_paths  content discovery candidates DERIVED from the
                      observed vocabulary (resource nouns + lifecycle
                      suffixes), not from a static list; the generic
                      PROBE_PATHS sweep is demoted to the fallback arm.
  harvest_param_names every observed response body's keys feed a run-wide
                      parameter pool (notes["param_pool"]) that the PREEX
                      hidden-parameter miner consumes — recon output must
                      be consumable input, not a dead-end log line.
"""
from ..specialist import Specialist, Trigger

import re                # hard-lab upgrade U1: hint extraction

PROBE_PATHS = ["/admin", "/api/admin", "/.git/HEAD", "/backup.zip",
               "/.env", "/api/debug"]

# lifecycle/administrative suffixes tried AFTER an observed resource noun
# (target-derived content discovery; nothing here is target-specific)
_NOUN_SUFFIXES = ("recent", "history", "all", "list", "export", "audit",
                  "internal", "bulk")

# lifecycle verbs appended to parameterised object paths (hidden state
# machines: settle/rebook/release-class verbs the stale doc never mentions)
_LIFECYCLE_VERBS = ("settle", "rebook", "cancel", "release", "consume",
                    "pickup", "deliver", "approve", "retry")

# endpoint-shaped path inside JS/HTML/assets: /seg/seg with word/param chars
_ASSET_PATH_RE = re.compile(
    r"[\"'`](/(?:api|v\d)?/[A-Za-z0-9_\-.{}]+(?:/[A-Za-z0-9_\-.{}]+)+)"
    r"[\"'`]")
_SRC_RE = re.compile(r"(?:src|href)=\"([^\"]+)\"")

# plausible field-name keys harvested into the run-wide parameter pool
_FIELD_RE = re.compile(r"^[a-z][a-z0-9_]{2,40}$")
_STOP_KEYS = {"error", "status", "paths", "info", "openapi", "resources",
              "service", "summary", "requestbody", "schema", "properties",
              "type", "required", "name", "parameters", "version", "title",
              "raw", "token", "password", "username", "raw", "hint"}


def _derive_candidates(documented_paths, cap=16):
    """Content-discovery candidates DERIVED from the target's observed
    vocabulary (Intigriti 2025 tradecraft, target-agnostic):
      item level       — parameterised object paths x lifecycle verbs
                         (hidden state machines outrank everything);
      collection level — resource-noun paths (len==2) x lifecycle suffixes.
    Documented paths are excluded, candidates deduped, capped for budget."""
    doc = {str(p).rstrip("/") for p in (documented_paths or []) if p}
    out = []
    param_paths = []
    for p in sorted(doc):
        segs = [s for s in p.split("/") if s]
        if len(segs) == 2 and not p.endswith(("claim", "login",
                                              "register")):
            for suf in _NOUN_SUFFIXES:
                c = p + "/" + suf
                if c not in doc:
                    out.append(c)
        elif any("{" in s for s in segs) and segs[-1].startswith("{"):
            # OBJECT paths only: lifecycle verbs on an already-verb-ful
            # action sub-path (/rerate/settle) are junk candidates
            param_paths.append(p)
    verb_out = []
    for p in param_paths:
        tail = p.rstrip("/").split("/")[-1]
        if tail in _LIFECYCLE_VERBS:
            continue
        for v in _LIFECYCLE_VERBS:
            c = p.rstrip("/") + "/" + v
            if c not in doc:
                verb_out.append(c)
    return (verb_out + out)[:cap]


def _collect_field_keys(obj, acc, depth=0):
    if depth > 3 or not isinstance(obj, dict):
        return
    for k, v in obj.items():
        if isinstance(k, str) and _FIELD_RE.match(k) and k not in _STOP_KEYS:
            acc.add(k)
        if isinstance(v, (dict, list)):
            _collect_field_keys(v, acc, depth + 1)


def _documented_paths(board):
    """Paths the target itself has disclosed so far (openapi doc, route
    index) — the seed vocabulary for derivation."""
    paths = []
    try:
        facts = board.query(kind="OBSERVATION")
    except Exception:
        return paths
    for f in facts:
        pl = f.get("payload") or {}
        if "openapi" in (f.get("tags") or []):
            paths.extend(pl.get("openapi_paths") or [])
        elif "route-index" in (f.get("tags") or []):
            idx = pl.get("route_index") or {}
            for spec in idx.values() if isinstance(idx, dict) else []:
                if isinstance(spec, dict):
                    for entry in spec.get("actions", []) or []:
                        if entry.get("path"):
                            paths.append(entry["path"])
                    if isinstance(spec.get("create"), dict) and \
                            spec["create"].get("path"):
                        paths.append(spec["create"]["path"])
                    if isinstance(spec.get("object"), dict) and \
                            spec["object"].get("path"):
                        paths.append(spec["object"]["path"])
    return paths


class ReconSpecialist(Specialist):
    name = "recon"
    states = ("RECON",)

    def triggers(self):
        return [Trigger("CONTROL", lambda f, b:
                        f["payload"].get("event") == "engage", 2.0)]

    def skills(self):
        return {"fetch": lambda m, p, b=None: self.ctx["executor"].request(
                    m, "GET", p, body=b, phase="recon"),
                "probe_path": lambda m, p: self.ctx["executor"].request(
                    m, "GET", p, phase="recon")}

    # ------------------------------------------------------------------ act --
    def act(self, fact, board):
        ex, anon = self.ctx["executor"], self.ctx["anon"]
        done = self.private.setdefault("done", [])
        produced = []
        # M5 group-aware ordering (E1 bandit orders WITHIN groups): the
        # disclosure ladder is the information source — derived techniques
        # (asset mining, content discovery, param harvest) consume its
        # facts, so they must not run before it on a fresh bandit.
        order = self.memory.technique_order(
            ["fetch_robots", "fetch_index", "fetch_route_index",
             "fetch_openapi"]) + \
            self.memory.technique_order(
            ["mine_asset_strings", "derive_probe_paths",
             "harvest_param_names"]) + \
            self.memory.technique_order(
            ["probe_common_paths", "fingerprint_server"])
        for tech in order:
            if tech in done:
                continue
            done.append(tech)
            if not self.memory.should_run(tech):
                self.private.setdefault("skipped", []).append(tech)
                continue
            n0 = len(produced)
            # hard-lab upgrade U1: index/route-index recon (Kettle BH'23 step-2
            # "probe for clues" tradecraft; target-agnostic).
            if tech == "fetch_index":
                r = ex.request(anon, "GET", "/", phase="recon", tag=tech)
                body = r["resp_body"]
                if 200 <= r["status"] < 300:
                    raw = body.get("raw", "") if isinstance(body, dict) else ""
                    hints = []
                    for m in re.findall(r"<!--(.*?)-->", raw, re.S):
                        hints.append(m.strip()[:200])
                    for m in re.findall(r"src=\"([^\"]+)\"", raw):
                        hints.append(m)
                    if hints:
                        produced.append(self.pub(board, "OBSERVATION",
                            {"index_status": r["status"], "hints": hints},
                            tags=["index"], derived_from=[fact["id"]]))
            elif tech == "fetch_route_index":
                r = ex.request(anon, "GET", "/api", phase="recon", tag=tech)
                if 200 <= r["status"] < 300 and \
                        isinstance(r["resp_body"].get("resources"), dict):
                    produced.append(self.pub(board, "OBSERVATION",
                        {"route_index": r["resp_body"]["resources"],
                         "service": r["resp_body"].get("service"),
                         "resources": sorted(r["resp_body"]["resources"])},
                        tags=["route-index"], derived_from=[fact["id"]]))
            elif tech == "mine_asset_strings":
                # LinkFinder-style: endpoint-shaped strings from the index
                # page and its asset references (M5/RESEARCH-M5 §1)
                r = ex.request(anon, "GET", "/", phase="recon", tag=tech)
                found, probed_assets = set(), 0
                if 200 <= r["status"] < 300:
                    raw = r["resp_body"].get("raw", "") \
                        if isinstance(r["resp_body"], dict) else ""
                    found.update(_ASSET_PATH_RE.findall(raw or ""))
                    for src in _SRC_RE.findall(raw or "")[:3]:
                        if not src.startswith("/") or \
                                ex.count >= self.ctx["budget"] - 4:
                            continue
                        ra = ex.request(anon, "GET", src.split("?")[0],
                                        phase="recon", tag=tech)
                        probed_assets += 1
                        araw = ra["resp_body"].get("raw", "") \
                            if isinstance(ra["resp_body"], dict) else \
                            (ra["resp_body"] if isinstance(
                                ra["resp_body"], str) else "")
                        found.update(_ASSET_PATH_RE.findall(araw or ""))
                if found:
                    produced.append(self.pub(board, "OBSERVATION",
                        {"asset_endpoints": sorted(found)[:24],
                         "assets_probed": probed_assets,
                         "origin": "asset-mining"},
                        tags=["asset-mining"], derived_from=[fact["id"]]))
            elif tech == "derive_probe_paths":
                # target-derived content discovery (M5): error-differential
                # probing — 401/403/405 on a candidate means the route EXISTS
                # behind auth/method; 404 means absent. Unauthenticated, so
                # the policy never sees a write. Self-sufficient: if the
                # disclosure ladder has not published a doc yet, fetch one.
                paths = _documented_paths(board)
                if not paths:
                    rd = ex.request(anon, "GET", "/openapi.json",
                                    phase="recon", tag=tech)
                    if 200 <= rd["status"] < 300 and \
                            isinstance(rd["resp_body"], dict) and \
                            "paths" in rd["resp_body"]:
                        paths = sorted(rd["resp_body"]["paths"])
                cands = _derive_candidates(paths)
                hits = []
                for c in cands:
                    if ex.count >= self.ctx["budget"] - 2:
                        break
                    rr = ex.request(anon, "GET", c, phase="recon",
                                    tag=tech)
                    if rr["status"] != 404:
                        hits.append({"path": c, "status": rr["status"],
                                     "signal": ("live" if
                                                rr["status"] < 300 else
                                                "walled")})
                if hits:
                    produced.append(self.pub(board, "OBSERVATION",
                        {"derived_probes": {"probed": len(cands),
                                            "hits": hits},
                         "origin": "derived-content-discovery"},
                        tags=["derived-content-discovery"],
                        derived_from=[fact["id"]]))
            elif tech == "harvest_param_names":
                # every observed vocabulary key feeds the run-wide parameter
                # pool the PREEX hidden-parameter miner consumes (M5)
                pool = set()
                try:
                    for f2 in board.query(kind="OBSERVATION"):
                        _collect_field_keys(f2.get("payload") or {}, pool)
                except Exception:
                    pass
                if pool:
                    produced.append(self.pub(board, "OBSERVATION",
                        {"param_pool": sorted(pool)[:64],
                         "origin": "harvest_param_names"},
                        tags=["param-pool"], derived_from=[fact["id"]]))
            elif tech == "fetch_robots":
                r = ex.request(anon, "GET", "/robots.txt", phase="recon",
                               tag=tech)
                if 200 <= r["status"] < 300:
                    produced.append(self.pub(board, "OBSERVATION",
                        {"robots": r["resp_body"]}, tags=["robots"],
                        derived_from=[fact["id"]]))
            elif tech == "fetch_openapi":
                r = ex.request(anon, "GET", "/openapi.json", phase="recon",
                               tag=tech)
                if 200 <= r["status"] < 300 and "paths" in r["resp_body"]:
                    produced.append(self.pub(board, "OBSERVATION",
                        {"openapi_paths": sorted(r["resp_body"]["paths"]),
                         "openapi_doc": r["resp_body"]["paths"],
                         "count": len(r["resp_body"]["paths"])},
                        tags=["openapi"], derived_from=[fact["id"]]))
            elif tech == "probe_common_paths":
                hits, probed = [], 0
                for p in PROBE_PATHS:
                    r = ex.request(anon, "GET", p, phase="recon", tag=tech)
                    probed += 1
                    if 200 <= r["status"] < 300:
                        hits.append(p)
                if hits:
                    produced.append(self.pub(board, "OBSERVATION",
                        {"probed": probed, "hits": hits},
                        tags=["paths"], derived_from=[fact["id"]]))
                # no hits = no consumable intel: dead-end probing is a FAILURE
                # outcome, not a success-with-empty-fact (E1 incentive fix)
            elif tech == "fingerprint_server":
                r = ex.request(anon, "GET", "/health", phase="recon",
                               tag=tech)
                hdr = (r.get("resp_headers") or {})
                if hdr.get("Server"):
                    produced.append(self.pub(board, "OBSERVATION",
                        {"status": r["status"], "server": hdr["Server"]},
                        tags=["fingerprint"], derived_from=[fact["id"]]))
                # absent banner -> no fact -> failure outcome
            # technique outcome (raw; curation applies verification weights)
            self.private.setdefault("outcomes", {})[tech] = \
                "success" if len(produced) > n0 else "failure"
            self.private.setdefault("tech_facts", {})[tech] = \
                [f["id"] for f in produced[n0:]]
        return produced
