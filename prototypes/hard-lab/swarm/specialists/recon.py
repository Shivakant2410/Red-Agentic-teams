"""RECON state specialist. Minimal skill surface (M8): raw HTTP fetch + path
probe only. Techniques are bandit-ordered from its own memory namespace
(E1) — dead-end techniques learned in a previous run are skipped outright
(posterior < 0.4 with >= 1 trial), which is the demo-visible improvement.
"""
from ..specialist import Specialist, Trigger

import re                # hard-lab upgrade U1: hint extraction

PROBE_PATHS = ["/admin", "/api/admin", "/.git/HEAD", "/backup.zip",
               "/.env", "/api/debug"]


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
        for tech in self.memory.technique_order(
                ["fetch_robots", "fetch_index", "fetch_route_index",
                 "fetch_openapi", "probe_common_paths",
                 "fingerprint_server"]):
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
