"""SURFACE state specialist — turns raw observations into an attack-surface
graph: endpoints x auth model x stateful flows x parameterised objects.
This is the fact the hypothesis engine reasons over.

v2 (fortress upgrade): additionally parses the FULL openapi document into a
target-agnostic resource/action graph (resource_actions + body schemas +
declared kinds) so hypothesis/exploit can operate on UNSEEN domains instead
of dvlba-shaped keyword buckets. All v1 buckets are preserved.
"""
import re

from ..specialist import Specialist, Trigger

_READBACK_FALLBACK = ("wallet", "cart", "orders/{", "callback", "ledger",
                      "audit", "events", "history", "notifications")


def _split_path(p):
    """'/api/subscriptions/{subscription_id}/seats' ->
    ('api', 'subscriptions', '{subscription_id}', 'seats')"""
    return [s for s in p.strip("/").split("/") if s]


class SurfaceMapper(Specialist):
    name = "surface_mapper"
    states = ("SURFACE",)

    def triggers(self):
        return [Trigger("OBSERVATION",
                        lambda f, b: "openapi" in f["tags"], 2.0),
                Trigger("OBSERVATION",
                        lambda f, b: "route-index" in f["tags"], 1.9),
                Trigger("OBSERVATION",
                        lambda f, b: "robots" in f["tags"], 0.8)]

    def skills(self):
        return {"classify_paths": self._classify}

    @staticmethod
    def _classify(paths):
        buckets = {"param_objects": [], "coupon": [], "refund": [],
                   "redeem": [], "async": [], "state_writes": [],
                   "readback": [], "other": []}
        for p in paths:
            if "{order_id}" in p or "{id}" in p:
                buckets["param_objects"].append(p)
            if "coupon" in p and "redeem" in p:
                buckets["redeem"].append(p)
            elif "coupon" in p:
                buckets["coupon"].append(p)
            if "refund" in p and "async" in p:
                buckets["async"].append(p)
            elif "refund" in p:
                buckets["refund"].append(p)
            if "checkout" in p:
                buckets["state_writes"].append(p)
            if any(k in p for k in _READBACK_FALLBACK):
                buckets["readback"].append(p)
        return buckets

    # ------------------------------------------------------------ v2 graph --
    @staticmethod
    def _resource_graph(doc):
        """Parse openapi paths into {resource: {create, actions[], param}}.
        Target-agnostic: only path SHAPE and declared body schemas are used."""
        graph = {}
        for p, spec in (doc or {}).items():
            segs = _split_path(p)
            if len(segs) < 2:
                continue
            resource = segs[1]
            g = graph.setdefault(resource, {"create": None, "actions": [],
                                            "param": None, "param_name": None})
            method_spec = None
            for m in ("post", "get", "put", "patch", "delete"):
                if m in spec:
                    method_spec = spec[m]
                    method = m
                    break
            if method_spec is None:
                continue
            body = (method_spec.get("requestBody") or {}).get(
                "application/json", {}).get("schema", {})
            props = body.get("properties", {})
            kind = method_spec.get("x-kind", "")
            params = [pp.get("name") for pp in method_spec.get("parameters", [])
                      if pp.get("in") == "path"]
            if len(segs) == 2 and method == "post" and not params:
                g["create"] = p
                g["create_schema"] = props
            elif params:
                if g["param"] is None:      # keep the FIRST param path (read)
                    g["param"] = p
                g["param_name"] = params[0]
                verb = segs[-1] if segs[-1] != ("{%s}" % params[0]) else \
                    ("read" if method == "get" else "mutate")
                if method == "get" and verb != "read":
                    verb = "read_" + verb
                g["actions"].append({"verb": verb, "path": p,
                                     "method": method.upper(),
                                     "schema": props, "kind": kind})
            elif len(segs) >= 3 and method == "post":
                # verb-style action path without a path parameter, e.g.
                # /api/promo/claim or /api/credits/transfer
                g["actions"].append({"verb": segs[-1], "path": p,
                                     "method": "POST",
                                     "schema": props, "kind": kind})
        return graph

    # ------------------------------------------- U2: route-index graph -------
    @staticmethod
    def _surface_from_index(index):
        """hard-lab upgrade U2: build the attack-surface graph from a thin
        route index (resources + verbs, NO schemas/params/state machine).
        Target-agnostic: consumes the route-index SHAPE, not target names."""
        graph = {}
        readback = []
        for res, spec in (index or {}).items():
            if not isinstance(spec, dict):
                continue
            g = graph.setdefault(res, {"create": None, "actions": [],
                                       "param": None, "param_name": None,
                                       "create_schema": {}})
            for entry in spec.get("actions", []) or []:
                verb = str(entry.get("verb") or
                           (entry.get("path", "").rstrip("/").split("/")[-1]
                            if entry.get("path") else "?"))
                g["actions"].append({"verb": verb,
                                     "path": entry.get("path"),
                                     "method": entry.get("method", "POST"),
                                     "schema": {},
                                     "schema_unknown": True})
            if isinstance(spec.get("create"), dict):
                g["create"] = spec["create"]["path"]
                g["create_schema"] = {}
            if isinstance(spec.get("object"), dict):
                opath = spec["object"]["path"]
                g["param"] = opath
                if "{" in opath and "}" in opath:
                    g["param_name"] = opath.split("{")[1].split("}")[0]
            if isinstance(spec.get("read"), dict):
                rp = spec["read"]["path"]
                if "{" not in rp:
                    readback.append(rp)
        return graph, readback

    def act(self, fact, board):
        ex, anon = self.ctx["executor"], self.ctx["anon"]
        produced = []
        if "openapi" in fact["tags"]:
            paths = fact["payload"]["openapi_paths"]
            doc = fact["payload"].get("openapi_doc") or {}
            buckets = self._classify(paths)
            graph = self._resource_graph(doc)

            # auth boundary probe (execution evidence, E6 — not assumption)
            r = ex.request(anon, "GET", "/api/wallet", phase="surface",
                           tag="auth_boundary_probe")
            auth = ("bearer-required" if r["status"] == 401
                    else "open:%d" % r["status"])

            # v2 stateful flows: any resource with a create AND >=1 action
            flows = []
            if any("checkout/confirm" in p for p in paths):
                flows.append("checkout/init -> checkout/confirm")
            for res, g in sorted(graph.items()):
                if g["create"] and g["actions"]:
                    verbs = ",".join(a["verb"] for a in g["actions"])
                    flows.append("%s: create -> %s" % (res, verbs))

            surface = {
                "path_count": len(paths),
                "endpoints": paths,
                "auth_model": auth,
                "stateful_flows": flows,
                "resource_actions": graph,
                **buckets,
            }
            produced.append(self.pub(board, "SURFACE", surface,
                                     tags=["surface"],
                                     derived_from=[fact["id"]]))
            produced.append(self.pub(board, "OBSERVATION",
                {"auth_model": auth,
                 "evidence": "anon GET /api/wallet -> %d" % r["status"]},
                tags=["auth-boundary"], derived_from=[fact["id"]]))
            self.private.setdefault("outcomes", {})["map_surface"] = "success"
            self.private.setdefault("tech_facts", {})["map_surface"] = \
                [f["id"] for f in produced]
        elif "route-index" in fact["tags"]:
            # hard-lab upgrade U2: openapi-less surface from the route index.
            index = fact["payload"].get("route_index") or {}
            graph, readback = self._surface_from_index(index)

            r = ex.request(anon, "GET", readback[0] if readback else "/api/me",
                           phase="surface", tag="auth_boundary_probe")
            auth = ("bearer-required" if r["status"] == 401
                    else "open:%d" % r["status"])

            flows = []
            for res, g in sorted(graph.items()):
                if g["create"] and g["actions"]:
                    verbs = ",".join(a["verb"] for a in g["actions"])
                    flows.append("%s: create -> %s" % (res, verbs))
                elif g["create"] is None and g["actions"]:
                    verbs = ",".join(a["verb"] for a in g["actions"])
                    flows.append("%s: %s" % (res, verbs))

            surface = {
                "path_count": len(graph),
                "endpoints": sorted({a["path"] for g in graph.values()
                                     for a in g["actions"]
                                     if a.get("path")} |
                                    {g["create"] for g in graph.values()
                                     if g["create"]} |
                                    {g["param"] for g in graph.values()
                                     if g["param"]} |
                                    set(readback) - {None}),
                "auth_model": auth,
                "stateful_flows": flows,
                "resource_actions": graph,
                "readback": readback,
                "param_objects": [g["param"] for g in graph.values()
                                  if g["param"]],
                "source": "route-index",
            }
            produced.append(self.pub(board, "SURFACE", surface,
                                     tags=["surface"],
                                     derived_from=[fact["id"]]))
            produced.append(self.pub(board, "OBSERVATION",
                {"auth_model": auth,
                 "evidence": "anon GET %s -> %d"
                             % (readback[0] if readback else "/api/me",
                                r["status"])},
                tags=["auth-boundary"], derived_from=[fact["id"]]))
            self.private.setdefault("outcomes", {})["map_surface"] = "success"
            self.private.setdefault("tech_facts", {})["map_surface"] = \
                [f["id"] for f in produced]
        else:  # robots
            produced.append(self.pub(board, "OBSERVATION",
                {"note": "robots parsed; no new scope"},
                tags=["robots-parsed"], derived_from=[fact["id"]]))
        return produced
