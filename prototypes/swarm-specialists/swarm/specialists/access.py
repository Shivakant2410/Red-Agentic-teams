"""ACCESS state specialist — post-exploit impact: consumes verification
events and turns verified findings into capability chains (confused-deputy
reachability, Phase-A S8.5), publishing ESCALATION facts with the chain
impact. Fires only on VERIFIED work — access never escalates refuted noise.

M5 (offensive core): on the first verified finding it ALSO runs the
post-exploitation ladder (techniques_postex) — amplification of the
verified primitive across fresh victim principals (reachability math,
BloodHound/Elmiger + XBOW variant analysis), persistence/replay
(double-credit detection), and a capability footprint of a foothold
session. Post-ex payloads publish as ESCALATION facts tagged "postex";
they are measured evidence on VERIFIED work only, never new claims.
"""
from ..specialist import Specialist, Trigger
from .. import techniques as T
from .. import techniques_postex as PXT
from statefuzz import chains as chainlib


class AccessSpecialist(Specialist):
    name = "access"
    states = ("ACCESS",)

    def triggers(self):
        return [Trigger("CONTROL",
                        lambda f, b: f["payload"].get("event") ==
                        "finding_verified", 1.2)]

    def skills(self):
        return {"chain": chainlib.build_chains}

    def act(self, fact, board):
        verified = [f for f in board.query(kind="FINDING")
                    if str(f["payload"].get("status", "")).startswith(
                        "verified")]
        # dedupe across provenance copies before chaining (SW-* vs SF-* are
        # the same capability if invariant+endpoint match)
        seen, fds = set(), []
        for f in verified:
            fd = f["payload"]["finding"]
            key = (fd["invariant"], fd["endpoint"])
            if key not in seen:
                seen.add(key)
                fds.append(fd)
        seen_chains = self.private.setdefault("published_chains", set())

        produced = []
        try:
            chains_ = chainlib.build_chains(fds)
        except Exception:
            chains_ = []
        for c in chains_:
            if c["chain_id"] in seen_chains:
                continue
            seen_chains.add(c["chain_id"])
            produced.append(self.pub(board, "ESCALATION",
                {"chain": c, "impact": c["impact"],
                 "severity": c["severity"],
                 "members": c["members"]},
                tags=["chain", c["severity"]],
                derived_from=[f["id"] for f in verified
                              if f["payload"]["finding"]["id"]
                              in c["members"]]))
        # accumulate (never overwrite): success if ANY dispatch produced work
        prev = self.private.setdefault("outcomes", {}).get("escalate")
        self.private["outcomes"]["escalate"] = "success" if (
            produced or prev == "success") else "failure"
        tf = self.private.setdefault("tech_facts", {}).setdefault(
            "escalate", [])
        tf.extend(f["id"] for f in produced)

        # ---------------- M5: post-exploitation ladder (once per run) -----
        if verified and "postex_done" not in self.private and \
                (self.ctx["budget"] - self.ctx["executor"].count) >= 48:
            self.private["postex_done"] = True
            surface = None
            try:
                for f2 in board.query(kind="SURFACE"):
                    surface = f2["payload"]          # latest wins
            except Exception:
                surface = None
            if surface and surface.get("resource_actions"):
                env = T.Env(self.ctx["executor"], self.ctx["anon"], surface,
                            self.ctx["budget"], phase="postex")
                try:
                    pxt_out, pxt_pay = PXT.run(
                        env, [f["payload"] for f in verified])
                except Exception:
                    pxt_out, pxt_pay = {}, {}
                for tech, oc in pxt_out.items():
                    self.memory.record(tech, oc, 1.0)
                self.memory.record("postex_ladder",
                                   "success" if pxt_pay else "failure", 0.75)
                for name, payload in pxt_pay.items():
                    produced.append(self.pub(board, "ESCALATION",
                        {"postex": payload, "technique": name},
                        tags=["postex", name],
                        derived_from=[f["id"] for f in verified]))
                self.private["outcomes"]["postex"] = \
                    "success" if pxt_pay else "failure"
                self.private.setdefault("tech_facts", {})["postex"] = \
                    [f["id"] for f in produced]
        return produced
