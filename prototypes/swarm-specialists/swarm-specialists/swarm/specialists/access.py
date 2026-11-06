"""ACCESS state specialist — post-exploit impact: consumes verification
events and turns verified findings into capability chains (confused-deputy
reachability, Phase-A S8.5), publishing ESCALATION facts with the chain
impact. Fires only on VERIFIED work — access never escalates refuted noise.
"""
from ..specialist import Specialist, Trigger
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
        return produced
