"""engine/watch.py — M3 (G3a): the ambient wallet oracle.

GAP-PROOF band D, GV-8: the settle verb-probe CREDITED the prober during
discovery and "no oracle noticed" — discovery moved money, no finding
resulted, nothing saw it. The fix is an ambient observer at the one place a
money effect cannot hide: the balance read-back.

Mechanism (per technique act):
  adopt    — Env.register hands each new principal to the watcher, which
             snapshots its wallet right after login (<= 3 adopts per act;
             multi-principal race arms carry their own attribution in their
             finding evidence).
  settle   — after the act, one wallet read per adopted principal. The
             delta is ATTRIBUTED when the act produced a FINDING fact (the
             finding's own evidence tells the wallet story); otherwise it is
             an UNEXPLAINED ambient credit — the caller publishes the
             ESCALATION that is the OBSERVATION->hypothesis bridge's trigger.

Layering: spine module — must not import the swarm. All requests go through
the shared executor, so budget, STOP kill-file and traffic provenance apply.
Wallet discovery mirrors engine.window's read-back contract (readback list +
money-hint field), cached per watcher instance.
"""
MONEY_HINTS = ("balance", "credit", "wallet")

# adopts per technique act: single-principal arms always fit; race arms
# (8+ principals) carry their own evidence, so they are capped hardest.
MAX_ADOPTS_PER_ACT = 3


class WalletWatcher:
    """Ambient I4 oracle over the shared executor."""

    def __init__(self, ex, surface, phase="technique", events=None):
        self.ex = ex
        self.surface = surface or {}
        self.phase = phase
        self._spec = None                 # (path, field) money read-back
        self._baselines = {}              # principal name -> wallet cents
        self._adopted_this_act = 0
        # events may be a caller-owned list (the run context's shared
        # ambient_events) so the report and the attack graph see the trace
        self.events = events if events is not None else []

    # ----------------------------------------------------------- discovery --
    def _wallet_spec(self, p):
        if self._spec is not None:
            return self._spec
        self._spec = (None, None)
        for path in self.surface.get("readback", []) or []:
            if "{" in path:
                continue
            r = self.ex.request(p, "GET", path, phase=self.phase,
                                tag="ambient-spec")
            body = r["resp_body"]
            if isinstance(body, dict):
                for k, v in body.items():
                    if isinstance(v, int) and \
                            any(h in k.lower() for h in MONEY_HINTS):
                        self._spec = (path, k)
                        return self._spec
        return self._spec

    def wallet(self, p):
        path, field = self._wallet_spec(p)
        if not path:
            return None
        r = self.ex.request(p, "GET", path, phase=self.phase,
                            tag="ambient-wallet")
        v = r["resp_body"]
        return v.get(field) if isinstance(v, dict) else None

    # -------------------------------------------------------------- adopt --
    def begin_act(self, tag):
        """Called by the exploit specialist before each technique act."""
        self._current_tag = tag
        self._adopted_this_act = 0

    def adopt(self, principal):
        """Baseline a freshly registered principal (called by Env.register).
        Returns True when the baseline was taken."""
        if principal is None or \
                self._adopted_this_act >= MAX_ADOPTS_PER_ACT:
            return False
        w = self.wallet(principal)
        self._adopted_this_act += 1
        if w is None:
            return False
        self._baselines[principal.name] = w
        return True

    # ------------------------------------------------------------- settle --
    def settle_act(self, produced_findings):
        """One wallet read per adopted principal. attributed = the act
        produced a FINDING fact. Returns the UNEXPLAINED delta events."""
        attributed = bool(produced_findings)
        unexplained = []
        principal = None
        for name in list(self._baselines):
            principal = self.ex.principals.get(name)
            if principal is None:
                continue
            now = self.wallet(principal)
            before = self._baselines[name]
            self._baselines[name] = now if now is not None else before
            if now is None or now == before:
                continue
            evt = {"name": name, "tag": getattr(self, "_current_tag", "?"),
                   "before": before, "after": now, "delta": now - before,
                   "attributed": attributed}
            self.events.append(evt)
            if not attributed:
                unexplained.append(evt)
        return unexplained

    def summary(self):
        """Machine-readable watcher yield for the report/summary."""
        return {"events": len(self.events),
                "unexplained": sum(1 for e in self.events
                                   if not e["attributed"]),
                "deltas": [{"name": e["name"], "tag": e["tag"],
                            "delta": e["delta"],
                            "attributed": e["attributed"]}
                           for e in self.events]}
