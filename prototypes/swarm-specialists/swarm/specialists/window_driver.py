"""WINDOW state specialist — M1 (G1): the ledger steering the run.

The M0 spine was a passive sink: techniques ran, the board was projected
into the ledger at end-of-run. This specialist inverts the flow — the
ledger's live markers decide what happens NEXT between dispatch rounds:

  1. GROUND  — every unmarked 202/event exchange in the shared traffic
     transcript is published as an async-opened OBSERVATION (grounded on
     the freshest SURFACE fact, E6) and registered as a marker.
  2. MARK    — the triggering async-opened fact's own shape is registered
     (idempotent per event path).
  3. DRIVE   — WindowDriver.drive_pending() polls windows to settle,
     probes cancel-after-settle (GV-5) and, once per run, opens a fresh
     drained window (GV-4). Violations become FINDING facts carrying
     technique "h_window_driver"; markers resolve in the ledger with the
     wallet trace as evidence.

Without the spine (ctx["ledger"] None) the specialist is inert — the
deterministic v1 path is untouched, same contract as the M0 seam.
"""
from ..specialist import Specialist, Trigger


class WindowDriverSpecialist(Specialist):
    name = "window_driver"
    states = ("WINDOW",)

    def triggers(self):
        return [Trigger("OBSERVATION",
                        lambda f, b: "async-opened" in f["tags"], 2.1),
                Trigger("CONTROL",
                        lambda f, b: f["payload"].get("event")
                        == "stall-escalate", 1.2)]

    # no scoped skills of its own: the driver acts through the shared
    # executor inside act() — the ledger marker state is its tool selector
    # (G1c), and an empty skill surface keeps the M2/M8 contract honest.

    # ---------------------------------------------------------------- act --
    def act(self, fact, board):
        ledger = self.ctx.get("ledger")
        if ledger is None:
            return []                    # spine off: v1 path unchanged
        try:
            from engine.window import WindowDriver
        except ImportError:
            return []
        surfaces = board.query(kind="SURFACE")
        surface = surfaces[-1]["payload"] if surfaces else {}
        driver = WindowDriver(ledger, self.ctx["executor"], surface,
                              anon=self.ctx.get("anon"), phase="window",
                              state=self.private.setdefault("m1_state", {}))
        grounding = self._grounding(board, fact)
        marked = {(e.get("marker") or {}).get("event_path")
                  for e in ledger.markers()}

        produced = []
        # 1) auto-register markers from ANY unmarked 202/event in traffic
        for shape in driver.scan_traffic():
            if shape["event_path"] in marked:
                continue
            if not shape.get("principal") or shape["principal"] not in \
                    self.ctx["executor"].principals:
                continue
            obs = self.pub(board, "OBSERVATION",
                           {"async_opened": shape,
                            "evidence": "auto-registered from traffic scan "
                                        "(202/event shape)"},
                           tags=["async-opened", "traffic-scan"],
                           derived_from=grounding)
            driver.open_from_shape(shape, [obs["id"]],
                                   "window-driver/scan")
        # 2) the triggering fact's own seam
        shape = fact["payload"].get("async_opened")
        if shape:
            driver.open_from_shape(shape, [fact["id"]],
                                   "window-driver/obs")
        # 3) drive every pending window (interleaved — this runs between
        #    dispatch rounds, inside the settle TTL)
        for item in driver.drive_pending(grounding=grounding):
            produced.append(self.pub(board, "FINDING",
                {"finding": item, "status": "candidate",
                 "technique": "h_window_driver"}, confidence=0.9,
                tags=["h_window_driver", item.get("invariant", "")],
                derived_from=grounding))
        return produced

    def _grounding(self, board, fact):
        """E6: the freshest surface or observation fact id the marker can
        cite. The triggering fact itself is already observation-grade."""
        if fact["kind"] in ("OBSERVATION", "SURFACE"):
            return [fact["id"]]
        surfaces = board.query(kind="SURFACE")
        if surfaces:
            return [surfaces[-1]["id"]]
        return [fact["id"]]
