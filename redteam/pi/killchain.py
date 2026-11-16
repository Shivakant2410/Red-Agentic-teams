"""Kill-chain projection of the PI registry (our tool).

The registry organizes by delivery family; the planner organizes by
(technique, stage) reachability. Neither answers the operator's chain
question: THROUGH WHICH PHASES does each technique move an attack, and
WHERE does the chain break under a given capability set? This module
answers it MECHANICALLY — every phase assignment is derived from the
registry's own fields (payload encodings, oracle choice, success stage,
payload URLs), so the map cannot drift from the registry it describes.

Ancestry — two real frameworks, named:
  MITRE ATLAS tactics   the phase anchors cite the ATLAS tactic each phase
                        sits in (labels verified in atlas.py's catalog:
                        Execution T0051, Privilege Escalation T0053/T0054,
                        Persistence T0020/T0051.002, Exfiltration
                        T0057/T0077/T0086, Resource Development T0020).
  Hutchins et al. 2011  the canonical intrusion kill chain (Reconnaissance,
                        Weaponization, Delivery, Exploitation, Installation,
                        Command & Control, Actions on Objectives) — the
                        PHASE SHAPES descend from it, adapted to the PI
                        surface: C2 is folded into DELIVER/EXECUTE (the
                        directive IS the control channel), and the three
                        terminal outcomes of this surface (privilege use,
                        persistence, exfiltration) split Actions on
                        Objectives.

The seven phases:
  RECON      map channels/tools/capabilities. NO technique occupies it:
             the recon artifact is the planner's own output
             (deployment_plan / attack graph) — recorded here as such.
  WEAPONIZE  payload construction: encoded companions ({b64}/{tags}/
             {zw}/{rot13}) or operator-supplied search material (the A6
             suffix). Mechanical rule, documented below.
  DELIVER    untrusted-channel entry (or the attacker's own turn for the
             direct family). Every technique delivers; the map records
             direct vs indirect per the channel's untrusted flag.
  EXECUTE    the model adopts the directive (canary RELAYED or beyond).
             Registry invariant: every technique's success stage is at
             least RELAYED, so every technique occupies EXECUTE.
  PRIVILEGE  attacker-directed privileged action — the forbidden-tool
             oracle's success stage (ATLAS T0053 tool invocation,
             T0054 jailbreak adjacency).
  PERSIST    cross-session survival — the PERSISTED success stage
             (ATLAS T0020 poisoning / T0051.002 triggered adjacency).
  EXFIL      data movement toward an attacker-controlled channel — the
             canary riding an egress-shaped URL in the payload body
             (ATLAS T0077/T0086 shapes; T0057 broader).

kill_chain_map()       the static projection: phases per technique.
kill_chain_plan()      the capability-conditioned projection: reuses the
                       attack-graph planner's reachability (kernel-backed)
                       and reports per-phase alive/blocked, chain breaks,
                       and the deepest reachable phase.
kill_chain_audit()     the CLI payload: full registry, fixture capabilities,
                       structural gaps, and the phase anchors.
"""

from __future__ import annotations

from .oracles import CanaryStage
from .planner import FIXTURE_CAPABILITIES, deployment_plan
from .techniques import BY_ID, DELIVERY_CHANNELS, TECHNIQUES, PITechnique

__all__ = [
    "PHASES",
    "PHASE_RANK",
    "PHASE_ANCHORS",
    "kill_chain_map",
    "kill_chain_plan",
    "kill_chain_audit",
]

PHASES: tuple[str, ...] = (
    "RECON", "WEAPONIZE", "DELIVER", "EXECUTE",
    "PRIVILEGE", "PERSIST", "EXFIL",
)

# Outcome depth: how far along the chain a technique cashes out. The three
# terminal phases sit at the same rank — they are alternative objectives.
PHASE_RANK: dict[str, int] = {
    "RECON": 0, "WEAPONIZE": 1, "DELIVER": 2, "EXECUTE": 3,
    "PRIVILEGE": 4, "PERSIST": 4, "EXFIL": 4,
}

PHASE_ANCHORS: dict[str, dict] = {
    "RECON": {
        "atlas_tactic": "Reconnaissance",
        "kill_chain": "Reconnaissance (Hutchins et al. 2011)",
        "artifact": "deployment_plan / attack graph — recon is the planner's "
                    "output, not a technique",
    },
    "WEAPONIZE": {
        "atlas_tactic": "Resource Development / ML Attack Staging",
        "kill_chain": "Weaponization (Hutchins et al. 2011)",
        "artifact": "encoded companions or operator-supplied optimization "
                    "material inside a technique's payloads",
    },
    "DELIVER": {
        "atlas_tactic": "Initial Access",
        "kill_chain": "Delivery (Hutchins et al. 2011)",
        "artifact": "the technique's delivery channels (direct vs untrusted)",
    },
    "EXECUTE": {
        "atlas_tactic": "Execution (AML.T0051)",
        "kill_chain": "Exploitation (Hutchins et al. 2011)",
        "artifact": "the canary oracle's RELAYED stage — directive adoption",
    },
    "PRIVILEGE": {
        "atlas_tactic": "Privilege Escalation (AML.T0053/T0054)",
        "kill_chain": "Exploitation/Installation (Hutchins et al. 2011)",
        "artifact": "the forbidden-tool oracle — agent tool invocation "
                    "under attacker direction",
    },
    "PERSIST": {
        "atlas_tactic": "Persistence (AML.T0020, T0051.002)",
        "kill_chain": "Installation (Hutchins et al. 2011)",
        "artifact": "the PERSISTED success stage — survival into a later "
                    "session",
    },
    "EXFIL": {
        "atlas_tactic": "Exfiltration (AML.T0057/T0077/T0086)",
        "kill_chain": "Actions on Objectives (Hutchins et al. 2011)",
        "artifact": "the canary riding an egress-shaped URL in the payload "
                    "body (T0077 render relay, T0086 tool-input relay)",
    },
}


def _occupies_weaponize(t: PITechnique) -> bool:
    """Encoded companions ({b64}/{tags}/{zw}/{rot13}) or operator-supplied
    optimization material — payload CONSTRUCTION beyond plain text."""
    return any(p.encoded_body for p in t.payloads) or bool(t.operator_input)


def _occupies_exfil(t: PITechnique) -> bool:
    """The canary rides an egress-shaped URL in a VISIBLE payload body: the
    movement is toward an attacker-addressable channel (render relay or
    outbound request). Encoded companions do not count — their movement is
    model-internal until decoded."""
    return any("https://" in p.body and "{canary}" in p.body
               for p in t.payloads)


def _phases_for(t: PITechnique) -> list[str]:
    """Mechanical phase derivation from the registry's own fields. Order is
    the chain order (WEAPONIZE first, terminal outcomes last)."""
    phases: list[str] = []
    if _occupies_weaponize(t):
        phases.append("WEAPONIZE")
    phases.append("DELIVER")
    phases.append("EXECUTE")
    if t.primary_oracle == "pi.forbidden_tool":
        phases.append("PRIVILEGE")
    if t.success_stage is CanaryStage.PERSISTED:
        phases.append("PERSIST")
    if _occupies_exfil(t):
        phases.append("EXFIL")
    return phases


def _delivery_kind(t: PITechnique) -> str:
    """direct = the attacker's own turn (untrusted=False channel);
    indirect = the directive rides attacker-controlled content."""
    return "direct" if not DELIVERY_CHANNELS[t.delivery[0]].untrusted \
        else "indirect"


def kill_chain_map(techniques: tuple | list | None = None) -> dict:
    """The static projection: which phases each technique occupies, derived
    mechanically (see _phases_for). Deterministic: registry order."""
    techs = list(TECHNIQUES if techniques is None else techniques)
    by_phase: dict[str, list] = {p: [] for p in PHASES}
    entries: dict = {}
    for t in techs:
        phases = _phases_for(t)
        for p in phases:
            by_phase[p].append(t.id)
        entries[t.id] = {
            "family": t.family,
            "name": t.name,
            "phases": phases,
            "deepest_stage": t.success_stage.value,
            "delivery": _delivery_kind(t),
            "payload_ref": t.payload_ref,
        }
    return {"phases": by_phase, "techniques": entries}


def kill_chain_plan(techniques: tuple | list | None = None,
                    capabilities: tuple[str, ...] = FIXTURE_CAPABILITIES,
                    ) -> dict:
    """The capability-conditioned kill chain: the attack-graph planner's
    reachability (kernel-backed, Python-reference identical) projected onto
    the phase model. A phase is a CHAIN BREAK when every technique that
    occupies it is capability-blocked — the point the chain cannot pass.

    Phase reachability is decided by the SPECIFIC ladder state the phase
    exercises (not the technique's overall alive/partial status):
      WEAPONIZE / DELIVER  the attempt is possible (EXPOSED reachable)
      EXECUTE              the adoption node reachable (the technique's
                           primary stage — RELAYED, or EXECUTED for the
                           direct-EXECUTED shape E3)
      PRIVILEGE            the EXECUTED node reachable (the tool invocation
                           IS the phase)
      PERSIST              the PERSISTED node reachable (survival IS the
                           phase)
      EXFIL                the claimed stage reachable (E1/E2 relay the
                           canary at RELAYED; E3 needs the EXECUTED request)
    A partially-alive technique therefore counts for its phases only up to
    the stage it can actually reach — a forbidden_tool technique that can
    relay but cannot invoke tools does NOT count for PRIVILEGE.
    """
    techs = list(TECHNIQUES if techniques is None else techniques)
    # accept technique ids ("PI.B6") or PITechnique objects — a caller
    # passing registry ids must not crash inside the planner
    techs = [BY_ID[x] if isinstance(x, str) else x for x in techs]
    plan = deployment_plan(tuple(techs), tuple(capabilities))
    mapping = kill_chain_map(techs)

    def _reach(phases: list[str], tid: str) -> tuple[list, list]:
        """Split the technique's phase list into reachable / blocked for
        THIS capability set, per the ladder-state rule in the docstring.
        planner's per-technique dead_states carry BARE stage names while
        states are full node ids ('PI.A3#EXECUTED') — compare by suffix."""
        entry = plan["techniques"][tid]
        dead = set(entry["dead_states"])
        states = entry["states"]
        stage = [s.split("#")[-1] for s in states]
        primary = stage[1] if len(stage) > 1 else ""        # adoption node
        executed = stage[-1] if stage[-1] == "EXECUTED" else ""
        persisted = next((s for s in stage if s == "PERSISTED"), "")
        reachable_by_phase = {
            "WEAPONIZE": "EXPOSED" not in dead,
            "DELIVER": "EXPOSED" not in dead,
            "EXECUTE": bool(primary) and primary not in dead,
            "PRIVILEGE": bool(executed) and executed not in dead,
            "PERSIST": bool(persisted) and persisted not in dead,
            "EXFIL": bool(primary) and primary not in dead,
        }
        ok = [p for p in phases if reachable_by_phase.get(p)]
        no = [p for p in phases if not reachable_by_phase.get(p)]
        return ok, no

    phase_alive: dict[str, list] = {p: [] for p in PHASES}
    phase_blocked: dict[str, list] = {p: [] for p in PHASES}
    for t in techs:
        phases = mapping["techniques"][t.id]["phases"]
        ok, no = _reach(phases, t.id)
        for p in ok:
            phase_alive[p].append(t.id)
        for p in no:
            phase_blocked[p].append(t.id)

    phases: dict = {}
    for p in PHASES:
        if p == "RECON":
            phases[p] = {"total": 0, "alive": [], "blocked": [],
                         "blocked_by": [],
                         "note": PHASE_ANCHORS[p]["artifact"]}
            continue
        ids = mapping["phases"][p]
        blocked = phase_blocked[p]
        blockers = sorted({plan["techniques"][i]["blocked_by"]
                           for i in blocked
                           if plan["techniques"][i]["blocked_by"]})
        phases[p] = {"total": len(ids), "alive": phase_alive[p],
                     "blocked": blocked, "blocked_by": blockers}

    # chain breaks: occupied phases where NOTHING is alive
    chain_breaks = [
        {"phase": p, "blocked_by": phases[p]["blocked_by"],
         "reason": f"all {phases[p]['total']} technique(s) occupying {p} "
                   f"are capability-blocked"}
        for p in ("WEAPONIZE", "DELIVER", "EXECUTE", "PRIVILEGE", "PERSIST",
                  "EXFIL")
        if phases[p]["total"] and not phases[p]["alive"]]

    # deepest reachable phase: the highest-rank phase with >=1 alive occupant
    reachable = [p for p in ("EXFIL", "PERSIST", "PRIVILEGE", "EXECUTE",
                             "DELIVER", "WEAPONIZE")
                 if phases[p]["total"] and phases[p]["alive"]]
    depth_phase = reachable[0] if reachable else "RECON"

    return {
        "capabilities": sorted(capabilities),
        "chain_order": PHASES,
        "phase_anchors": PHASE_ANCHORS,
        "phases": phases,
        "chain_breaks": chain_breaks,
        "reachable_depth": {"rank": PHASE_RANK[depth_phase],
                            "phase": depth_phase},
        "summary": plan["summary"],
        "techniques": mapping["techniques"],
    }


def kill_chain_audit() -> dict:
    """The CLI payload: full-registry map + fixture-conditioned plan +
    structural gaps (phases nothing occupies) + the phase anchors."""
    mapping = kill_chain_map()
    structural_gaps = [p for p in ("WEAPONIZE", "DELIVER", "EXECUTE",
                                   "PRIVILEGE", "PERSIST", "EXFIL")
                       if not mapping["phases"][p]]
    return {
        "registry": {"techniques": len(TECHNIQUES),
                     "payloads": sum(len(t.payloads) for t in TECHNIQUES)},
        "structural_gaps": structural_gaps,
        "recon": PHASE_ANCHORS["RECON"],
        **kill_chain_plan(),
    }
