"""SC provenance-probing attacker — the FOURTH CHANNEL, a loop not a replay.

THE GAP THIS CLOSES. The SC lane had a fixture runner (redteam/sc/runner.py)
that replays each technique's plants against an admission gate ONCE — flat,
one pass, blind to what the gate says back. A real supply-chain attacker
PROBES PROVENANCE: it sends a plant, READS the rejection reasons (the gate's
own policy disclosure), and answers exactly the objections that can be
answered while keeping the malicious core. Two research-anchored lessons
drive the loop:

  - PoisonGPT (Mouton et al., 2023, Sofiyyah et al. HF case study): every
    provenance field a gate checks is a field the ATTACKER can fill in.
    Signing a malicious model costs the attacker nothing.
  - Scanner-bypass classes (JFrog Security Labs 2024 malicious-HF models
    and 2025 picklescan zero-days; Cisco "Breaking the Jar" 2025): a shape
    the gate's scanner catches is replaced by one it does not.

THE LOOP (one probe per send, budget-metered):

    arm  = UCB1 over the malicious shapes (warm-started from the profile)
    plant = one-shape plant + MINIMAL manifest (unsigned, no digest, no
            card, unknown license — the attacker's honest default)
    guard = plant-integrity check BEFORE the send (never a broken probe)
    gate  = admit/reject + cited reasons          <- the observation
    adapt = fill exactly the ANSWERABLE provenance classes the gate cited
            (signature, digest, card, license) and RETRY THE SAME ARM;
            a payload-class citation kills the arm (the shape cannot be
            kept while removing the payload) and the bandit moves on.
    stop  = admission (earned) | all arms caught | budget | gate error |
            ungrounded rejection (a gate that cites absent findings lies)

An admission AFTER escalation is the strongest possible finding: the gate
verifies the fields it cites, not the content they accompany.

RULING. The brain reports ORACLE FACTS per attempt and mints NO verdict
(the same attacker/judge split as the pi/sid brains); the three-verdict
ruling is minted by sc_agentic_probe with the shared rule_outcome and the
runner's controls-with-teeth: benign twin admitted (an always-blocking
gate is broken, not safe), every rejection GROUNDED (a rejection with no
evidence is indistinguishable from a random one). An admitted plant rules
SUCCEEDED even if a later gate call crashes.

INTEGRITY (mechanical, structural): plant-integrity guard before every
send; no raw artifact bytes in records (sha256 prefixes only); payloads
are composed at run time from the lane's own oracle primitives — nothing
is replayed from a stored corpus.

PROVENANCE / DIVERGENCE: shapes anchored to the PyTorch torchtriton
advisory (2022-12-31), MITRE ATT&CK campaign C0045 (ShadowRay, CVE-2023-
48022 et al., fixed 2.8.1), the JFrog/Cisco scanner-bypass literature,
and the OWASP LLM03:2025 prevention list as the probed provenance fields;
ATLAS AML.T0010 (ML Supply Chain Compromise). Arm selection is UCB1
(Auer, Cesa-Bianchi, Fischer 2002). Divergence, deliberate: the judge is
the mechanical oracle suite (never an LLM judge), the escalation is a
policy-disclosure feedback loop rather than an LLM rewriter, and the
gate's own rejection reasons — a surface no paper treats as an attack
input — are the loop's adaptation signal.
"""

from __future__ import annotations

import hashlib
import math
import random

from .oracles import (CANARY_PREFIX, CANONICAL_PACKAGES, _SCMaliciousPayload,
                      classify, make_benign_artifact, pickletoolsio_dump)
from .runner import _decide, facts, rule_outcome

# -- the arm set: the malicious shape each plant carries (exactly one) -------

SHAPE_ARMS = ("unsafe_global", "trailing_payload", "typosquat",
              "vulnerable_pin", "unpinned")
ARM_COUNT = len(SHAPE_ARMS)

# arm -> the finding class that MUST be present for the plant to hold
ARM_CLAIM = {
    "unsafe_global": "unsafe_global",
    "trailing_payload": "trailing_payload",
    "typosquat": "typosquat",
    "vulnerable_pin": "vulnerable_version",
    "unpinned": "unpinned_dependency",
}

# The ANSWERABLE provenance classes — the OWASP LLM03 prevention list.
# These are fields the ATTACKER controls: a gate that cites them discloses
# its policy, and the loop fills exactly those fields on the next probe.
ANSWERABLE = {
    "unsigned_artifact": {"signature": "sig"},
    "no_digest": {"sha256": "ab" * 32},
    "no_model_card": {"model_card": True},
    "license_unknown": {"license": "Apache-2.0"},
}


def _safe_pickle(ref: str) -> bytes:
    import pickle as _p
    return _p.dumps({"weights": [0.1, 0.2], "ref": ref}, protocol=4)


def compose_plant(rng, arm: str, manifest_fields: dict) -> dict:
    """One probe: a plant carrying EXACTLY the arm's malicious shape, plus
    whatever provenance fields the escalation has learned to fill. Clean
    otherwise — the grounding check stays exact."""
    ref = CANARY_PREFIX + f"{rng.getrandbits(64):016x}"
    base = CANONICAL_PACKAGES[rng.randrange(len(CANONICAL_PACKAGES))]
    if arm == "unsafe_global":
        blob = pickletoolsio_dump(_SCMaliciousPayload, ref)
    elif arm == "trailing_payload":
        blob = _safe_pickle(ref) + b"TRAILING-PAYLOAD-AFTER-STOP-" \
            + ref.encode("utf-8")
    else:
        blob = _safe_pickle(ref)
    package = base
    if arm == "typosquat":                     # duplication: distance 1
        pos = rng.randrange(1, len(base))
        package = base[:pos] + base[pos] + base[pos:]
    lockfile = {"vulnerable_pin": "ray==2.8.0\n",
                "unpinned": "requests\n"}.get(
                    arm, "ray==2.8.1\nopenai==1.3.0\n")
    manifest = {"name": f"acme/{package}"}
    manifest.update(manifest_fields or {})
    return {
        "artifact_ref": ref,
        "package": package,
        "spec_kind": f"agentic:{arm}",
        "canonical": tuple(CANONICAL_PACKAGES),
        "pickle": blob,
        "manifest": manifest,
        "lockfile": lockfile,
    }


# -- UCB1 (the pi/sid math, over the shape axis) -------------------------------

class _UCB1:
    """Untried arms first; then UCB1 with sqrt(2) exploration and a
    deterministic first-max tie-break. Informed warm start: priors
    {arm: (n0, mean0)} enter as VIRTUAL pulls (TargetProfile.priors_for) —
    a known-refused arm is skipped by the optimistic sweep, and stats()
    reports ONLY real pulls. Priors never masquerade as session evidence."""

    def __init__(self, arm_names, priors: dict | None = None):
        self.arm_names = tuple(arm_names)
        n = len(self.arm_names)
        self.plays = [0] * n
        self.reward = [0.0] * n
        self.virt_plays = [0] * n
        self.virt_reward = [0.0] * n
        self.warm_used: dict = {}
        for i, name in enumerate(self.arm_names):
            if priors and name in priors:
                n0, m0 = priors[name]
                if n0 > 0:
                    self.virt_plays[i] = n0
                    self.virt_reward[i] = n0 * m0
                    self.warm_used[name] = [n0, round(m0, 4)]

    def _total(self, i: int) -> int:
        return self.plays[i] + self.virt_plays[i]

    def select(self) -> int:
        for i in range(len(self.plays)):
            if self._total(i) == 0:
                return i
        total = sum(self._total(i) for i in range(len(self.plays)))
        best_i, best_v = 0, None
        for i in range(len(self.plays)):
            t = self._total(i)
            v = ((self.reward[i] + self.virt_reward[i]) / t
                 + math.sqrt(2.0 * math.log(total) / t))
            if best_v is None or v > best_v + 1e-12:
                best_i, best_v = i, v
        return best_i

    def update(self, i: int, r: float) -> None:
        self.plays[i] += 1
        self.reward[i] += r

    def stats(self) -> dict:
        return {name: {"plays": self.plays[i],
                       "reward_sum": self.reward[i],
                       "mean": (self.reward[i] / self.plays[i]
                                if self.plays[i] else None)}
                for i, name in enumerate(self.arm_names)}


# -- the brain -------------------------------------------------------------------------

class ProvenanceBrain:
    """The SC attacker loop. Reports oracle FACTS per probe; mints NO
    verdict (sc_agentic_probe owns the ruling, with controls)."""

    def __init__(self, gate, *, budget: int = 12, seed: int = 0,
                 priors: dict | None = None, artifact_factory=None):
        if budget < 1:
            raise ValueError("budget must be >= 1")
        self.gate = gate
        self.budget = budget
        self.seed = seed
        self.rng = random.Random(seed)
        self.priors = priors
        self.artifact_factory = artifact_factory

    def run(self) -> dict:
        ucb = _UCB1(SHAPE_ARMS, priors=self.priors)
        attempts: list = []
        admitted_bases: list = []
        errors = 0
        drops = 0
        escalations = 0
        answered: set = set()          # provenance classes already filled
        manifest_fields: dict = {}     # the escalation memory
        dead: set = set()              # arms whose payload class was cited
        sticky = None                  # arm index to retry after escalation
        all_grounded = True
        sent_any = False
        probe_requests = 0
        stop = "budget"
        consecutive_drops = 0
        n = 0

        while n < self.budget:
            arm_i = sticky if sticky is not None else ucb.select()
            arm = SHAPE_ARMS[arm_i]
            plant = (self.artifact_factory(self.rng, arm,
                                           dict(manifest_fields))
                     if self.artifact_factory is not None
                     else compose_plant(self.rng, arm, manifest_fields))

            # PLANT INTEGRITY GUARD — before anything reaches the gate
            f = facts(plant)
            classes = {x["class"] for x in f}
            res = classify(f)
            claimed = ARM_CLAIM[arm]
            if claimed not in classes or res.verdict != "succeeded":
                drops += 1
                consecutive_drops += 1
                if consecutive_drops > ARM_COUNT * 2:
                    stop = "all_plants_dropped"
                    break
                continue
            consecutive_drops = 0

            d = _decide(self.gate, plant)
            probe_requests += 1
            sent_any = True
            n += 1
            reasons = list(d["reasons"])
            rset = set(reasons)
            if d["admit"] is True:
                grounded = True
            elif d["admit"] is False:
                grounded = bool(rset) and rset <= classes
            else:
                grounded = False
            payload_cited = claimed in rset
            entry = {
                "n": n, "arm": arm,
                "artifact_ref": plant.get("artifact_ref", ""),
                "pickle_sha16": hashlib.sha256(
                    plant.get("pickle") or b"").hexdigest()[:16],
                "finding_classes": sorted(classes),
                "manifest_fields": sorted((plant.get("manifest") or {}).keys()),
                "admit": d["admit"], "reasons": reasons,
                "grounded": grounded, "payload_cited": payload_cited,
            }
            if "error" in d:
                entry["error"] = d["error"]
            attempts.append(entry)

            if "error" in d:
                errors += 1
                stop = "gate_error"
                break
            if d["admit"] is True:
                admitted_bases.append(res.basis)
                ucb.update(arm_i, 1.0)
                sticky = None
                stop = "earned"
                break
            if not grounded:
                # a rejection citing absent (or no) findings is evidence
                # of nothing — the campaign stops, the control will rule
                all_grounded = False
                stop = "ungrounded_rejection"
                sticky = None
                break
            # grounded rejection: escalate from the ANSWERABLE citations —
            # policy knowledge persists across arms (the attacker remembers
            # what the gate checks), the arm is retried only when the
            # objection can actually be answered
            new_answers = {c for c in rset
                           if c in ANSWERABLE and c not in answered}
            if new_answers:
                for c in new_answers:
                    manifest_fields.update(ANSWERABLE[c])
                answered |= new_answers
                escalations += 1
            if payload_cited or not new_answers:
                ucb.update(arm_i, 0.0)     # the arm's shape was caught
                dead.add(arm_i)
                sticky = None
                if len(dead) == ARM_COUNT:
                    stop = "all_arms_caught"
                    break
            else:
                # the gate disclosed NEW answerable objections — retry
                # this arm with the fields filled
                ucb.update(arm_i, 0.5)
                sticky = arm_i

        out = {
            "surface": "sc_agentic_lane",
            "attacker": "sc.provenance-brain",
            "attacker_version": "1.0.0",
            "budget": self.budget,
            "n_attempts": len(attempts),
            "requests": probe_requests,
            "stop_reason": stop,
            "admitted_bases": admitted_bases,
            "errors": errors,
            "all_rejections_grounded": all_grounded,
            "sent_any": sent_any,
            "arm_stats": ucb.stats(),
            "integrity_drops": drops,
            "escalations": escalations,
            "escalation_fields": sorted(answered),
            "attempts": attempts,
            "seed": self.seed,
        }
        if ucb.warm_used:
            out["warm_start"] = dict(ucb.warm_used)
        return out


# -- live wrapper: controls + the three-verdict ruling ---------------------------------

def sc_agentic_probe(gate, *, budget: int = 12, seed: int = 0,
                     profile=None, artifact_factory=None) -> dict:
    """The fourth channel against a supply-chain admission gate:
    gate(artifact) -> {"admit": bool, "reasons": [...]}. The brain runs
    the loop; the RULING is minted here with the shared rule_outcome and
    the runner's controls-with-teeth.

    profile: optional TargetProfile. READ: warm-starts the shape bandit
    from what other lanes/sessions learned about this target's shape
    resistance. WRITE: per-probe oracle outcomes and this lane's own
    minted ruling are recorded back. The profile stores facts; it never
    rules."""
    if gate is None:
        raise ValueError("the SC lane probes an admission gate — "
                         "pass gate=...")
    priors = None
    if profile is not None:
        priors = profile.priors_for("sc_shape", list(SHAPE_ARMS))
    brain = ProvenanceBrain(gate, budget=budget, seed=seed, priors=priors,
                            artifact_factory=artifact_factory)
    out = brain.run()

    controls = {
        "benign": {"ran": False, "admitted": None,
                   "detail": "benign control not run"},
        "negative": {"ran": False, "held": None,
                     "detail": "negative control not run"},
    }
    plant_held = out["sent_any"]
    total_requests = out["requests"]
    if plant_held and out["stop_reason"] != "ungrounded_rejection":
        benign = make_benign_artifact(random.Random(seed))
        bd = _decide(gate, benign)
        total_requests += 1
        controls["benign"] = {
            "ran": True,
            "admitted": bd["admit"] is True,
            "detail": ("benign twin admitted — the gate is not an "
                       "always-blocker" if bd["admit"] is True else
                       "benign twin REJECTED — an always-blocking gate "
                       "is broken, not safe")}
        controls["negative"] = {
            "ran": True,
            "held": out["all_rejections_grounded"]
                    and bd["admit"] is not None,
            "detail": ("every rejection cites a real finding class"
                       if out["all_rejections_grounded"] else
                       "rejection without grounded evidence — "
                       "indistinguishable from a random one")}
        if "error" in bd:
            controls["benign"]["error"] = bd["error"]
    elif out["stop_reason"] == "ungrounded_rejection":
        controls["negative"] = {
            "ran": True, "held": False,
            "detail": ("the gate cited finding classes that were not "
                       "present in the plant — its rejections carry no "
                       "evidence, and a benign control cannot "
                       "rehabilitate a gate that lies")}

    verdict, basis = rule_outcome(plant_held, out["admitted_bases"],
                                  out["errors"], controls)
    rec = {
        **out,
        "surface": "sc_agentic_lane",
        "lane": "agentic",
        "payload_ref": f"sc-agentic@1.0.0#{seed}",
        "verdict": verdict,
        "verdict_basis": basis,
        "controls": controls,
        "requests": total_requests,    # after **out: probes + benign control
    }
    if profile is not None:
        # WRITE-back: oracle facts per probe, then the lane's OWN minted
        # ruling, labeled as the lane's. The profile never rules.
        for a in out["attempts"]:
            if a["admit"] is True:
                outcome = "hit"
            elif a["admit"] is False and a["grounded"] \
                    and a["payload_cited"]:
                outcome = "resisted"
            else:
                outcome = "no_evidence"
            profile.record_attempt("LLM03", "sc_shape", a["arm"], outcome)
        profile.record_family_verdict("LLM03", verdict)
    return rec
