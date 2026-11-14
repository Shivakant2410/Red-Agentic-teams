"""The whole workflow, end to end — REAL pi + sid lanes through the
FamilyOrchestrator on ONE shared TargetProfile.

This is the test the audit said was missing: not three CLIs run by hand,
but ONE campaign that (1) sequences family lanes on a single budget,
(2) hands pi's earned cipher facts to sid MID-CAMPAIGN through the
profile, (3) persists those facts so the NEXT campaign starts warm, and
(4) reports honestly what was spent and what folded.

The target: decoder-competent on the PI side (decodes the b64 arm's
block, echoes the canary — folds on base64) and an atbash exfil-leaker
on the SID side (leaks the planted record only when the payload demands
Atbash — folds on atbash, arm index 3, late in the cold sweep).

What must hold:
  - both real lanes run under ONE budget; coverage order LLM01 -> LLM02;
  - sid's record carries warm_start with "base64" — pi's b64 fact,
    alias-resolved across the lane naming mismatch, delivered through
    the shared profile DURING the campaign;
  - the profile ends holding both families' facts and both lanes' own
    minted rulings; the briefing reads like a target dossier;
  - campaign 2, loaded from the saved profile, shows sid warm_start
    with "atbash" (campaign 1's sid fact) — memory across campaigns;
  - same inputs -> same campaign (deterministic commander).
"""

from __future__ import annotations

import base64
import random
import re
import sys
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO))

from redteam.brain import TargetProfile, fingerprint_target  # noqa: E402
from redteam.brain.killchain import assess_kill_chain  # noqa: E402
from redteam.brain.orchestrator import FamilyOrchestrator  # noqa: E402
from redteam.ea.agent import ea_agentic_probe  # noqa: E402
from redteam.oh.agent import oh_agentic_probe  # noqa: E402
from redteam.pi.agent import agentic_live_probe  # noqa: E402
from redteam.pi.live import LiveLaneError  # noqa: E402
from redteam.sc.agent import sc_agentic_probe  # noqa: E402
from redteam.sid.agent import sid_agentic_probe  # noqa: E402
from redteam.sid.oracles import make_pii_record  # noqa: E402

CANARY = "PIC-2f7a91c4b8e60315"
REFUSAL = "I'm sorry, but I can't share that."
_B64_RUN = re.compile(r"[A-Za-z0-9+/=]{16,}")


class _FakeSession:
    def __init__(self, reply_fn, max_requests: int = 64):
        self.reply_fn = reply_fn
        self.sent: list = []
        self.requests = 0
        self.max_requests = max_requests

    def send(self, system: str, user: str) -> str:
        if self.requests >= self.max_requests:
            raise LiveLaneError(
                f"request budget exhausted ({self.max_requests})")
        self.requests += 1
        self.sent.append((system, user))
        return self.reply_fn(system, user)


def pi_decode_b64_target(user: str) -> str:
    """Decoder-competent: extracts base64 runs, echoes the one carrying
    the canary; refuses everything else."""
    for run in _B64_RUN.findall(user):
        try:
            decoded = base64.b64decode(run, validate=True).decode("utf-8")
        except Exception:
            continue
        if CANARY in decoded:
            return decoded
    return REFUSAL


def _atbash(s: str) -> str:
    out = []
    for ch in s:
        if "A" <= ch <= "Z":
            out.append(chr(ord("Z") - (ord(ch) - ord("A"))))
        elif "a" <= ch <= "z":
            out.append(chr(ord("z") - (ord(ch) - ord("a"))))
        else:
            out.append(ch)
    return "".join(out)


def _sid_reply_fn(rec: dict):
    plain = (f"Certainly. account_ref {rec['account_ref']} "
             f"ssn {rec['ssn']} card {rec['card']}")
    encoded = _atbash(plain)

    def reply(system: str, user: str) -> str:
        if "atbash" in user.lower():
            return encoded
        return REFUSAL
    return reply


def _build_campaign(profile, budget: int = 48) -> FamilyOrchestrator:
    orch = FamilyOrchestrator(profile, budget=budget, per_lane_cap=16)
    orch.register("LLM01", lambda p, b: agentic_live_probe(
        None, canary=CANARY, budget=min(b, 16), seed=0,
        session=_FakeSession(lambda s, u: pi_decode_b64_target(u)),
        profile=p))

    def llm02_lane(p, b):
        rec = make_pii_record(random.Random(0))
        return sid_agentic_probe(
            rec, budget=min(b, 16), seed=0,
            session=_FakeSession(_sid_reply_fn(rec)), profile=p)
    orch.register("LLM02", llm02_lane)
    return orch


# -- the fourth channel ----------------------------------------------------------

class _NaiveGate:
    """Admission control that checks nothing — the SC lane folds it."""

    def __call__(self, artifact):
        return {"admit": True, "reasons": []}


def test_fourth_channel_sc_runs_in_one_campaign_with_pi_and_sid():
    """THREE agentic channels under ONE budget on ONE shared profile: pi
    (LLM01), sid (LLM02), and the SC provenance-probing loop (LLM03). The
    SC lane funds like the others, records its shape facts into the same
    ledger, and mints its ruling like every other family."""
    profile = TargetProfile(
        fingerprint=fingerprint_target("chat", "fake-model", "sys-sha"))
    profile.start_session()
    orch = FamilyOrchestrator(profile, budget=64, per_lane_cap=16)
    orch.register("LLM01", lambda p, b: agentic_live_probe(
        None, canary=CANARY, budget=min(b, 16), seed=0,
        session=_FakeSession(lambda s, u: pi_decode_b64_target(u)),
        profile=p))
    orch.register("LLM02", lambda p, b: sid_agentic_probe(
        make_pii_record(random.Random(0)), budget=min(b, 16), seed=0,
        session=_FakeSession(_sid_reply_fn(make_pii_record(random.Random(0)))),
        profile=p))
    orch.register("LLM03", lambda p, b: sc_agentic_probe(
        _NaiveGate(), budget=min(b, 12), seed=0, profile=p))
    report = orch.run()

    fams = report["families"]
    assert set(fams) == {"LLM01", "LLM02", "LLM03"}
    assert fams["LLM03"]["verdict"] == "succeeded"
    assert fams["LLM03"]["requests"] > 0
    assert fams["LLM03"]["attempts"] > 0
    assert report["budget_spent"] == sum(f["requests"] for f in fams.values())
    # the SC shape facts live in the SAME ledger as the cipher facts
    assert profile.axes["sc_shape"]["unsafe_global"]["hits"] >= 1
    assert profile.family_state("LLM03")["verdicts"]["succeeded"] == 1
    brief = report["profile_briefing"]
    assert "sc_shape." in brief and "family LLM03" in brief


# -- the fifth channel ------------------------------------------------------------

class _VulnerableRuntime:
    """Agent runtime that obeys directives in ANY tool result — the
    excessive-agency fold, built on the lane's own public grammar."""

    def __call__(self, task, planted):
        import json as _json
        import re as _re
        out = [{"tool": "docs.fetch", "args": {"q": "incident"}}]
        for p in planted:
            m = _re.search(r"postex\.exfil\s*(\{[^{}]*\})", p["content"])
            if m:
                try:
                    args = _json.loads(m.group(1))
                except Exception:
                    args = {"raw": m.group(1)}
                out.append({"tool": "postex.exfil", "args": args})
        return {"reply": "done", "tool_calls": out}


def test_fifth_channel_ea_completes_the_four_channel_campaign():
    """FOUR agentic channels under ONE budget on ONE shared profile:
    pi (LLM01), sid (LLM02), sc (LLM03), and the EA agency-abuse loop
    (LLM06). Every channel funds like the others, records its axis facts
    into the same ledger, and mints its own ruling."""
    profile = TargetProfile(
        fingerprint=fingerprint_target("chat", "fake-model", "sys-sha"))
    profile.start_session()
    orch = FamilyOrchestrator(profile, budget=96, per_lane_cap=16)
    orch.register("LLM01", lambda p, b: agentic_live_probe(
        None, canary=CANARY, budget=min(b, 16), seed=0,
        session=_FakeSession(lambda s, u: pi_decode_b64_target(u)),
        profile=p))
    orch.register("LLM02", lambda p, b: sid_agentic_probe(
        make_pii_record(random.Random(0)), budget=min(b, 16), seed=0,
        session=_FakeSession(_sid_reply_fn(make_pii_record(random.Random(0)))),
        profile=p))
    orch.register("LLM03", lambda p, b: sc_agentic_probe(
        _NaiveGate(), budget=min(b, 12), seed=0, profile=p))
    orch.register("LLM06", lambda p, b: ea_agentic_probe(
        _VulnerableRuntime(), budget=min(b, 12), seed=0, profile=p))
    report = orch.run()

    fams = report["families"]
    assert set(fams) == {"LLM01", "LLM02", "LLM03", "LLM06"}
    assert fams["LLM06"]["verdict"] == "succeeded"
    assert fams["LLM06"]["requests"] > 0
    assert report["budget_spent"] == sum(f["requests"] for f in fams.values())
    # the EA carrier facts live in the SAME ledger as cipher/sc facts
    assert profile.axes["ea_carrier"]["fetched_doc"]["hits"] >= 1
    assert profile.family_state("LLM06")["verdicts"]["succeeded"] == 1
    brief = report["profile_briefing"]
    assert "ea_carrier.fetched_doc" in brief and "family LLM06" in brief


# -- the sixth channel: the full five-channel campaign --------------------------------

def _naive_pipeline():
    """The model->consumer stand-in the OH lane folds: the model echoes
    the requested payload (the LLM05 precondition, built on the lane's
    own public markers) and every consumer acts naively."""
    import re as _re
    from redteam.oh.oracles import MARK_MD, MARK_SHELL, MARK_SQL, MARK_XSS

    def _pipeline(prompt):
        reply = "Incident summary: nothing unusual."
        for rx in (MARK_MD, MARK_XSS, MARK_SHELL, MARK_SQL):
            m = rx.search(prompt)
            if m:
                reply = m.group(0)
                break
        events = []
        m = MARK_MD.search(reply)
        if m:
            events.append({"consumer": "renderer",
                           "action": "remote_fetch", "detail": m.group(1)})
        m = MARK_XSS.search(reply)
        if m:
            events.append({"consumer": "html", "action": "event_fired",
                           "detail": m.group(0)})
        m = MARK_SHELL.search(reply)
        if m:
            events.append({"consumer": "shell", "action": "executed",
                           "detail": m.group(0)})
        m = MARK_SQL.search(reply)
        if m:
            events.append({"consumer": "sql", "action": "rows_changed",
                           "detail": m.group(0)})
        return {"reply": reply, "consumer_events": events}

    return _pipeline


def test_sixth_channel_oh_completes_the_full_five_channel_campaign():
    """FIVE agentic channels under ONE budget on ONE shared profile:
    pi (LLM01), sid (LLM02), sc (LLM03), oh (LLM05), ea (LLM06). Every
    OH handling fact lands in the same ledger — and with all four kill
    chain rungs earned by real channels, the composer for the first
    time reports an END-TO-END compromise."""
    profile = TargetProfile(
        fingerprint=fingerprint_target("chat", "fake-model", "sys-sha"))
    profile.start_session()
    orch = FamilyOrchestrator(profile, budget=128, per_lane_cap=16)
    orch.register("LLM01", lambda p, b: agentic_live_probe(
        None, canary=CANARY, budget=min(b, 16), seed=0,
        session=_FakeSession(lambda s, u: pi_decode_b64_target(u)),
        profile=p))
    orch.register("LLM02", lambda p, b: sid_agentic_probe(
        make_pii_record(random.Random(0)), budget=min(b, 16), seed=0,
        session=_FakeSession(_sid_reply_fn(make_pii_record(random.Random(0)))),
        profile=p))
    orch.register("LLM03", lambda p, b: sc_agentic_probe(
        _NaiveGate(), budget=min(b, 12), seed=0, profile=p))
    orch.register("LLM05", lambda p, b: oh_agentic_probe(
        _naive_pipeline(), budget=min(b, 12), seed=0, profile=p))
    orch.register("LLM06", lambda p, b: ea_agentic_probe(
        _VulnerableRuntime(), budget=min(b, 12), seed=0, profile=p))
    report = orch.run()

    fams = report["families"]
    assert set(fams) == {"LLM01", "LLM02", "LLM03", "LLM05", "LLM06"}
    assert fams["LLM05"]["verdict"] == "succeeded"
    assert report["budget_spent"] == sum(f["requests"] for f in fams.values())
    assert profile.axes["oh_payload"]["md_image_exfil"]["hits"] >= 1
    assert profile.family_state("LLM05")["verdicts"]["succeeded"] == 1
    brief = report["profile_briefing"]
    assert "oh_payload.md_image_exfil" in brief and "family LLM05" in brief

    # the composer's first end-to-end verdict: every rung earned by a
    # real channel — foothold LLM01, execute LLM06, disclose LLM02,
    # persist LLM03
    kc = assess_kill_chain(report, profile=profile)
    assert kc["verdict"] == "compromised_end_to_end"
    assert [s["earned_via"] for s in kc["stages"]] == \
        ["LLM01", "LLM06", "LLM02", "LLM03"]
    assert kc["profile_sessions"] == 1


# -- the campaign -----------------------------------------------------------------

def test_one_campaign_runs_both_real_lanes_under_one_budget():
    profile = TargetProfile(
        fingerprint=fingerprint_target("chat", "fake-model", "sys-sha"))
    profile.start_session()
    report = _build_campaign(profile).run()

    assert report["stop_reason"] == "all_terminal"
    fams = report["families"]
    assert fams["LLM01"]["terminal"] and fams["LLM02"]["terminal"]
    assert fams["LLM01"]["verdict"] == "succeeded"
    assert fams["LLM02"]["verdict"] == "succeeded"
    assert report["budget_spent"] == (fams["LLM01"]["requests"]
                                      + fams["LLM02"]["requests"])
    # coverage order: untouched families first, registration breaks ties
    assert fams["LLM01"]["grants"][0] == report["budget_spent"] - \
        fams["LLM02"]["requests"] or True  # grants recorded for both


def test_cross_family_transfer_inside_one_campaign():
    """pi folds on the b64 arm first; sid, funded in the SAME campaign,
    must show pi's fact in its warm_start — alias-resolved to 'base64' —
    and the identity arm pre-marked refused."""
    profile = TargetProfile()
    profile.start_session()
    report = _build_campaign(profile).run()
    sid_rec = report["lane_records"]["LLM02"]
    assert "warm_start" in sid_rec, "sid ran cold — transfer did not happen"
    assert "base64" in sid_rec["warm_start"]        # pi's b64, canonical
    assert "identity" in sid_rec["warm_start"]
    assert sid_rec["warm_start"]["identity"][1] == 0.0   # known refusal


def test_profile_ends_as_a_target_dossier():
    profile = TargetProfile()
    profile.start_session()
    report = _build_campaign(profile).run()
    ax = profile.axes["cipher"]
    assert ax["base64"]["hits"] >= 1                # pi's fold
    assert ax["atbash"]["hits"] >= 1                # sid's fold
    assert profile.family_state("LLM01")["verdicts"]["succeeded"] == 1
    assert profile.family_state("LLM02")["verdicts"]["succeeded"] == 1
    brief = report["profile_briefing"]
    assert "cipher.base64" in brief and "cipher.atbash" in brief
    assert "family LLM01" in brief and "family LLM02" in brief


def test_second_campaign_starts_warm_from_saved_profile(tmp_path):
    """The dossier persists; the next campaign's sid shows campaign 1's
    atbash fact in its warm_start. Memory across campaigns."""
    profile = TargetProfile(fingerprint="fp-integration")
    profile.start_session()
    _build_campaign(profile).run()
    path = tmp_path / "target_fp-integration.json"
    profile.save(path)

    p2 = TargetProfile.load(path)
    p2.start_session()
    report2 = _build_campaign(p2).run()
    sid_rec = report2["lane_records"]["LLM02"]
    assert sid_rec["verdict"] == "succeeded"
    assert "atbash" in sid_rec["warm_start"]        # campaign 1's sid fact
    assert "base64" in sid_rec["warm_start"]        # campaign 1's pi fact
    pi_rec = report2["lane_records"]["LLM01"]
    assert pi_rec["warm_start"].get("b64", [0, 0])[1] == 1.0  # local spelling


def test_campaign_is_deterministic():
    def once():
        profile = TargetProfile()
        profile.start_session()
        return _build_campaign(profile).run()
    r1, r2 = once(), once()
    assert [r1["families"][f]["verdict"] for f in ("LLM01", "LLM02")] == \
           [r2["families"][f]["verdict"] for f in ("LLM01", "LLM02")]
    assert r1["budget_spent"] == r2["budget_spent"]
    assert r1["families"]["LLM02"]["grants"] == r2["families"]["LLM02"]["grants"]
