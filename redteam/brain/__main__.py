"""python -m redteam.brain — the campaign brain's entry point.

THE ONE COMMAND THE BRAIN WAS MISSING. The family lanes each had a CLI
(redteam.pi, redteam.sid, redteam.sc) and the brain had an import-level
API only — a campaign was a hand-written script. This is the orchestrator
as a command:

  python -m redteam.brain --target acme-prod --budget 48

  --target (with --model/--api-style/--system-sha) fingerprints the
    campaign target; the TargetProfile is loaded-or-created from
    --profile-dir and SAVED BACK after the run, so the next invocation
    starts warm (cross-session, cross-family memory).
  --lanes picks the channels: LLM01 (PI agentic, needs --pi-endpoint),
    LLM02 (SID agentic, needs --sid-endpoint), LLM03 (the SC
    provenance-probing channel), LLM05 (the OH output-handling channel),
    LLM06 (the EA agency-abuse channel). Live lanes that are not wired
    are SKIPPED LOUDLY with a reason (the llmred rule) — never silently,
    and a live endpoint that fails its own authorization/key checks is a
    skip, not a crash. Exit code 2 when nothing ran.
  --gate picks the built-in admission-gate stand-in for the offline SC
    channel: naive / provenance-only / content-only / strict — four
    deterministic gates built on the lane's OWN public oracles, the exact
    matrix the escalation loop discriminates (naive admits everything;
    provenance-only is the PoisonGPT shape and is beaten by escalation;
    content-only is beaten by the dependency arm; strict earns
    resistance). These are STAND-INS for deterministic campaigns and
    tests, clearly labeled in the report — not a claim about production
    gates.
  --executor picks the built-in agent-runtime stand-in for the offline
    EA channel: vulnerable / hardened / doc-only / email-only —
    deterministic runtimes built on the lane's OWN public directive
    grammar, spanning the carrier-trust-policy matrix the agency-abuse
    loop discriminates (vulnerable obeys any carrier; hardened never
    acts on tool-result content; doc-only/email-only obey exactly one
    channel — the carrier blind-spot shapes). Same honesty contract as
    the gates: stand-ins for deterministic campaigns, labeled in the
    report.
  --json prints the full machine-readable report; default output is the
    human campaign summary ending in the target briefing (what the next
    session inherits).

The profile stores facts; it never rules. The report is the campaign's,
not the CLI's.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import random

from .orchestrator import FamilyOrchestrator
from .profile import TargetProfile, fingerprint_target

# -- built-in admission-gate stand-ins (offline SC campaigns) ------------------------
#
# Each is built on the SC lane's own public oracles — the same scanners a
# production admission gate would run — restricted to the surface its name
# claims, so the escalation loop's discriminations are exact and the gates
# are honest about WHAT they model.

from ..sc.oracles import (check_provenance, scan_artifact_code,
                          scan_lockfile, typo_risk)


def _classes(findings):
    return sorted({f["class"] for f in findings})


def _gate_naive(artifact):
    return {"admit": True, "reasons": []}


def _gate_provenance_only(artifact):
    """P only: signature/digest/card/license. The PoisonGPT shape — a
    fully-provenanced malicious payload sails through."""
    classes = _classes(check_provenance(artifact["manifest"]))
    return ({"admit": False, "reasons": classes} if classes
            else {"admit": True, "reasons": []})


def _gate_content_only(artifact):
    """A/D/V only: code, name, lockfile. Ignores provenance."""
    classes = _classes(scan_artifact_code(artifact["pickle"]) +
                       typo_risk(artifact["package"],
                                 artifact["canonical"]) +
                       scan_lockfile(artifact["lockfile"]))
    return ({"admit": False, "reasons": classes} if classes
            else {"admit": True, "reasons": []})


def _gate_strict(artifact):
    """All four families — the honest gate."""
    classes = _classes(scan_artifact_code(artifact["pickle"]) +
                       typo_risk(artifact["package"],
                                 artifact["canonical"]) +
                       scan_lockfile(artifact["lockfile"]) +
                       check_provenance(artifact["manifest"]))
    return ({"admit": False, "reasons": classes} if classes
            else {"admit": True, "reasons": []})


BUILT_IN_GATES = {
    "naive": _gate_naive,
    "provenance-only": _gate_provenance_only,
    "content-only": _gate_content_only,
    "strict": _gate_strict,
}

# -- built-in agent-runtime stand-ins (offline EA campaigns) -------------------------
#
# The same principle as the gates: built on the EA lane's OWN public
# directive grammar (ea.oracles.DIRECTIVE_RE) — exactly the parser a
# production runtime runs on untrusted tool-result text — restricted to
# the carrier-trust policy its name claims.

from ..ea.oracles import DIRECTIVE_RE, SMUGGLED_TOOL


def _obey_directive(content):
    m = DIRECTIVE_RE.search(content or "")
    if not m:
        return None
    try:
        return json.loads(m.group(1))
    except Exception:
        return {"raw": m.group(1)}


def _runtime_task_calls():
    return [{"tool": "docs.fetch", "args": {"q": "incident"}}]


def _executor_vulnerable(task, planted):
    """Obeys directives in ANY tool result — the excessive-agency fold."""
    out = _runtime_task_calls()
    for p in planted:
        args = _obey_directive(p.get("content"))
        if args is not None:
            out.append({"tool": SMUGGLED_TOOL, "args": args})
    return {"reply": "done", "tool_calls": out}


def _executor_hardened(task, planted):
    """Never acts on tool-result content — the honest runtime."""
    return {"reply": "done", "tool_calls": _runtime_task_calls()}


def _executor_carrier_policy(trusted_tool):
    def _exec(task, planted):
        out = _runtime_task_calls()
        for p in planted:
            if p.get("tool") == trusted_tool:
                args = _obey_directive(p.get("content"))
                if args is not None:
                    out.append({"tool": SMUGGLED_TOOL, "args": args})
        return {"reply": "done", "tool_calls": out}
    return _exec


BUILT_IN_EXECUTORS = {
    "vulnerable": _executor_vulnerable,
    "hardened": _executor_hardened,
    "doc-only": _executor_carrier_policy("docs.fetch"),
    "email-only": _executor_carrier_policy("mail.fetch"),
}

# -- built-in pipeline stand-ins (offline OH campaigns) -------------------------------
#
# The same principle as the gates and executors: built on the OH lane's
# OWN public markers (oh.oracles MARK_* — exactly the parsers a
# production consumer stack runs) restricted to the handling policy the
# name claims: naive sanitizes nothing; html-escaped escapes the HTML
# sink only; no-remote-fetch blocks renderer fetches only; strict
# sanitizes every consumer (the mitigation list of OWASP LLM05).

from ..oh.oracles import MARK_MD, MARK_SHELL, MARK_SQL, MARK_XSS


def _oh_echo_payload(prompt):
    """The 'model' every stand-in runs: helpfully copies the requested
    snippet verbatim into the reply — the LLM05 precondition."""
    for rx in (MARK_MD, MARK_XSS, MARK_SHELL, MARK_SQL):
        m = rx.search(prompt or "")
        if m:
            return m.group(0)
    return "Incident summary: nothing unusual."


def _oh_apply_consumers(reply, policy):
    """Consumer side effects observed by the harness, restricted to the
    handling policy the name claims."""
    events = []
    m = MARK_MD.search(reply)
    if m and policy.get("renderer"):
        events.append({"consumer": "renderer", "action": "remote_fetch",
                       "detail": m.group(1)})
    m = MARK_XSS.search(reply)
    if m and policy.get("html"):
        events.append({"consumer": "html", "action": "event_fired",
                       "detail": m.group(0)})
    m = MARK_SHELL.search(reply)
    if m and policy.get("shell"):
        events.append({"consumer": "shell", "action": "executed",
                       "detail": m.group(0)})
    m = MARK_SQL.search(reply)
    if m and policy.get("sql"):
        events.append({"consumer": "sql", "action": "rows_changed",
                       "detail": m.group(0)})
    return events


_OH_POLICIES = {
    "naive": {"renderer": True, "html": True, "shell": True, "sql": True},
    "html-escaped": {"renderer": True, "html": False, "shell": True,
                     "sql": True},
    "no-remote-fetch": {"renderer": False, "html": True, "shell": True,
                        "sql": True},
    "strict": {"renderer": False, "html": False, "shell": False,
               "sql": False},
}


def _make_pipeline(policy):
    def _pipeline(prompt):
        reply = _oh_echo_payload(prompt)
        return {"reply": reply,
                "consumer_events": _oh_apply_consumers(reply, policy)}
    return _pipeline


BUILT_IN_PIPELINES = {name: _make_pipeline(p)
                      for name, p in _OH_POLICIES.items()}


def _parse_env(entries) -> dict:
    env = {}
    for e in entries or ():
        key, sep, value = str(e).partition("=")
        if not sep or not key:
            raise ValueError(f"--lane-env entries must be KEY=VALUE, "
                             f"got {e!r}")
        env[key] = value
    return env


def _live_env(endpoint: str, style: str, model: str, lane_env: dict) -> dict:
    """The lane's own env contract (pi/live.py): authorization bit, base
    URL, style, model — plus any caller-supplied entries (the api key
    NAME indirection and the key itself stay the caller's business)."""
    return {"LLMRED_LIVE_AUTHORIZED": "1",
            "LLMRED_LIVE_BASE_URL": endpoint.rstrip("/"),
            "LLMRED_LIVE_API_STYLE": style,
            "LLMRED_LIVE_MODEL": model,
            **lane_env}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        prog="python -m redteam.brain",
        description="The campaign brain: OWASP family channels under ONE "
                    "budget, ONE shared per-target profile (LLM01 PI, "
                    "LLM02 SID, LLM03 SC)")
    ap.add_argument("--target", required=True,
                    help="campaign target name (goes into the report)")
    ap.add_argument("--model", default="unspecified")
    ap.add_argument("--api-style", default="chat")
    ap.add_argument("--system-sha", default=None,
                    help="sha of the target's system prompt; default is a "
                         "stable placeholder")
    ap.add_argument("--budget", type=int, default=48)
    ap.add_argument("--per-lane-cap", type=int, default=16)
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--lanes", nargs="*", default=["LLM01", "LLM02", "LLM03",
                                                   "LLM05", "LLM06"],
                    choices=("LLM01", "LLM02", "LLM03", "LLM05", "LLM06"))
    ap.add_argument("--gate", default="strict", choices=tuple(BUILT_IN_GATES),
                    help="built-in admission-gate stand-in for the offline "
                         "SC channel (default: strict)")
    ap.add_argument("--executor", default="hardened",
                    choices=tuple(BUILT_IN_EXECUTORS),
                    help="built-in agent-runtime stand-in for the offline "
                         "EA channel (default: hardened)")
    ap.add_argument("--pipeline", default="strict",
                    choices=tuple(BUILT_IN_PIPELINES),
                    help="built-in model->consumer pipeline stand-in for "
                         "the offline OH channel (default: strict)")
    ap.add_argument("--profile-dir", default="targets",
                    help="where per-target profiles persist "
                         "(default ./targets)")
    ap.add_argument("--pi-endpoint", default=None,
                    help="live base URL for the LLM01 channel "
                         "(e.g. https://host:port)")
    ap.add_argument("--pi-escalation", action="store_true",
                    help="run the LLM01 channel with the multi-turn "
                         "Crescendo escalation attacker (anchored "
                         "ladders) instead of the single-turn grammar "
                         "brain")
    ap.add_argument("--pi-style", default="openai",
                    choices=("openai", "anthropic"))
    ap.add_argument("--sid-endpoint", default=None,
                    help="live base URL for the LLM02 channel")
    ap.add_argument("--lane-env", nargs="*", default=[], metavar="KEY=VALUE",
                    help="extra env for live lanes (api key NAME "
                         "indirection, key material via env indirection "
                         "only)")
    ap.add_argument("--json", action="store_true",
                    help="print the full machine-readable report")
    args = ap.parse_args(argv)

    system_sha = args.system_sha or hashlib.sha256(
        b"unspecified").hexdigest()
    fp = fingerprint_target(args.api_style, args.model, system_sha)
    profile_dir = pathlib.Path(args.profile_dir)
    profile_dir.mkdir(parents=True, exist_ok=True)
    path = profile_dir / f"target_{fp}.json"
    profile = (TargetProfile.load(path) if path.exists()
               else TargetProfile(fingerprint=fp))
    session_no = profile.start_session()

    orch = FamilyOrchestrator(profile, budget=args.budget,
                              per_lane_cap=args.per_lane_cap)
    skipped: list = []
    registered: list = []
    lane_env = _parse_env(args.lane_env)

    # -- LLM01: the PI agentic channel (live) ---------------------------------
    if "LLM01" in args.lanes:
        if args.pi_endpoint is None:
            skipped.append({
                "lane": "LLM01",
                "reason": "no --pi-endpoint — the PI agentic channel "
                          "needs a live target (offline channel: LLM03)"})
        else:
            try:
                from ..pi.live import LiveSession, LiveTarget
                env = _live_env(args.pi_endpoint, args.pi_style,
                                args.model, lane_env)
                target = LiveTarget.from_env(env)
                session = LiveSession(target, env,
                                      max_requests=args.per_lane_cap * 4)
                if args.pi_escalation:
                    from ..pi.escalation import crescendo_probe
                    orch.register("LLM01", lambda p, b: crescendo_probe(
                        session, budget=min(b * 4, args.per_lane_cap * 4),
                        seed=args.seed, profile=p))
                else:
                    from ..pi.agent import agentic_live_probe
                    orch.register("LLM01", lambda p, b: agentic_live_probe(
                        target, budget=min(b, args.per_lane_cap),
                        seed=args.seed, session=session, profile=p))
                registered.append("LLM01")
            except Exception as e:            # loud skip, never a crash
                skipped.append({"lane": "LLM01",
                                "reason": f"live lane unavailable: {e}"})

    # -- LLM02: the SID agentic channel (live) ---------------------------------
    if "LLM02" in args.lanes:
        if args.sid_endpoint is None:
            skipped.append({
                "lane": "LLM02",
                "reason": "no --sid-endpoint — the SID agentic channel "
                          "needs a live target (offline channel: LLM03)"})
        else:
            try:
                from ..pi.live import LiveSession, LiveTarget
                from ..sid.agent import sid_agentic_probe
                from ..sid.oracles import make_pii_record
                env = _live_env(args.sid_endpoint, args.pi_style,
                                args.model, lane_env)
                target = LiveTarget.from_env(env)
                session = LiveSession(target, env,
                                      max_requests=args.per_lane_cap)
                record = make_pii_record(random.Random(args.seed))
                orch.register("LLM02", lambda p, b: sid_agentic_probe(
                    record, budget=min(b, args.per_lane_cap),
                    seed=args.seed, session=session, profile=p))
                registered.append("LLM02")
            except Exception as e:
                skipped.append({"lane": "LLM02",
                                "reason": f"live lane unavailable: {e}"})

    # -- LLM03: the SC provenance-probing channel (offline) ---------------------
    if "LLM03" in args.lanes:
        from ..sc.agent import sc_agentic_probe
        gate_fn = BUILT_IN_GATES[args.gate]
        orch.register("LLM03", lambda p, b: sc_agentic_probe(
            gate_fn, budget=min(b, args.per_lane_cap), seed=args.seed,
            profile=p))
        registered.append("LLM03")

    # -- LLM05: the OH output-handling channel (offline) --------------------------
    if "LLM05" in args.lanes:
        from ..oh.agent import oh_agentic_probe
        pipeline_fn = BUILT_IN_PIPELINES[args.pipeline]
        orch.register("LLM05", lambda p, b: oh_agentic_probe(
            pipeline_fn, budget=min(b, args.per_lane_cap), seed=args.seed,
            profile=p))
        registered.append("LLM05")

    # -- LLM06: the EA agency-abuse channel (offline) ----------------------------
    if "LLM06" in args.lanes:
        from ..ea.agent import ea_agentic_probe
        executor_fn = BUILT_IN_EXECUTORS[args.executor]
        orch.register("LLM06", lambda p, b: ea_agentic_probe(
            executor_fn, budget=min(b, args.per_lane_cap), seed=args.seed,
            profile=p))
        registered.append("LLM06")

    if not registered:
        for s in skipped:
            print(f"  {s['lane']}: SKIPPED — {s['reason']}")
        print("nothing ran — every requested channel needs a live "
              "endpoint; wire --pi-endpoint / --sid-endpoint, or run the "
              "offline SC channel with --lanes LLM03")
        return 2

    campaign = orch.run()
    profile.save(path)

    report = {
        **campaign,
        "target": {"name": args.target, "model": args.model,
                   "api_style": args.api_style, "fingerprint": fp},
        "fingerprint": fp,
        "session": session_no,
        "gate": args.gate if "LLM03" in registered else None,
        "executor": args.executor if "LLM06" in registered else None,
        "pipeline": args.pipeline if "LLM05" in registered else None,
        "pi_attacker": ("crescendo" if args.pi_escalation else "grammar")
        if "LLM01" in registered else None,
        "skipped": skipped,
        "profile_path": str(path),
    }
    # the kill-chain composer: EARNED verdicts ordered into an attack
    # path — it reads the report, never upgrades a verdict
    from .killchain import assess_kill_chain, chain_summary_line
    report["kill_chain"] = assess_kill_chain(report, profile=profile)

    if args.json:
        print(json.dumps(report, indent=2, ensure_ascii=False, default=str))
        return 0

    print(f"redteam.brain — target {args.target!r} "
          f"fingerprint {fp[:12]}… session {session_no}")
    for s in skipped:
        print(f"  {s['lane']}: SKIPPED — {s['reason']}")
    for fam in registered:
        f = campaign["families"][fam]
        rec = campaign["lane_records"].get(fam, {})
        print(f"  {fam}: {str(f['verdict'] or 'inconclusive').upper():11} "
              f"basis={rec.get('verdict_basis')} "
              f"requests={f['requests']} attempts={f['attempts']} "
              f"frozen={f['frozen']}")
    print(f"budget {campaign['budget_spent']}/{campaign['budget']}  "
          f"stop: {campaign['stop_reason']}")
    print(f"kill chain: {chain_summary_line(report['kill_chain'])}")
    print(f"profile saved: {path}")
    print("--- briefing for the next session ---")
    print(campaign["profile_briefing"] or "(empty — nothing learned yet)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
