"""retest — post-remediation re-proof of recorded findings (ARTEX 漏洞复测, ported).

ARTEX's retester answers the question every engagement eventually asks: the
client says "we fixed it" — is the finding actually gone? It spawns a separate
agent session per retest. We ported the MECHANISM and dropped the agent: a
recorded finding already carries its own replay recipe (check_type +
check_spec, stored by the proof tool that ran the original check), so the
retest is a DETERMINISTIC rebuild-and-replay — no LLM, no token cost, no
narration to trust, bit-for-bit the same proof the pipeline accepted the first
time. That is a stronger retest than asking a model to re-derive one.

The verdict vocabulary is the retest question, NOT the verification question:

    reproducible    the proof still reproduces (k-of-n, or any successful
                    reproduction at all — a flaky bug is not a fixed bug)
    fixed           every trial got a REAL response and none satisfied the
                    vulnerability assertion — the hole closed
    cannot_confirm  we could not judge: transport dead on some/all trials
                    (host down, DNS gone), a replay session no longer exists,
                    or a workflow finding retested without fresh identifiers.
                    Honest separation from "fixed" — certifying a remediation
                    over dead trials is how false remediation reports happen.
    blocked         the stored check now falls OUTSIDE the current RoE (the
                    engagement changed between run and retest, or scope.json
                    was rebuilt narrower). Never laundered into a soft verdict:
                    a scope-anomalous retest is an operator-visible event.

Differences from the original verification (independent_verify): no negative
control — the retest WANTS the attack to reproduce; a benign control proves
nothing about remediation. No promotion/demotion of `confidence` — verification
state records whether the finding was real; retest history records whether it
STILL IS, and the two dimensions stay orthogonal.

Every retest is appended to the finding's retest_history (auditable timeline of
"still reproducible" claims across remediation cycles), and every fired request
goes through the run's scope guard and traffic recorder — a retest is real
traffic and obeys the same RoE as the engagement that produced it.
"""

from __future__ import annotations

import datetime as _dt
import json

from .events import safe_emit
from .proof import ProofCheck, eval_condition
from .scope import ScopeViolation
from .verify import DifferentialCheck, HttpCheck, verify
from .tools.http import make_fetch
from .tools.logic import run_ordered_steps

REPRODUCIBLE, FIXED, CANNOT_CONFIRM, BLOCKED = (
    "reproducible", "fixed", "cannot_confirm", "blocked")


class _TransportBox:
    """Counts trials whose transport died (status 0 — host down, DNS, refused).
    Fetch-level, not assertion-level: only real evidence the target was gone."""

    def __init__(self):
        self.unreachable = 0

    def guard(self, fetch):
        box = self

        def inner():
            status, body, elapsed = fetch()
            if status == 0:
                box.unreachable += 1
            return status, body, elapsed
        return inner


def _verdict_from(reproductions: int, trials: int, unreachable: int) -> tuple[str, str]:
    """The mapping that makes the three-way call honest. See module docstring."""
    if reproductions >= trials:
        return REPRODUCIBLE, f"reproduced on all {trials} trials"
    if reproductions > 0:
        return (REPRODUCIBLE,
                f"flaky but real: reproduced {reproductions}/{trials} trials — "
                f"any reproduction means the hole is still open")
    if unreachable >= trials:
        return CANNOT_CONFIRM, f"transport dead on all {trials} trials — target unreachable"
    if unreachable > 0:
        return (CANNOT_CONFIRM,
                f"transport dead on {unreachable}/{trials} trials — cannot certify a "
                f"fix over failed requests")
    return FIXED, f"0/{trials} reproductions, all trials reached a live target"


def retest_finding(f, ctx, *, trials: int = 5, need: int = 4,
                   fresh_attack_steps: list | None = None,
                   fresh_control_steps: list | None = None) -> dict:
    """Replay one finding's stored check. `ctx` is the run's ToolContext (scope,
    traffic, sessions, audit all wired) — a retest obeys the same RoE as the run.
    Never raises for finding-level problems: every failure mode becomes a verdict."""
    out = {"finding_id": f.id, "title": f.title, "check_type": f.check_type,
           "reproductions": 0, "trials": trials, "unreachable": 0}
    try:
        verdict, detail, extra = _replay(f, ctx, trials, need,
                                         fresh_attack_steps, fresh_control_steps)
    except ScopeViolation as exc:
        verdict, detail, extra = BLOCKED, f"stored check is out of the current RoE: {exc}", {}
    except Exception as exc:  # a broken replay must not take the caller down
        verdict, detail, extra = CANNOT_CONFIRM, f"retest machinery error: {exc}", {}
    out.update(verdict=verdict, detail=detail, **extra)
    return out


def _replay(f, ctx, trials, need, fresh_attack_steps, fresh_control_steps):
    box = _TransportBox()
    spec = f.check_spec or {}

    if f.check_type == "http":
        request = spec.get("request")
        if not request:
            return CANNOT_CONFIRM, "no stored request to replay", {}
        check = HttpCheck(fetch=box.guard(make_fetch(ctx, request)),
                          expect_status=spec.get("expect_status"),
                          body_regex=spec.get("body_regex"),
                          max_latency=spec.get("max_latency"))
        result = verify(check, trials=trials, need=need)
        return (*_verdict_from(result.reproductions, result.trials, box.unreachable),
                {"reproductions": result.reproductions})

    if f.check_type == "differential":
        baseline, payload = spec.get("baseline_request"), spec.get("payload_request")
        if not (baseline and payload):
            return CANNOT_CONFIRM, "no stored baseline/payload requests to replay", {}
        check = DifferentialCheck(
            fetch_baseline=box.guard(make_fetch(ctx, baseline)),
            fetch_payload=box.guard(make_fetch(ctx, payload)),
            min_latency_delta=spec.get("min_latency_delta"),
            body_differs_regex=spec.get("body_differs_regex"))
        result = verify(check, trials=trials, need=need)
        return (*_verdict_from(result.reproductions, result.trials, box.unreachable),
                {"reproductions": result.reproductions})

    if f.check_type == "proof":
        requests_spec = spec.get("requests") or {}
        conditions = spec.get("conditions") or []
        if not requests_spec or not conditions:
            return CANNOT_CONFIRM, "no stored requests/conditions to replay", {}
        fetchers = {name: box.guard(make_fetch(ctx, req))
                    for name, req in requests_spec.items()}
        result = verify(ProofCheck(fetchers, conditions), trials=trials, need=need)
        return (*_verdict_from(result.reproductions, result.trials, box.unreachable),
                {"reproductions": result.reproductions})

    if f.check_type == "privilege":
        if ctx.sessions is None:
            return CANNOT_CONFIRM, "session store unavailable for replay", {}
        high = ctx.sessions.get(spec.get("high_session_label", ""))
        if high is None:
            return (CANNOT_CONFIRM,
                    f"session {spec.get('high_session_label')!r} no longer available "
                    f"to replay the privilege proof", {})
        low_label = spec.get("low_session_label") or ""
        low = ctx.sessions.get(low_label) if low_label else None
        method, url = spec.get("method", "GET"), spec.get("privileged_url", "")
        fetchers = {"payload": box.guard(make_fetch(ctx, {
            "method": method, "url": url, "headers": high.apply({})}))}
        conditions = [{"type": "status", "request": "payload",
                       "equals": spec.get("expect_status", 200)},
                      {"type": "body_regex", "request": "payload",
                       "pattern": spec.get("privileged_marker", "")}]
        result = verify(ProofCheck(fetchers, conditions), trials=trials, need=need)
        return (*_verdict_from(result.reproductions, result.trials, box.unreachable),
                {"reproductions": result.reproductions})

    if f.check_type == "workflow":
        # One-shot sequences (redeem-twice, skip-a-step) consume their own
        # precondition — verbatim replay would "fix" every real bug for free.
        # Same contract as independent_verify: the operator supplies a fresh
        # identifier's attack/control sequences shaped like the original.
        if not fresh_attack_steps or not fresh_control_steps:
            return (CANNOT_CONFIRM,
                    "workflow findings need fresh_attack_steps/fresh_control_steps "
                    "(a new identifier) — one-shot steps cannot be replayed verbatim", {})
        invariant = spec.get("invariant") or []
        control_invariant = spec.get("control_invariant") or invariant
        try:
            attack = run_ordered_steps(ctx, fresh_attack_steps)
        except Exception as exc:
            return CANNOT_CONFIRM, f"fresh attack sequence failed: {exc}", {}
        ok, details = True, []
        for cond in invariant:
            try:
                passed, d = eval_condition(cond, attack)
            except KeyError as exc:
                return CANNOT_CONFIRM, f"invariant references unknown step: {exc}", {}
            ok = ok and passed
            details.append(("PASS " if passed else "fail ") + "attack: " + d)
        if not ok:
            return REPRODUCIBLE, "fresh-identifier attack still violates the invariant: " + "; ".join(details), {}
        try:
            control = run_ordered_steps(ctx, fresh_control_steps)
        except Exception as exc:
            return CANNOT_CONFIRM, f"fresh control sequence failed: {exc}", {}
        control_ok = True
        for cond in control_invariant:
            try:
                passed, d = eval_condition(cond, control)
            except KeyError as exc:
                return CANNOT_CONFIRM, f"control_invariant references unknown step: {exc}", {}
            control_ok = control_ok and passed
            details.append(("PASS " if passed else "fail ") + "control: " + d)
        if control_ok:
            return (CANNOT_CONFIRM,
                    "the honest control (fresh identifier) ALSO violates the invariant — "
                    "the original check may be unsound; re-verify before believing a fix", {})
        return FIXED, "fresh-identifier attack no longer violates the invariant; control held", {}

    return CANNOT_CONFIRM, f"no replayable check_type ({f.check_type!r}) stored", {}


def retest_run(store, ctx, *, finding_id: str = "", trials: int = 5, need: int = 4,
               fresh_attack_steps: list | None = None,
               fresh_control_steps: list | None = None,
               record_history: bool = True) -> list[dict]:
    """Retest one finding (by id) or every finding with a stored replay recipe.
    Appends each result to the finding's retest_history (never touches confidence —
    verification state and remediation state are orthogonal)."""
    results = []
    for f in store.all():
        if finding_id and f.id != finding_id:
            continue
        if not f.check_type:
            continue  # never had a replay recipe — nothing deterministic to run
        out = retest_finding(f, ctx, trials=trials, need=need,
                             fresh_attack_steps=fresh_attack_steps,
                             fresh_control_steps=fresh_control_steps)
        out["title"] = f.title
        results.append(out)
        if record_history:
            entry = {"when": _dt.datetime.now(_dt.timezone.utc).isoformat(),
                     "verdict": out["verdict"], "reproductions": out["reproductions"],
                     "trials": out["trials"], "detail": out["detail"]}
            store.append_retest(f.id, entry)
        safe_emit(getattr(ctx, "events", None), "finding.retested",
                  finding_id=f.id, verdict=out["verdict"], detail=out["detail"][:200])
    return results


def build_ctx_for_run(engagement, run_dir):
    """A minimal ToolContext for retesting a FINISHED run: the frozen RoE from
    scope.json (rebuilt as an Engagement — the original engagement file may have
    changed since), a fresh audit/traffic/inventory against the run dir, no LLM."""
    from .audit import AuditLog
    from .findings import FindingStore
    from .inventory import AssetInventory
    from .ratelimit import RateLimiter
    from .scope import ScopeGuard
    from .traffic import TrafficRecorder
    from .tools import ToolContext
    from .session import SessionStore

    scope = ScopeGuard(engagement)
    ctx = ToolContext(
        scope=scope,
        limiter=RateLimiter(engagement.max_requests_per_second,
                            engagement.max_total_requests),
        audit=AuditLog(run_dir / "audit.log.jsonl"),
        findings=FindingStore(run_dir / "findings.json"),
        approve=lambda action, details: True,   # the operator INVOKING the retest is the approval
        sessions=SessionStore(),
    )
    ctx.traffic = TrafficRecorder(run_dir / "traffic.jsonl")
    ctx.inventory = AssetInventory(run_dir / "inventory.json")
    return ctx


def engagement_from_scope_json(run_dir):
    """Rebuild the retest engagement from the run's frozen scope.json — never from
    the live engagement file, which may have drifted since the run."""
    from .config import Engagement, LlmConfig, SandboxConfig
    p = run_dir / "scope.json"
    raw = json.loads(p.read_text(encoding="utf-8"))
    return Engagement(
        name=f"retest:{run_dir.name}", client="retest", authorized_by="scope.json",
        ticket="retest of a recorded run", starts=_dt.date.today(), ends=_dt.date.today(),
        allowed_hosts=tuple(raw.get("allowed_hosts", ())),
        excluded_hosts=tuple(raw.get("excluded_hosts", ())),
        allowed_ports=tuple(raw.get("allowed_ports", ())),
        allowed_schemes=tuple(raw.get("allowed_schemes", ("http", "https"))),
        max_requests_per_second=raw.get("max_requests_per_second", 5.0),
        max_total_requests=raw.get("max_total_requests", 1000),
        allow_private_ranges=raw.get("allow_private_ranges", False),
        require_approval_for=(), llm=LlmConfig(), sandbox=SandboxConfig(), raw={},
    )


def main(argv: list[str] | None = None) -> int:  # pragma: no cover - thin CLI
    import argparse
    from pathlib import Path

    ap = argparse.ArgumentParser(
        prog="python -m redteam.retest",
        description="Deterministic post-remediation retest of recorded findings "
                    "(no LLM — replays each finding's stored proof recipe).")
    ap.add_argument("run_dir", help="the run directory to retest against")
    ap.add_argument("--finding", default="", help="retest one finding by id (default: all)")
    ap.add_argument("--trials", type=int, default=5)
    ap.add_argument("--need", type=int, default=4)
    ap.add_argument("--fresh-attack", default="", help="JSON file with fresh attack steps (workflow findings)")
    ap.add_argument("--fresh-control", default="", help="JSON file with fresh control steps (workflow findings)")
    args = ap.parse_args(argv)

    run_dir = Path(args.run_dir)
    engagement = engagement_from_scope_json(run_dir)
    ctx = build_ctx_for_run(engagement, run_dir=run_dir)
    results = retest_run(ctx.findings, ctx, finding_id=args.finding,
                         trials=args.trials, need=args.need,
                         fresh_attack_steps=json.loads(Path(args.fresh_attack).read_text()) if args.fresh_attack else None,
                         fresh_control_steps=json.loads(Path(args.fresh_control).read_text()) if args.fresh_control else None)
    print(json.dumps(results, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
