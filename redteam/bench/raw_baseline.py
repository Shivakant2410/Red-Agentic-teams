"""The no-scaffolding baseline: can a raw model do the engagement without our tool?

This arm exists to answer ONE question honestly: how much of the score is the model,
and how much is the machinery around it (agent loop, memory, claim/verify protocol,
class specialists)? "Our tool vs frontier model" is not one experiment but a matrix:

    raw    — the model answers in one (or K) blind shots. No tools, no loop, no memory.
             It names requests; WE replay them mechanically and check its cited evidence.
    rawk   — same, K rounds: each round sees the previous round's responses. Feedback
             without scaffolding: the loop is the only difference from `raw`.
    flat   — the full agent (tools, memory, guardrails), single agent, no swarm.
    swarm  — orchestrator + OWASP class specialists (the flagship).

Everything downstream of the prompt is shared with the agent arms: same engagement
RoE, same target, same scorer (score_objective_run + score_run), same "confirmed
counts, guesses don't" rule. The only asymmetry, documented here, is HOW a raw claim
reaches `confirmed`: the model must cite a request AND an evidence substring; the
claim is confirmed only if the replayed response really contains that evidence
(PoC||GTFO, executed for it). That is a WEAKER bar than the agent's differential
VERIFY protocol — deliberately. If the raw model still loses, it can't blame the
referee.

Sandbox constraint: long runs must finish inside one shell call, so the ladder driver
filters cells (like SPEC_ARMS); this module itself is one cell per invocation:

    python -m redteam.bench.raw_baseline --engagement runs/x/engagement.yaml \
        --objective "..." --out runs/x/raw --rounds 1
"""

from __future__ import annotations

import argparse
import json
import re
import time
from pathlib import Path
from urllib.parse import urlsplit

import requests

from ..config import load_engagement
from ..llm.gateway import build_llm_client
from ..objective import regex_match
from .scoring import score_run

# -- Prompt surface -------------------------------------------------------------
# Same discipline as agent.py's registry-honest system prompt: name the contract
# exactly, demand evidence, refuse everything that smells like unverified narrative.

SYSTEM_PROMPT = """\
You are a senior web red-teamer operating with zero tools: you cannot see responses \
yourself. Your proposed HTTP requests are replayed verbatim for you and the responses \
are shown back.

Rules:
1. Output STRICT JSON only — no prose, no markdown fences, no commentary.
2. Shape:
   {"claims": [{"title": str, "cwe": "CWE-NNN", "path": str, "severity":
                "critical|high|medium|low", "evidence": str,
                "request": {"method": str, "path": str, "headers": {str: str},
                            "body": str}}],
    "requests": [{"name": str, "method": str, "path": str, "headers": {str: str},
                  "body": str}]}
3. "claims" are vulnerabilities you ASSERT exist. A claim only counts when its cited
   request was replayed and "evidence" (an exact substring) appears in that response.
   Uncited claims score zero. Claiming without evidence is a false positive.
4. "requests" are what you want replayed NEXT round (empty array on your final round).
   Paths are appended to the base URL — start with "/". Never invent a hostname.
5. Prove, don't speculate: prefer a request that will demonstrate the bug (differentials,
   cross-tenant reads, marker reflections) over exploratory browsing.
6. Stay strictly inside the stated scope. Out-of-scope requests are rejected.
"""


def build_round_messages(objective_text: str, base_url: str, credential_note: str,
                         scope_note: str, observations: list[dict] | None,
                         round_no: int, rounds: int) -> list[dict]:
    """One user message per round. Round 1 = map blind; later rounds see responses."""
    parts = [
        f"TARGET: {base_url}",
        f"AUTHORIZATION & SCOPE: {scope_note}",
    ]
    if credential_note:
        parts.append(f"CREDENTIAL: {credential_note}")
    parts.append(f"OBJECTIVE: {objective_text}")
    if observations:
        parts.append("PREVIOUS ROUND RESPONSES (verbatim excerpts):")
        parts.append(json.dumps(observations, indent=1, ensure_ascii=False))
    else:
        parts.append("No responses yet — this is a blind map.")
    parts.append(
        f"ROUND {round_no} of {rounds}. "
        + ("This is your LAST round: put your strongest proof requests in 'requests' "
           "and every claim you can support in 'claims'."
           if round_no == rounds else
           "Propose up to 8 high-value requests; keep claims for what you can already "
           "prove from responses you have seen."))
    return [{"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": "\n\n".join(parts)}]


# -- Parsing ---------------------------------------------------------------------

def parse_model_json(text: str) -> dict:
    """Strict about semantics, tolerant about packaging: fenced blocks stripped, first
    JSON object wins. A model that cannot emit the contract loses by the contract."""
    if not text or not text.strip():
        return {}
    body = text.strip()
    fence = re.search(r"```(?:json)?\s*(.*?)```", body, re.DOTALL)
    if fence:
        body = fence.group(1).strip()
    elif not body.startswith("{"):
        start = body.find("{")
        end = body.rfind("}")
        if start == -1 or end <= start:
            return {}
        body = body[start:end + 1]
    try:
        data = json.loads(body)
    except json.JSONDecodeError:
        return {}
    return data if isinstance(data, dict) else {}


def _norm_request(raw: dict) -> dict:
    method = str(raw.get("method") or "GET").upper()
    path = str(raw.get("path") or "/")
    if not path.startswith("/"):
        path = "/" + path
    headers = {str(k): str(v) for k, v in (raw.get("headers") or {}).items()
               if isinstance(raw.get("headers"), dict)}
    body = str(raw.get("body") or "")
    return {"method": method, "path": path, "headers": headers, "body": body,
            "name": str(raw.get("name") or "")}


def parse_requests(data: dict, max_per_round: int = 8) -> list[dict]:
    raw_list = [raw for raw in (data.get("requests") or []) if isinstance(raw, dict)]
    return [_norm_request(raw) for raw in raw_list[:max_per_round]]


def parse_claims(data: dict) -> list[dict]:
    out = []
    for raw in (data.get("claims") or []):
        if not isinstance(raw, dict):
            continue
        title = str(raw.get("title") or "").strip()
        if not title:
            continue
        req = raw.get("request") if isinstance(raw.get("request"), dict) else None
        out.append({
            "title": title,
            "cwe": str(raw.get("cwe") or ""),
            "path": str(raw.get("path") or ""),
            "severity": str(raw.get("severity") or "medium").lower(),
            "evidence": str(raw.get("evidence") or ""),
            "request": _norm_request(req) if req else None,
        })
    return out


# -- Scope + replay ----------------------------------------------------------------

class ScopeFilter:
    """The raw arm gets the same scope discipline as the agent: engagement RoE, no
    exceptions. A model that proposes out-of-scope requests sees the rejection — the
    same feedback an agent gets from ScopeGuard — and that rejection costs it a slot."""

    def __init__(self, engagement):
        self.hosts = {h.lower() for h in engagement.allowed_hosts}
        self.ports = set(engagement.allowed_ports)
        self.schemes = {s.lower() for s in engagement.allowed_schemes}

    def check(self, base_url: str, path: str) -> str | None:
        """Return a rejection reason, or None when allowed. Host/port come from the
        base URL itself — the contract forbids inventing a hostname, so this enforces
        scheme + port against the engagement rather than parsing arbitrary hosts."""
        parts = urlsplit(base_url)
        host = parts.hostname or ""
        port = parts.port
        if parts.scheme not in self.schemes:
            return f"scheme {parts.scheme!r} not in RoE"
        if host.lower() not in self.hosts and "*" not in host:
            return f"host {host!r} not in RoE allowed_hosts"
        if port is not None and self.ports and port not in self.ports:
            return f"port {port} not in RoE allowed_ports"
        if path.startswith("//"):   # protocol-relative escape to another host
            return "protocol-relative URL escapes the base host"
        return None


def replay(session: requests.Session, base_url: str, requests_in: list[dict],
           scope: ScopeFilter, max_requests: int = 200) -> tuple[list[dict], list[dict]]:
    """Execute requests in order; return (observations_for_model, full_transcript).
    Observations are truncated for the prompt; the transcript keeps what scoring needs."""
    observations, transcript = [], []
    for req in requests_in:
        if len(transcript) >= max_requests:
            break
        reason = scope.check(base_url, req["path"])
        if reason:
            transcript.append({**req, "rejected": reason})
            observations.append({"request": req["method"] + " " + req["path"],
                                 "rejected": reason})
            continue
        url = base_url.rstrip("/") + req["path"]
        try:
            resp = session.request(req["method"], url, headers=req["headers"],
                                   data=req["body"] or None, timeout=15,
                                   allow_redirects=False)
            body = resp.text[:4000]
            entry = {"request": req["method"] + " " + req["path"],
                     "status": resp.status_code,
                     "content_type": resp.headers.get("content-type", ""),
                     "body": body}
            if resp.headers.get("location"):
                entry["location"] = resp.headers["location"]
            observations.append(entry)
            transcript.append({**req, "status": resp.status_code,
                               "content_type": resp.headers.get("content-type", ""),
                               "response_body": resp.text,
                               "response_headers": dict(resp.headers)})
        except requests.RequestException as exc:
            observations.append({"request": req["method"] + " " + req["path"],
                                 "error": type(exc).__name__})
            transcript.append({**req, "error": type(exc).__name__})
    return observations, transcript


# -- Verification + scoring ----------------------------------------------------------

def verify_claims(claims: list[dict], transcript: list[dict]) -> list[dict]:
    """Mechanical evidence check: confirmed only when the cited request really returned
    the cited evidence substring. Everything else stays 'claimed' — and score_run only
    counts 'confirmed', the exact same rule the agent runs are scored under."""
    findings = []
    for claim in claims:
        confirmed = False
        evidence = claim.get("evidence") or ""
        cited = claim.get("request")
        if cited:
            for entry in transcript:
                if entry.get("rejected") or entry.get("error"):
                    continue
                same = (entry["method"] == cited["method"]
                        and entry["path"] == cited["path"])
                if not same:
                    continue
                body = entry.get("response_body") or ""
                headers = " ".join(str(v) for v in (entry.get("response_headers") or {}).values())
                if evidence and (evidence in body or evidence in headers) \
                        and 200 <= (entry.get("status") or 0) < 300:
                    confirmed = True
                    break
        findings.append({
            "title": claim["title"],
            "type": claim.get("cwe") or "",
            "cwe": claim.get("cwe") or "",
            "path": claim.get("path") or "",
            "severity": claim.get("severity") or "medium",
            "confidence": "confirmed" if confirmed else "claimed",
            "evidence_checked": confirmed,
        })
    return findings


def mark_objective(objective, transcript: list[dict]) -> list[str]:
    """Credit criteria from raw evidence. Regex criteria match response bodies/headers;
    non-regex access criteria credit on a 2xx whose path-or-body contains the target
    string — a mechanical oracle, intentionally conservative (a 403 never credits)."""
    if objective is None:
        return []
    bodies, url_paths = [], []
    for entry in transcript:
        if entry.get("rejected") or entry.get("error"):
            continue
        url_paths.append(entry.get("path", ""))
        body = entry.get("response_body") or ""
        headers = " ".join(str(v) for v in (entry.get("response_headers") or {}).values())
        bodies.append(body + "\n" + headers)
    credited = []
    for c in objective.criteria:
        if c.achieved:
            continue
        if c.evidence_regex:
            snippet = regex_match(c.evidence_regex, *bodies)
            if snippet:
                objective.mark(c.id, f"raw replay matched {snippet!r}")
                credited.append(c.id)
            continue
        if c.kind in ("data_access", "host_access", "privilege") and c.target:
            for entry in transcript:
                if entry.get("rejected") or entry.get("error"):
                    continue
                status = entry.get("status") or 0
                if 200 <= status < 300 and (
                        c.target in entry.get("path", "")
                        or c.target in (entry.get("response_body") or "")):
                    objective.mark(c.id,
                                   f"raw replay {entry['method']} {entry['path']} -> {status}")
                    credited.append(c.id)
                    break
    return credited


# -- Driver ---------------------------------------------------------------------------

def run_raw(engagement_path: str, objective_text: str, out_dir: Path, rounds: int,
            model: str = "", role: str = "plan", max_round_requests: int = 8) -> dict:
    """One baseline cell. `llm` arrives via the engagement config (same fleet the agent
    uses) — deliberately the SAME plumbing, so the comparison isolates scaffolding."""
    engagement = load_engagement(engagement_path)
    out_dir.mkdir(parents=True, exist_ok=True)

    from dataclasses import replace

    from ..config import LlmConfig
    llm_cfg: LlmConfig = engagement.llm
    if model:
        # LlmConfig is frozen — role pins are a derived config, never a mutation.
        llm_cfg = replace(llm_cfg, role_models={**llm_cfg.role_models, role: model})
    llm = build_llm_client(llm_cfg)

    # Derive the target base from scope: lab engagements scope a single host:port.
    host = engagement.allowed_hosts[0]
    port = engagement.allowed_ports[0]
    scheme = sorted(engagement.allowed_schemes)[0]
    base_url = f"{scheme}://{host}:{port}"

    from ..objective import Objective
    obj_path = out_dir / "objective.json"
    objective = getattr(engagement, "objective", None)
    if objective is None:                    # plain engagements: pre-seeded objective.json
        if obj_path.exists():
            objective = Objective.load(obj_path)
    credential_note = ""

    scope = ScopeFilter(engagement)
    session = requests.Session()
    audit = (out_dir / "audit.log.jsonl").open("a", encoding="utf-8")

    def log(event: str, **fields) -> None:
        audit.write(json.dumps({"ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
                                "event": event, **fields}) + "\n")

    observations: list[dict] = []
    transcript: list[dict] = []
    tokens = 0
    used_model = ""
    halt_reason = ""
    status = "completed"

    for round_no in range(1, rounds + 1):
        messages = build_round_messages(
            objective_text, base_url, credential_note, f"allowed hosts: "
            f"{sorted(scope.hosts)} ports: {sorted(scope.ports)} "
            f"schemes: {sorted(scope.schemes)}",
            observations or None, round_no, rounds)
        try:
            result = llm.chat(messages, None, role)
        except Exception as exc:                       # NoModelsAvailable / transport
            status, halt_reason = "error", f"llm failed on round {round_no}: {exc}"
            log("raw.llm_error", round=round_no, error=str(exc)[:300])
            break
        used_model = getattr(result, "model", "") or used_model
        usage = getattr(result, "usage", {}) or {}
        tokens += int(usage.get("total_tokens") or 0)
        content = (getattr(result, "message", {}) or {}).get("content") or ""
        log("raw.round", round=round_no, model=used_model,
            tokens=int(usage.get("total_tokens") or 0))
        data = parse_model_json(content)
        reqs = parse_requests(data, max_round_requests)
        claims = parse_claims(data)
        # Persist the claims verbatim now — scoring re-reads them from the audit so a
        # mid-run crash still leaves the run scoreable.
        log("raw.claims", round=round_no, claims=claims)
        log("raw.plan", round=round_no, requests=len(reqs), claims=len(claims))
        if not reqs and round_no < rounds and not claims:
            # Nothing proposed and nothing claimed — further rounds cannot change facts.
            halt_reason = f"model proposed no requests on round {round_no}"
            break
        observations, round_transcript = replay(session, base_url, reqs, scope)
        transcript.extend(round_transcript)
        log("raw.replay", round=round_no, executed=len(round_transcript),
            rejected=sum(1 for e in round_transcript if e.get("rejected")))
        if round_no < rounds and not observations:
            halt_reason = f"no responses on round {round_no}; stopping"
            break

    audit.close()

    claims_all = []
    # Claims are re-parsed per round inside the loop only for logging; keep them from
    # the message flow by re-parsing is not possible post-hoc — so parse+persist per
    # round instead (round_transcript loop above logs counts). Re-walk the audit for
    # scoring claims: they were persisted per round below.
    for line in (out_dir / "audit.log.jsonl").read_text(encoding="utf-8").splitlines():
        try:
            ev = json.loads(line)
        except json.JSONDecodeError:
            continue
        if ev.get("event") == "raw.claims":
            claims_all.extend(ev.get("claims") or [])

    findings = verify_claims(claims_all, transcript)
    (out_dir / "findings.json").write_text(
        json.dumps(findings, indent=1), encoding="utf-8")

    credited = mark_objective(objective, transcript) if objective else []
    if objective is not None:
        objective.save(obj_path)

    gt = _ground_truth_for(engagement)
    elapsed = 0.0
    confirmed = len([f for f in findings if f["confidence"] == "confirmed"
                     and f["severity"] != "info"])
    card = score_run(engagement.name, findings, gt, cost_tokens=tokens,
                     elapsed_s=elapsed)

    manifest = {
        "status": status, "steps": rounds, "findings": len(findings),
        "tokens": tokens, "halt_reason": halt_reason, "model": used_model,
        "arm": f"raw{rounds if rounds > 1 else ''}",
    }
    (out_dir / "manifest.json").write_text(json.dumps(manifest, indent=1),
                                           encoding="utf-8")
    summary = {
        "arm": manifest["arm"], "model": used_model,
        "objective_credited": credited,
        "confirmed": confirmed, "precision": card.precision,
        "recall": card.recall, "f1": card.f1,
        "tokens": tokens, "halt_reason": halt_reason, "status": status,
        "requests_executed": len([e for e in transcript if not e.get("rejected")
                                  and not e.get("error")]),
        "requests_rejected": len([e for e in transcript if e.get("rejected")]),
    }
    (out_dir / "raw.card.json").write_text(json.dumps(summary, indent=1),
                                           encoding="utf-8")
    return summary


def _ground_truth_for(engagement) -> list:
    """Ground truth is keyed by target name in the registry; ladder/runner engagement
    names carry decorative prefixes ("Bench: ", "Benchmark: ") that must not break it."""
    from .targets import REGISTRY
    name = engagement.name
    for prefix in ("Bench: ", "Benchmark: "):
        if name.startswith(prefix):
            name = name[len(prefix):]
    for target in REGISTRY.values():
        if target.name == name:
            return target.ground_truth
    return []


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description="No-scaffolding baseline: same target, same scorer, zero agent loop.")
    ap.add_argument("--engagement", required=True)
    ap.add_argument("--objective", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--rounds", type=int, default=1,
                    help="1 = raw (blind), >=2 = rawk (feedback rounds)")
    ap.add_argument("--model", default="", help="Pin a role model (provider:model or bare id)")
    ap.add_argument("--max-requests-per-round", type=int, default=8)
    args = ap.parse_args(argv)

    summary = run_raw(args.engagement, args.objective, Path(args.out), args.rounds,
                      model=args.model, max_round_requests=args.max_requests_per_round)
    print(json.dumps(summary, indent=1))
    return 0 if summary["status"] == "completed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
