"""ExperienceStore — the agent's long-term, cross-engagement memory (the learning loop).

This is what turns a static tool into a compounding one: every run distills a few
*generalizable* lessons that are recalled on future runs. Weights never change, but the
system gets smarter each engagement.

Design principles (from the 2025-26 agent-memory literature — Storage -> Reflection ->
Experience):
  - Store DISTILLED lessons, not raw trajectories (no log bloat).
  - DEDUPE: identical lessons merge and gain support instead of piling up.
  - DECAY + PRUNE: utility decays; when over capacity the least useful lessons are
    forgotten ("learn what not to forget"). The store stays small and high-signal.
  - Reflection is DETERMINISTIC here (derived from audit events + findings), so lessons
    are never hallucinated. LLM-distilled reflection is a later upgrade.

Backend is pluggable (`Backend`): a local JSON file today, HelixDB (graph+vector) later —
the agent code never changes when the backend does.
"""

from __future__ import annotations

import datetime as _dt
import json
import re
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Protocol

SUCCESS, FAILURE, CAUTION = "success", "failure", "caution"


def _now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).isoformat()


@dataclass
class Lesson:
    text: str
    kind: str                       # success | failure | caution
    tags: list[str] = field(default_factory=list)
    utility: float = 1.0            # reinforced when it helps, decayed over time
    uses: int = 0                   # times recalled
    helped: int = 0                 # times it was recalled in a run that then confirmed a finding
    support: int = 1                # how many runs corroborated it
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    created: str = field(default_factory=_now)
    last_used: str = field(default_factory=_now)

    @property
    def signature(self) -> str:
        return self.kind + "|" + ",".join(sorted(self.tags))


class Backend(Protocol):
    def load(self) -> list[dict]: ...
    def save(self, rows: list[dict]) -> None: ...


class LocalJSONBackend:
    def __init__(self, path: str | Path):
        self._path = Path(path)

    def load(self) -> list[dict]:
        if not self._path.exists():
            return []
        try:
            return json.loads(self._path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return []

    def save(self, rows: list[dict]) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._path.write_text(json.dumps(rows, indent=2, ensure_ascii=False), encoding="utf-8")


class ExperienceStore:
    def __init__(self, path: str | Path | None = None, backend: Backend | None = None,
                 max_lessons: int = 200, decay: float = 0.98, floor: float = 0.15):
        self._backend = backend or (LocalJSONBackend(path) if path else None)
        self._max = max_lessons
        self._decay = decay
        self._floor = floor                 # forget lessons whose utility falls below this
        self._last_recall: list[str] = []   # ids recalled in the current run, for crediting
        self._lessons: dict[str, Lesson] = {}
        if self._backend:
            for row in self._backend.load():
                les = Lesson(**row)
                self._lessons[les.id] = les

    # -- write ----------------------------------------------------------------

    def learn(self, text: str, kind: str, tags: list[str] | None = None) -> Lesson:
        """Add a distilled lesson. Merges with an existing one of the same signature
        (kind + tags) instead of duplicating, reinforcing its support/utility."""
        tags = sorted(set(t.lower() for t in (tags or [])))
        new = Lesson(text=text.strip(), kind=kind, tags=tags)
        for les in self._lessons.values():
            if les.signature == new.signature:
                les.support += 1
                les.utility += 0.5           # corroboration strengthens it
                les.last_used = _now()
                if len(text) < len(les.text):  # prefer the tighter phrasing
                    les.text = text.strip()
                self._flush()
                return les
        self._lessons[new.id] = new
        self._prune()
        self._flush()
        return new

    def reflect_on_run(self, findings: list, audit_events: list[dict]) -> list[Lesson]:
        """Distill a few generalizable lessons from a completed run (deterministic)."""
        learned: list[Lesson] = []

        # Successes: confirmed findings -> the class/tool that worked.
        for f in findings:
            conf = getattr(f, "confidence", None) or (f.get("confidence") if isinstance(f, dict) else None)
            if conf != "confirmed":
                continue
            cwe = (getattr(f, "cwe", None) or (f.get("cwe") if isinstance(f, dict) else "") or "").upper()
            if cwe:
                learned.append(self.learn(
                    f"{cwe} is confirmable on this kind of target — prioritize probing it and "
                    f"prove it with a reproducing check.", SUCCESS, tags=[cwe.lower(), "confirmed"]))

        # Failures: a class whose proofs kept getting rejected -> refine, don't repeat.
        rejected: dict[str, int] = {}
        for e in audit_events:
            if e.get("event") in ("verify_vuln.result", "confirm.result", "idor.result",
                                  "access_control.result") and e.get("verdict") not in (None, "confirmed"):
                cwe = (e.get("cwe") or "").upper()
                if cwe:                     # only keep per-class lessons; skip label-less noise
                    rejected[cwe] = rejected.get(cwe, 0) + 1
        for cwe, n in rejected.items():
            if n >= 3:
                learned.append(self.learn(
                    f"Proof attempts for {cwe} failed to reproduce {n}x in a run — refine the "
                    f"oracle/approach before recording; do not brute-repeat the same proof.",
                    FAILURE, tags=[cwe.lower()]))

        # Cautions: repeat-blocked tools -> pivot instead of retrying.
        blocked: dict[str, int] = {}
        for e in audit_events:
            if e.get("event") == "agent.repeat_blocked":
                t = e.get("tool", "?")
                blocked[t] = blocked.get(t, 0) + 1
        for tool, n in blocked.items():
            if n >= 1:
                learned.append(self.learn(
                    f"'{tool}' was repeat-blocked ({n}x) — identical failing calls waste turns; "
                    f"change inputs or pivot to another technique.", CAUTION, tags=[f"tool:{tool}"]))
        return learned

    # -- read -----------------------------------------------------------------

    def recall(self, query: str = "", tags: list[str] | None = None, k: int = 5) -> list[Lesson]:
        """Return the k most relevant lessons; reinforces the ones actually recalled."""
        want_tags = set(t.lower() for t in (tags or []))
        words = set(re.findall(r"[a-z0-9]+", (query or "").lower()))

        def score(les: Lesson) -> float:
            tag_overlap = len(want_tags & set(les.tags))
            kw = len(words & set(re.findall(r"[a-z0-9]+", les.text.lower())))
            return les.utility + 2.0 * tag_overlap + 0.3 * kw

        ranked = sorted(self._lessons.values(), key=score, reverse=True)[:k]
        for les in ranked:
            les.uses += 1
            les.last_used = _now()
        self._last_recall = [les.id for les in ranked]
        if ranked:
            self._flush()
        return ranked

    def credit(self, helpful: bool) -> None:
        """After a run, reward the lessons that were recalled if the run was productive
        (confirmed a finding), and mildly penalize them if it wasn't. Then forget lessons
        that have decayed below the utility floor. This keeps the DB filled only with
        lessons that actually help — not everything the agent ever saw."""
        for lid in self._last_recall:
            les = self._lessons.get(lid)
            if les is None:
                continue
            if helpful:
                les.helped += 1
                les.utility += 0.6
            else:
                les.utility -= 0.3
        self._last_recall = []
        self._forget_unhelpful()
        self._flush()

    def _forget_unhelpful(self) -> None:
        drop = [lid for lid, l in self._lessons.items() if l.utility < self._floor]
        for lid in drop:
            del self._lessons[lid]

    def briefing(self, query: str = "", tags: list[str] | None = None, k: int = 5) -> str:
        lessons = self.recall(query=query, tags=tags, k=k)
        if not lessons:
            return ""
        lines = ["[LESSONS FROM PAST ENGAGEMENTS]"]
        for les in lessons:
            lines.append(f"  ({les.kind}) {les.text}")
        return "\n".join(lines)

    def all(self) -> list[Lesson]:
        return sorted(self._lessons.values(), key=lambda l: l.utility, reverse=True)

    def summary(self) -> dict:
        by_kind: dict[str, int] = {}
        for l in self._lessons.values():
            by_kind[l.kind] = by_kind.get(l.kind, 0) + 1
        return {"lessons": len(self._lessons), "by_kind": by_kind, "cap": self._max}

    # -- maintenance ----------------------------------------------------------

    def _prune(self) -> None:
        # Decay everything slightly, then forget the least useful beyond capacity.
        for les in self._lessons.values():
            les.utility *= self._decay
        if len(self._lessons) > self._max:
            keep = sorted(self._lessons.values(), key=lambda l: l.utility, reverse=True)[:self._max]
            self._lessons = {l.id: l for l in keep}

    def _flush(self) -> None:
        if self._backend:
            self._backend.save([asdict(l) for l in self._lessons.values()])


# Curated, generalizable tradecraft — institutional knowledge to bootstrap the store so
# the agent starts with correct *prescriptive* how-to-prove recipes, not just diagnostics.
# These encode the oracle designs we learned through benchmarking. Seeding is idempotent
# (learn() dedupes by signature).
DEFAULT_TRADECRAFT = [
    (SUCCESS, ["cwe-639", "idor"],
     "To PROVE IDOR: authenticate as one user, then verify_vulnerability with two requests "
     "(baseline = your own object id, payload = another id) and conditions [status==200 on "
     "payload] AND [json_differs on the id/owner field]. Never use a static marker — you "
     "cannot know the victim's data in advance."),
    (SUCCESS, ["cwe-79", "xss"],
     "To PROVE reflected XSS: send a unique token like <rtx931> in a reflected parameter, "
     "then verify_vulnerability with a [reflected_unescaped] condition on that token. If it "
     "returns HTML-escaped (&lt;rtx931&gt;), it is NOT vulnerable — do not record it."),
    (SUCCESS, ["cwe-284", "access-control"],
     "To PROVE broken access control: request the protected URL with NO auth (empty headers) "
     "and assert [status==200] AND [body_regex for protected content] via verify_vulnerability. "
     "If unauth is denied (401/403), it is enforced — not a finding."),
    (SUCCESS, ["cwe-89", "auth"],
     "If a login endpoint is SQL-injectable, authenticate with the injection payload itself "
     "(email \"' OR 1=1--\") to bypass auth, rather than guessing credentials."),
    (SUCCESS, ["cwe-89", "blind"],
     "For blind/second-order SQLi, prove it with a differential latency check (baseline vs a "
     "SLEEP payload, min_delta ~4s), not error text — error text can be planted."),
    (CAUTION, ["hygiene", "no-recon-findings"],
     "Only record CONFIRMED vulnerabilities. Never record info-level recon (endpoints, tech) "
     "as findings — that inflates false positives."),
    (CAUTION, ["hygiene", "no-repeat"],
     "If a proof rejects, change the oracle or inputs — never brute-repeat the same failing "
     "call; it wastes turns and the guard will block it."),
]


def seed_tradecraft(store: ExperienceStore) -> int:
    """Bootstrap the store with curated tradecraft (idempotent). Returns lessons added."""
    before = len(store.all())
    for kind, tags, text in DEFAULT_TRADECRAFT:
        store.learn(text, kind, tags=tags)
    return len(store.all()) - before
