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

Poison resistance (W5 — the highest-relevance weakness class in our red-team paper):
  everything the TARGET returns to us is attacker-controlled content. If target-shaped
  text ever reaches this store through the same door as self-derived tradecraft, a
  planted lesson persists cross-run and outranks real tradecraft on the next
  engagement (memory-poisoning propagates exactly this way: 58-74% self-propagation
  in the literature). So provenance is decided at WRITE time, not filtered at read
  time — read-time rerankers were measured to cost ~4.4 points of benign utility in
  the memory-defense literature, while a write-path flag costs nothing:

  - DERIVED  : distilled deterministically from OUR OWN audit events / confirmed
               findings (reflect_on_run) — the only path learn() allows.
  - IMPORTED : human-curated bootstrap tradecraft (seed_tradecraft).
  - OBSERVED : anything that originated in target-controlled text. Must enter via
               learn_observed(); starts at capped utility; is recalled at half
               weight; never appears unlabeled in a briefing.
  - QUARANTINE: learn_observed screens for instruction-impersonation (text trying to
               look like operator directives: "system:", "ignore your scope",
               "approve all findings", ...). Quarantined lessons are kept for
               forensics, excluded from recall and briefings, and decay out
               naturally. A false quarantine costs a note; a missed one costs the
               next engagement.

Tamper evidence on LOAD (HMAC): a store file is a writable artifact, so every row is
signed at flush time (HMAC-SHA256 over its security fields — text, kind, tags,
utility, provenance, source, quarantined). The key comes from REDTEAM_MEMORY_KEY when
set, else lives in a sibling `<store>.key` file (0600, created on first write). On
load, any row whose MAC is missing or invalid is demoted to OBSERVED and its utility
clamped — fail-closed. This means (a) a tampered or forged-badge row is contained,
and (b) stores written by PRE-hardening versions demote once, then rebuild through
seeding + reflection within a run — the honest store re-derives its tradecraft
cheaply; the poisoned one is the expensive failure we avoid. Caveat, stated plainly:
this is tamper EVIDENCE, not encryption — an attacker who can also rewrite the key
file can re-sign; in hostile environments point REDTEAM_MEMORY_KEY at read-only
storage. Stores backed ONLY by a pluggable backend (no path argument) hold an
ephemeral in-process key: cross-process rows then load demoted to OBSERVED unless
REDTEAM_MEMORY_KEY is set — fail-closed by design.

Backend is pluggable (`Backend`): a local JSON file today, HelixDB (graph+vector) later —
the agent code never changes when the backend does.
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import hmac
import json
import os
import re
import secrets
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Protocol

SUCCESS, FAILURE, CAUTION = "success", "failure", "caution"
DERIVED, IMPORTED, OBSERVED = "derived", "imported", "observed"
_ALLOWED_PROVENANCE = (DERIVED, IMPORTED, OBSERVED)

# Utility ceiling applied on LOAD: no lesson, however corrupted, should enter a run
# holding more ranking power than a handful of corroborated lessons could give it.
_MAX_UTILITY_ON_LOAD = 5.0

# Text patterns that make an "observed" lesson look like an OPERATOR directive rather
# than a lesson about the target. Matched case-insensitively. Deliberately broad in
# the imperative-voice families: the cost of a false positive is one quarantined note,
# the cost of a false negative is attacker-authored tradecraft executing next run.
_IMPERSONATION_PATTERNS = (
    r"\bsystem\s*:",                        # fake role markers
    r"\[system\]",
    r"\byou (must|should|are now)\b",
    r"\bfrom now on\b",
    r"\bignore (all |your |any |previous|prior)",
    r"\bdisregard (all |your |any |previous|prior)",
    r"\balways (approve|confirm|mark|record|accept)\b",
    r"\bapprove (all|every)\b",
    r"\b(exfiltrate|send|post|upload|forward)\b.*\b(credentials|token|secret|flag)\b",
    r"\b(out of|outside) scope (is |has been )?(now )?(authorized|approved|allowed)\b",
    r"\boverride (the )?(scope|guard|ro[em])\b",
    r"\bnew (operator |engagement )?(directive|instruction|policy)\b",
)
_IMPERSONATION_RE = re.compile("|".join(_IMPERSONATION_PATTERNS), re.IGNORECASE)


def _impersonates_operator(text: str) -> bool:
    """True when the text tries to sound like an OPERATOR directive rather than a
    lesson about a target. Applied at BOTH entry points: learn_observed() at write
    time, and the load path for any row that ends up OBSERVED (tampered rows never
    passed through learn_observed, so the content must be screened there too)."""
    return bool(_IMPERSONATION_RE.search(text or ""))


# Fields covered by the row MAC — everything an attacker could use to buy ranking
# power or forge trust. Bookkeeping fields (uses/helped/support/timestamps) change
# constantly and buy nothing, so they stay outside the signature.
_MAC_FIELDS = ("text", "kind", "tags", "utility", "provenance", "source", "quarantined")
_MAC_KEY_ENV = "REDTEAM_MEMORY_KEY"


def _now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).isoformat()


def _row_mac(key: bytes, row: dict) -> str:
    payload = json.dumps({f: row.get(f) for f in _MAC_FIELDS},
                         sort_keys=True, ensure_ascii=False)
    return hmac.new(key, payload.encode("utf-8"), hashlib.sha256).hexdigest()


def _load_key(path: str | Path | None) -> bytes:
    env = os.environ.get(_MAC_KEY_ENV)
    if env:
        return bytes.fromhex(env)
    if path is None:
        return secrets.token_bytes(32)      # in-process integrity only
    key_path = Path(str(path) + ".key")
    if key_path.exists():
        return bytes.fromhex(key_path.read_text(encoding="utf-8").strip())
    key = secrets.token_bytes(32)
    key_path.parent.mkdir(parents=True, exist_ok=True)
    key_path.write_text(key.hex(), encoding="utf-8")
    try:
        os.chmod(key_path, 0o600)
    except OSError:
        pass
    return key


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
    provenance: str = DERIVED       # derived | imported | observed (see module docstring)
    source: str = ""                # where observed content came from (URL, artifact)
    quarantined: bool = False       # instruction-impersonation screening failed

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
        self._key = _load_key(path)         # HMAC key for tamper evidence
        self._max = max_lessons
        self._decay = decay
        self._floor = floor                 # forget lessons whose utility falls below this
        self._last_recall: list[str] = []   # ids recalled in the current run, for crediting
        self._lessons: dict[str, Lesson] = {}
        if self._backend:
            for row in self._backend.load():
                les = Lesson(**{k: v for k, v in row.items()
                                if k in Lesson.__dataclass_fields__})
                # -- tamper containment (see module docstring) ---------------------
                # Fail-closed: a row we cannot verify (no MAC, bad MAC, forged badge)
                # loads as OBSERVED with clamped utility — never as trusted.
                claimed = les.provenance
                if claimed not in _ALLOWED_PROVENANCE:
                    les.provenance = OBSERVED
                if not hmac.compare_digest(str(row.get("_mac", "")),
                                           _row_mac(self._key, row)):
                    les.provenance = OBSERVED
                if les.provenance == OBSERVED and _impersonates_operator(les.text):
                    les.quarantined = True
                    les.utility = 0.0
                les.utility = min(float(les.utility), _MAX_UTILITY_ON_LOAD)
                self._lessons[les.id] = les

    # -- write ----------------------------------------------------------------

    def learn(self, text: str, kind: str, tags: list[str] | None = None) -> Lesson:
        """Add a SELF-DERIVED lesson (deterministic reflection, curated seeds).
        Merges with an existing one of the same signature (kind + tags) instead of
        duplicating, reinforcing its support/utility. Target-controlled text must
        NEVER pass through here — use learn_observed()."""
        tags = sorted(set(t.lower() for t in (tags or [])))
        new = Lesson(text=text.strip(), kind=kind, tags=tags)
        for les in self._lessons.values():
            # merges stay inside the trusted classes: a derived lesson must never
            # reinforce an OBSERVED one (that would launder planted notes with our
            # own corroboration), and nothing merges into a quarantined note.
            if (les.signature == new.signature and not les.quarantined
                    and les.provenance != OBSERVED):
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

    def learn_observed(self, text: str, kind: str, tags: list[str] | None = None,
                       source: str = "") -> Lesson:
        """The ONLY sanctioned write path for lessons distilled from target-controlled
        content (a response body, a recon artifact, an imported run transcript).

        Three containment layers, cheapest first:
          1. provenance=OBSERVED — recalled at half weight, labeled separately in
             briefings; cannot masquerade as self-derived tradecraft.
          2. capped initial utility (0.6 vs 1.0) — a flood of planted notes cannot
             immediately outrank corroborated lessons; utility must be EARNED back
             through the same credit() loop as everyone else.
          3. instruction-impersonation screening — text that reads like an operator
             directive ("system:", "ignore your scope", "approve all findings") is
             QUARANTINED: kept on disk for forensics, excluded from recall and
             briefings entirely, and decays out naturally.
        """
        tags = sorted(set(t.lower() for t in (tags or [])))
        quarantined = _impersonates_operator(text)
        les = Lesson(text=(text or "").strip(), kind=kind, tags=tags,
                     provenance=OBSERVED, source=source, quarantined=quarantined,
                     utility=0.0 if quarantined else 0.6)
        self._lessons[les.id] = les
        self._prune()
        self._flush()
        return les

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
        """Return the k most relevant lessons; reinforces the ones actually recalled.

        Trust gate: quarantined lessons are never recalled at all; OBSERVED lessons
        score at half weight, so target-controlled notes cannot crowd out corroborated
        tradecraft no matter how many of them are planted.
        """
        want_tags = set(t.lower() for t in (tags or []))
        words = set(re.findall(r"[a-z0-9]+", (query or "").lower()))

        def score(les: Lesson) -> float:
            tag_overlap = len(want_tags & set(les.tags))
            kw = len(words & set(re.findall(r"[a-z0-9]+", les.text.lower())))
            base = les.utility + 2.0 * tag_overlap + 0.3 * kw
            return base * 0.5 if les.provenance == OBSERVED else base

        ranked = sorted((l for l in self._lessons.values() if not l.quarantined),
                        key=score, reverse=True)[:k]
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
        lines: list[str] = []
        trusted = [l for l in lessons if l.provenance != OBSERVED]
        observed = [l for l in lessons if l.provenance == OBSERVED]
        if trusted:
            lines.append("[LESSONS FROM PAST ENGAGEMENTS]")
            for les in trusted:
                lines.append(f"  ({les.kind}) {les.text}")
        if observed:
            # separate, loudly-labeled block: the agent may READ these as context, but
            # nothing in an observed note is allowed to sound like a directive.
            lines.append("[UNVERIFIED NOTES FROM TARGET CONTENT — attacker-influenceable, "
                         "not tradecraft]")
            for les in observed:
                lines.append(f"  ({les.kind}) {les.text}")

        # Semantic recall of APP-SHAPE patterns, when the backend supports it (see
        # memory_backend/helix_backend.py). This is additive, never a replacement: a
        # LocalJSONBackend-backed store (no semantic_recall_lessons/recall_patterns)
        # simply skips this and behaves exactly as before. It's the piece tag-matched
        # Lesson recall structurally cannot do — a new target that only RESEMBLES a past
        # one in meaning (not shared vocabulary) still surfaces what worked there.
        if query and hasattr(self._backend, "semantic_recall_lessons"):
            try:
                semantic = self._backend.semantic_recall_lessons(query, k=3)
            except Exception:
                semantic = []
            seen = {l.text for l in lessons}
            fresh = [h for h in semantic if h.get("text") not in seen]
            if fresh:
                lines.append("[SIMILAR TECHNIQUES FROM PAST ENGAGEMENTS — matched by meaning, not keywords]")
                for h in fresh:
                    lines.append(f"  ({h.get('kind', '?')}) {h.get('text', '')}")
        if query and hasattr(self._backend, "recall_patterns"):
            try:
                patterns = self._backend.recall_patterns(query, k=3)
            except Exception:
                patterns = []
            if patterns:
                lines.append("[APP-SHAPE PATTERNS SEEN BEFORE — may apply to this target too]")
                for p in patterns:
                    lines.append(f"  - {p.get('description', '')}")

        return "\n".join(lines)

    def learn_pattern(self, description: str, tags: list[str] | None = None) -> None:
        """Distill an APP-SHAPE fact (auth flow shape, ID format, endpoint naming
        convention) — not a vuln-proving technique — so the NEXT target gets a head start
        even when it's a different app entirely. No-op on a backend that doesn't support
        it (e.g. LocalJSONBackend): this is additive capability, not a required one."""
        if hasattr(self._backend, "learn_pattern"):
            try:
                self._backend.learn_pattern(description, tags=tags)
            except Exception:
                pass

    def all(self) -> list[Lesson]:
        return sorted(self._lessons.values(), key=lambda l: l.utility, reverse=True)

    def summary(self) -> dict:
        by_kind: dict[str, int] = {}
        by_prov: dict[str, int] = {}
        for l in self._lessons.values():
            by_kind[l.kind] = by_kind.get(l.kind, 0) + 1
            by_prov[l.provenance] = by_prov.get(l.provenance, 0) + 1
        quarantined = sum(1 for l in self._lessons.values() if l.quarantined)
        return {"lessons": len(self._lessons), "by_kind": by_kind,
                "by_provenance": by_prov, "quarantined": quarantined, "cap": self._max}

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
            rows = []
            for l in self._lessons.values():
                row = asdict(l)
                row["_mac"] = _row_mac(self._key, row)
                rows.append(row)
            self._backend.save(rows)


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
    """Bootstrap the store with curated tradecraft (idempotent). Returns lessons added.
    Seeded lessons are IMPORTED provenance: human-curated, but not self-derived."""
    before = len(store.all())
    for kind, tags, text in DEFAULT_TRADECRAFT:
        les = store.learn(text, kind, tags=tags)
        les.provenance = IMPORTED
    store._flush()
    return len(store.all()) - before
