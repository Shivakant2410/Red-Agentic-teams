"""Executable skill library — proven proofs stored as CODE, not advice.

The Voyager result we're adopting: "Skills are stored as code, not as natural-language
descriptions. Retrieval is by embedding similarity over the description, but execution is
deterministic code." Our run-9 failure was exactly the wrong shape — we gave the model a
text recipe for proving IDOR and it still had to *re-derive* a working proof, which a weak
model cannot do reliably.

Here, when a proof is CONFIRMED, we persist the working spec (requests + conditions) as a
parameterized template. Next time the agent doesn't design a proof — it picks a skill and
supplies the URLs. That turns "design a multi-step differential proof" (fails) into "fill
in two parameters" (succeeds).

Skills enter the library only on verified success, per Voyager's gating rule.
"""

from __future__ import annotations

import copy
import datetime as _dt
import json
import re
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path

_PLACEHOLDER = re.compile(r"\{\{(\w+)\}\}")


def _now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).isoformat()


@dataclass
class Skill:
    name: str
    description: str                 # for retrieval
    cwe: str = ""
    requests: dict = field(default_factory=dict)    # parameterized request specs
    conditions: list = field(default_factory=list)  # verbatim proof conditions
    params: list = field(default_factory=list)      # placeholder names to fill
    source: str = "learned"                         # learned | nuclei | imported
    successes: int = 1
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    created: str = field(default_factory=_now)
    last_used: str = field(default_factory=_now)


def parameterize(requests: dict) -> tuple[dict, list[str]]:
    """Replace concrete urls/bodies with placeholders so the proof is reusable."""
    tmpl = copy.deepcopy(requests)
    params: list[str] = []
    for name, spec in tmpl.items():
        if isinstance(spec, dict):
            if spec.get("url"):
                key = f"{name}_url"
                spec["url"] = "{{%s}}" % key
                params.append(key)
            if spec.get("body"):
                key = f"{name}_body"
                spec["body"] = "{{%s}}" % key
                params.append(key)
    return tmpl, params


def substitute(requests: dict, params: dict) -> dict:
    """Fill a skill template with concrete values."""
    out = copy.deepcopy(requests)
    for name, spec in out.items():
        if not isinstance(spec, dict):
            continue
        for field_name in ("url", "body"):
            val = spec.get(field_name)
            if isinstance(val, str):
                def repl(m):
                    k = m.group(1)
                    if k not in params:
                        raise KeyError(f"missing parameter '{k}'")
                    return str(params[k])
                spec[field_name] = _PLACEHOLDER.sub(repl, val)
    return out


class SkillLibrary:
    def __init__(self, path: str | Path | None = None, max_skills: int = 100):
        self._path = Path(path) if path else None
        self._max = max_skills
        self._skills: dict[str, Skill] = {}
        self._index: dict[str, str] = {}      # signature -> skill id, for O(1) dedupe
        if self._path and self._path.exists():
            try:
                for row in json.loads(self._path.read_text(encoding="utf-8")):
                    s = Skill(**row)
                    self._skills[s.id] = s
                    self._index[self._signature(s.cwe or s.name, s.conditions)] = s.id
            except (json.JSONDecodeError, TypeError):
                pass

    @staticmethod
    def _signature(key: str, conditions: list) -> str:
        return (key or "").lower() + "|" + json.dumps(conditions, sort_keys=True)[:400]

    def flush(self) -> None:
        """Public flush, for callers that batch many inserts (e.g. bulk imports)."""
        self._flush()

    # -- capture ---------------------------------------------------------------

    def capture(self, name: str, description: str, requests: dict, conditions: list,
                cwe: str = "") -> Skill:
        """Persist a CONFIRMED proof as a reusable skill (merges if we already have it)."""
        tmpl, params = parameterize(requests)
        signature = self._signature(cwe or name, conditions)
        existing_id = self._index.get(signature)
        if existing_id and existing_id in self._skills:
            s = self._skills[existing_id]
            s.successes += 1
            s.last_used = _now()
            self._flush()
            return s
        skill = Skill(name=name, description=description, cwe=cwe,
                      requests=tmpl, conditions=conditions, params=params)
        self._skills[skill.id] = skill
        self._index[signature] = skill.id
        if len(self._skills) > self._max:
            weakest = sorted(self._skills.values(), key=lambda s: s.successes)[0]
            self._index.pop(self._signature(weakest.cwe or weakest.name, weakest.conditions), None)
            del self._skills[weakest.id]
        self._flush()
        return skill

    def register(self, name: str, description: str, requests: dict, conditions: list,
                 params: list[str], cwe: str = "", source: str = "imported",
                 flush: bool = True) -> Skill:
        """Add an ALREADY-parameterized skill (e.g. imported from a nuclei template).

        Unlike capture(), the requests already contain {{placeholders}}, so we store them
        verbatim. Bulk importers pass flush=False and call flush() once at the end."""
        signature = self._signature(name, conditions)
        existing_id = self._index.get(signature)
        if existing_id and existing_id in self._skills:
            return self._skills[existing_id]
        skill = Skill(name=name, description=description, cwe=cwe, requests=requests,
                      conditions=conditions, params=sorted(set(params)), source=source)
        self._skills[skill.id] = skill
        self._index[signature] = skill.id
        if flush:
            self._flush()
        return skill

    # -- retrieve --------------------------------------------------------------

    def get(self, skill_id: str) -> Skill | None:
        return self._skills.get(skill_id)

    def recall(self, query: str = "", cwe: str = "", k: int = 5) -> list[Skill]:
        words = set(re.findall(r"[a-z0-9]+", (query or "").lower()))

        def score(s: Skill) -> float:
            hit = 3.0 if (cwe and s.cwe.lower() == cwe.lower()) else 0.0
            kw = len(words & set(re.findall(r"[a-z0-9]+", (s.description + " " + s.name).lower())))
            return hit + 0.5 * kw + 0.1 * s.successes
        return sorted(self._skills.values(), key=score, reverse=True)[:k]

    def briefing(self, query: str = "", k: int = 4) -> str:
        skills = self.recall(query=query, k=k)
        if not skills:
            return ""
        lines = ["[PROVEN SKILLS — reuse these instead of designing a new proof]",
                 "Call apply_skill(skill_id, params) with the parameters listed."]
        for s in skills:
            lines.append(f"  id={s.id} | {s.name}"
                         f"{' (' + s.cwe + ')' if s.cwe else ''} | worked {s.successes}x")
            lines.append(f"     {s.description}")
            lines.append(f"     params: {', '.join(s.params) or '(none)'}")
        return "\n".join(lines)

    def all(self) -> list[Skill]:
        return sorted(self._skills.values(), key=lambda s: s.successes, reverse=True)

    def summary(self) -> dict:
        return {"skills": len(self._skills)}

    def _flush(self) -> None:
        if not self._path:
            return
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._path.write_text(json.dumps([asdict(s) for s in self._skills.values()],
                                         indent=2, ensure_ascii=False), encoding="utf-8")
