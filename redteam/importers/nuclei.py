"""Import nuclei templates as executable skills.

Nuclei's 9,000+ community YAML templates are, structurally, exactly what our skill library
stores: **a request plus matcher conditions**. That makes them pre-built, community-vetted
skills — instead of the agent learning each detection from scratch, we import thousands of
proven ones and let it `apply_skill` them.

Faithfulness rules (deliberately conservative, because our whole edge is low false
positives):
  - Only single-request HTTP templates are imported.
  - Only AND semantics. Nuclei's *default* matchers-condition is OR, so we import a
    template only when it has exactly one matcher, or `matchers-condition: and`.
    Multi-matcher OR templates are skipped rather than mis-imported.
  - Only matcher types we can represent exactly: status, word, regex (body or header).
    `dsl` and `binary` matchers are skipped.
  - `negative: true` maps to our `present: false`.
  - Multiple words/regexes inside ONE matcher use that matcher's own `condition`
    (and -> separate conditions; or -> a single regex alternation), which is exact.

Anything we cannot represent exactly is skipped and counted, never approximated.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

import yaml

TARGET = "target_url"          # the one placeholder every imported skill takes
_BASEURL = re.compile(r"\{\{\s*BaseURL\s*\}\}", re.IGNORECASE)
# Nuclei templates may use other {{...}} helpers we cannot evaluate.
_OTHER_VAR = re.compile(r"\{\{(?!\s*BaseURL\s*\}\})[^}]+\}\}")


@dataclass
class ImportStats:
    imported: int = 0
    skipped: int = 0
    reasons: dict = None

    def skip(self, reason: str) -> None:
        self.skipped += 1
        self.reasons = self.reasons or {}
        self.reasons[reason] = self.reasons.get(reason, 0) + 1


def _alternation(values: list[str], as_regex: bool) -> str:
    parts = [v if as_regex else re.escape(str(v)) for v in values]
    return parts[0] if len(parts) == 1 else "(?:" + "|".join(parts) + ")"


def _matcher_to_conditions(m: dict) -> list[dict] | None:
    """Convert one nuclei matcher to our condition(s). None = unrepresentable."""
    mtype = (m.get("type") or "").lower()
    part = (m.get("part") or "body").lower()
    negative = bool(m.get("negative"))
    inner = (m.get("condition") or "or").lower()   # nuclei default inside a matcher is OR

    if mtype == "status":
        codes = m.get("status") or []
        if len(codes) != 1 or negative:
            return None                            # multi-status is OR; we don't fake it
        return [{"type": "status", "request": "payload", "equals": int(codes[0])}]

    if mtype in ("word", "regex"):
        values = m.get("words" if mtype == "word" else "regex") or []
        if not values:
            return None
        as_regex = (mtype == "regex")
        if part in ("body", "all", "response", ""):
            ctype = "body_regex"
        elif part == "header":
            ctype = "header_regex"
        else:
            return None                            # e.g. part: interactsh — unsupported
        if inner == "and":
            return [{"type": ctype, "request": "payload",
                     "pattern": v if as_regex else re.escape(str(v)),
                     "present": not negative} for v in values]
        return [{"type": ctype, "request": "payload",
                 "pattern": _alternation(values, as_regex), "present": not negative}]

    return None                                    # dsl, binary, etc.


def parse_template(doc: dict) -> tuple[dict, list[dict], str, str, str] | None:
    """Return (requests, conditions, name, description, cwe) or None if unrepresentable."""
    if not isinstance(doc, dict):
        return None
    http = doc.get("http") or doc.get("requests")
    if not isinstance(http, list) or len(http) != 1:
        return None
    req = http[0]
    if not isinstance(req, dict) or req.get("raw"):
        return None                                # raw requests: not supported

    paths = req.get("path") or []
    if isinstance(paths, str):
        paths = [paths]
    if len(paths) != 1:
        return None                                # multi-path templates are implicit OR
    path = paths[0]
    if _OTHER_VAR.search(_BASEURL.sub("", path)):
        return None                                # uses helpers/variables we can't resolve
    url = _BASEURL.sub("{{%s}}" % TARGET, path)
    if "{{%s}}" % TARGET not in url:
        return None                                # not anchored to the target

    matchers = req.get("matchers") or []
    if not matchers:
        return None
    cond_mode = (req.get("matchers-condition") or "or").lower()
    if len(matchers) > 1 and cond_mode != "and":
        return None                                # OR across matchers: skip, don't fake it

    conditions: list[dict] = []
    for m in matchers:
        got = _matcher_to_conditions(m)
        if got is None:
            return None
        conditions.extend(got)

    info = doc.get("info") or {}
    name = str(info.get("name") or doc.get("id") or "nuclei template")
    sev = str(info.get("severity") or "info")
    desc = str(info.get("description") or name).strip()[:200]
    classification = info.get("classification") or {}
    cwe_raw = classification.get("cwe-id") or ""
    if isinstance(cwe_raw, list):
        cwe_raw = cwe_raw[0] if cwe_raw else ""
    cwe = str(cwe_raw).upper() if cwe_raw else ""

    requests = {"payload": {"method": (req.get("method") or "GET").upper(), "url": url}}
    if req.get("headers"):
        requests["payload"]["headers"] = req["headers"]
    if req.get("body"):
        requests["payload"]["body"] = req["body"]
    return requests, conditions, name, f"[{sev}] {desc}", cwe


def import_file(path: Path, library, source: str = "nuclei", flush: bool = True) -> bool:
    try:
        doc = yaml.safe_load(path.read_text(encoding="utf-8", errors="ignore"))
    except (yaml.YAMLError, OSError, UnicodeDecodeError):
        return False
    try:
        parsed = parse_template(doc)
    except Exception:
        return False
    if parsed is None:
        return False
    requests, conditions, name, desc, cwe = parsed
    library.register(name=name, description=desc, requests=requests, conditions=conditions,
                     params=[TARGET], cwe=cwe, source=source, flush=flush)
    return True


def import_directory(directory: str | Path, library, limit: int | None = None) -> ImportStats:
    """Walk a nuclei-templates checkout and import every faithfully-representable template."""
    stats = ImportStats(reasons={})
    root = Path(directory)
    for path in sorted(root.rglob("*.yaml")):
        if limit is not None and stats.imported >= limit:
            break
        if import_file(path, library, flush=False):   # batch: one write at the end
            stats.imported += 1
        else:
            stats.skip("unrepresentable")
    library.flush()
    return stats
