"""Just-in-time attack research — the agent looks things up instead of memorizing them.

A human pentester does not download 11,000 signatures for every target. They fingerprint
what they are looking at, *research* what is relevant to THAT stack, try a few candidates,
and remember only what worked. Bulk-importing a template corpus into our skill DB just
rebuilds a generic scanner and bloats storage with signatures we will never fire.

So the corpus stays on disk as a *reference library* (nothing stored in our DB), and the
agent gets two tools:

  find_attack_templates(query)  -> research: search the corpus for what fits this target
  apply_template(ref, target)   -> probe: run one candidate through the full verifier
                                   (k-of-n + negative control) and record only if proven

A template that actually confirms on a real target is then promoted into the persistent
skill library — so the DB fills with *earned* skills, not downloaded signatures.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from ..falsify import FALSIFIED, run_negative_control
from ..findings import Finding
from ..importers.nuclei import TARGET, parse_template
from ..knowledge import ENDPOINT
from ..proof import ProofCheck
from ..scope import ScopeViolation
from ..skills import substitute
from ..verify import verify
from . import ToolContext
from .http import make_fetch

DEFAULT_CORPUS = "data/nuclei-templates/http"
_WORD = re.compile(r"[a-z0-9]+")


def _tokens(text: str) -> set[str]:
    return set(_WORD.findall((text or "").lower()))


def _corpus_root(ctx: ToolContext) -> Path:
    return Path(getattr(ctx, "template_corpus", None) or DEFAULT_CORPUS)


# Cached per corpus root: the path list plus token document-frequencies for IDF weighting.
_INDEX_CACHE: dict[str, tuple[list[tuple[Path, set[str]]], dict[str, int]]] = {}


def _catalog_path(root: Path) -> Path:
    return root.parent / ".rt_template_catalog.json"


def _build_catalog(root: Path) -> list[dict]:
    """One-time catalog of the corpus: id/name/tags per template.

    This is a library CATALOG, not a skill database. Many templates (CVEs especially) are
    filed as cves/2021/CVE-2021-26086.yaml, so the product name ('jira') exists only inside
    the YAML. Without indexing names/tags, the agent literally cannot find them by name.
    We store only a search key per file — never the template bodies."""
    import yaml
    rows = []
    for path in root.rglob("*.yaml"):
        name = tags = tid = ""
        try:
            doc = yaml.safe_load(path.read_text(encoding="utf-8", errors="ignore"))
            if isinstance(doc, dict):
                info = doc.get("info") or {}
                tid = str(doc.get("id") or "")
                name = str(info.get("name") or "")
                t = info.get("tags") or ""
                tags = ",".join(t) if isinstance(t, list) else str(t)
        except Exception:
            pass
        rows.append({"p": str(path), "n": name, "t": tags, "i": tid})
    return rows


def _corpus_index(root: Path):
    key = str(root.resolve())
    cached = _INDEX_CACHE.get(key)
    if cached is not None:
        return cached

    cat_file = _catalog_path(root)
    rows = None
    if cat_file.exists():
        try:
            rows = json.loads(cat_file.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            rows = None
    if rows is None:
        rows = _build_catalog(root)
        try:
            cat_file.write_text(json.dumps(rows), encoding="utf-8")
        except OSError:
            pass

    entries: list[tuple[Path, set[str]]] = []
    df: dict[str, int] = {}
    docs: list[str] = []
    for r in rows:
        path = Path(r["p"])
        text = (path.stem.replace("-", " ").replace("_", " ") + " " + path.parent.name
                + " " + r.get("n", "") + " " + r.get("t", "").replace(",", " ")
                + " " + r.get("i", "").replace("-", " "))
        docs.append(text)
        toks = _tokens(text)
        entries.append((path, toks))
        for t in toks:
            df[t] = df.get(t, 0) + 1

    # Semantic index: built in memory on first use, never written to disk.
    index = None
    try:
        from ..retrieval import build_index
        index = build_index(docs)
    except Exception:
        index = None

    _INDEX_CACHE[key] = (entries, df, index)
    return entries, df, index


def _search(root: Path, query: str, limit: int) -> list[dict]:
    """Two-stage search: IDF-weighted path ranking, then parse only the best candidates.

    IDF matters a lot here: without it, generic tokens ('config', 'exposure', 'disclosure')
    dominate and you get whatever shares those words. Weighting by rarity makes the
    distinctive term ('git', 'jira', 'wordpress') drive the match, which is what the agent
    actually meant."""
    q = _tokens(query)
    if not q:
        return []
    entries, df, index = _corpus_index(root)
    total = max(len(entries), 1)

    import math
    # Anchor term: the most distinctive word in the query (a product/tech/CVE name) acts as
    # a hard filter, the way a human researcher does it — "grafana path traversal" means
    # Grafana templates, not every path traversal. Without this, two mid-rare words
    # ("path"+"traversal") outscore one rare word ("grafana") and swamp the results.
    present = {t: df.get(t, 0) for t in q if df.get(t, 0) > 0}
    anchor = None
    if present:
        candidate, cdf = min(present.items(), key=lambda kv: kv[1])
        if cdf <= max(20, int(total * 0.01)):      # genuinely distinctive
            anchor = candidate

    lexical: list[float] = []
    for _, toks in entries:
        if anchor is not None and anchor not in toks:
            lexical.append(0.0)                     # filtered out by the anchor
            continue
        hits = q & toks
        # Smoothed IDF: rare, specific terms count far more. The +1 terms keep this strictly
        # positive — a raw log(total/(1+df)) goes negative on small corpora, which silently
        # inverted the ranking and made the anchor filter discard valid matches.
        lexical.append(sum(math.log((total + 1) / (1 + df.get(t, 0))) + 1.0 for t in hits)
                       if hits else 0.0)

    sem = index.similarities(query) if (index is not None and index.ready) else None

    # Hybrid, lexical-dominant. In security an exact rare term ("grafana", "CVE-2021-43798")
    # is a near-requirement, so semantics only ASSIST: it ranks among lexical matches and
    # surfaces near-misses, but must never outrank a strong exact-term hit. Weighting it
    # heavily made "confluence rce" return OpenCPU — the product name is the signal.
    lex_max = max(lexical) or 1.0
    scored: list[tuple[float, Path]] = []
    for i, (path, _) in enumerate(entries):
        if anchor is not None and lexical[i] <= 0:
            continue                                # anchored search: skip non-matches
        score = lexical[i] / lex_max
        if sem is not None:
            score += 0.3 * max(sem[i], 0.0)
        if score > 0:
            scored.append((score, path))
    scored.sort(key=lambda t: -t[0])

    out: list[dict] = []
    for _, path in scored[: limit * 20]:          # parse only a shortlist
        parsed = None
        try:
            import yaml
            doc = yaml.safe_load(path.read_text(encoding="utf-8", errors="ignore"))
            parsed = parse_template(doc)
        except Exception:
            parsed = None
        if parsed is None:
            continue                              # not faithfully representable -> skip
        requests, conditions, name, desc, cwe = parsed
        out.append({"ref": str(path), "name": name, "description": desc, "cwe": cwe,
                    "conditions": len(conditions), "params": [TARGET]})
        if len(out) >= limit:
            break
    return out


class FindAttackTemplatesTool:
    name = "find_attack_templates"

    def schema(self) -> dict:
        return {
            "name": self.name,
            "description": (
                "RESEARCH step: search a local corpus of community attack/detection templates "
                "for ones relevant to THIS target. Fingerprint the target first (technology, "
                "product, version, framework, exposed paths), then query with those terms "
                "(e.g. 'jira lfi', 'wordpress plugin sqli', 'git config exposure'). Returns a "
                "few candidates with a 'ref' you pass to apply_template. Nothing is stored "
                "until a candidate is actually proven on the target."
            ),
            "input_schema": {
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    "query": {"type": "string",
                              "description": "Target-specific terms: product, tech, version, or vuln class."},
                    "limit": {"type": "integer", "description": "Max candidates (default 5)."},
                },
                "required": ["query"],
            },
            "strict": True,
        }

    def run(self, ctx: ToolContext, query: str, limit: int = 5) -> str:
        root = _corpus_root(ctx)
        if not root.exists():
            return (f"No template corpus at {root}. This tool is optional; continue with "
                    f"your own probes via verify_vulnerability.")
        limit = max(1, min(int(limit), 10))
        results = _search(root, query, limit)
        ctx.audit.record("template.search", query=query, results=len(results))
        if not results:
            return json.dumps({"results": [], "note": "nothing relevant; refine the query "
                                                      "with the target's actual technology."})
        return json.dumps({"results": results}, ensure_ascii=False)


class ApplyTemplateTool:
    name = "apply_template"

    def schema(self) -> dict:
        return {
            "name": self.name,
            "description": (
                "PROBE step: run one researched template (its 'ref' from find_attack_templates) "
                "against an in-scope target URL. It goes through the same verification as any "
                "finding (k-of-n reproduction plus an optional negative control), and is only "
                "recorded if proven. A template that confirms is promoted into your permanent "
                "skill library so it can be reused directly next time."
            ),
            "input_schema": {
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    "ref": {"type": "string", "description": "The template ref from find_attack_templates."},
                    "target_url": {"type": "string", "description": "Base URL of the in-scope target."},
                    "severity": {"type": "string",
                                 "enum": ["info", "low", "medium", "high", "critical"]},
                    "negative_control": {"type": "object",
                                         "description": "Optional benign control request (recommended)."},
                    "trials": {"type": "integer"},
                    "need": {"type": "integer"},
                },
                "required": ["ref", "target_url"],
            },
            "strict": True,
        }

    def run(self, ctx: ToolContext, ref: str, target_url: str, severity: str = "medium",
            negative_control: dict | None = None, trials: int = 3, need: int = 3) -> str:
        path = Path(ref)
        root = _corpus_root(ctx).resolve()
        try:
            if not path.resolve().is_relative_to(root):
                return "ERROR: ref must point inside the template corpus."
        except (OSError, ValueError):
            return "ERROR: invalid template ref."
        if not path.exists():
            return f"ERROR: template not found: {ref}"

        try:
            import yaml
            parsed = parse_template(yaml.safe_load(path.read_text(encoding="utf-8", errors="ignore")))
        except Exception as exc:
            return f"ERROR parsing template: {exc}"
        if parsed is None:
            return "ERROR: this template cannot be represented faithfully; pick another."
        requests_t, conditions, name, desc, cwe = parsed

        trials = max(1, min(int(trials), 10)); need = max(1, min(int(need), trials))
        try:
            concrete = substitute(requests_t, {TARGET: target_url.rstrip("/")})
        except KeyError as exc:
            return f"ERROR: {exc}"

        fetchers = {}
        try:
            for rname, spec in concrete.items():
                fetchers[rname] = make_fetch(ctx, {"method": spec.get("method", "GET"),
                                                   "url": spec["url"],
                                                   "headers": spec.get("headers"),
                                                   "body": spec.get("body")})
        except ScopeViolation as exc:
            return f"BLOCKED (out of scope): {exc}"

        try:
            result = verify(ProofCheck(fetchers, conditions), trials=trials, need=need)
        except Exception as exc:
            return f"ERROR running template: {exc}"
        ctx.audit.record("template.apply", ref=ref, name=name, verdict=result.verdict)

        if result.verdict != "confirmed":
            return json.dumps({"verdict": result.verdict, "recorded": False,
                               "note": "target is not affected by this template — move on."})

        control_note = "no negative control supplied (weaker evidence)"
        if negative_control:
            try:
                fal = run_negative_control(
                    fetchers, conditions,
                    make_fetch(ctx, {"method": negative_control.get("method", "GET"),
                                     "url": negative_control["url"],
                                     "headers": negative_control.get("headers"),
                                     "body": negative_control.get("body")}), "payload")
            except (ScopeViolation, KeyError) as exc:
                return f"BLOCKED/ERROR building negative control: {exc}"
            if fal.falsified:
                return json.dumps({"verdict": FALSIFIED, "recorded": False, "detail": fal.detail})
            control_note = fal.detail

        f = ctx.findings.add(Finding(
            title=name, severity=severity, target=target_url, summary=desc,
            evidence="\n".join(result.details) + "\nControl: " + control_note,
            cwe=cwe, confidence="confirmed", verification_verdict=result.verdict,
            reproductions=result.reproductions, trials=result.trials,
            poc=f"template {path.name} applied to {target_url}"))
        if ctx.graph is not None:
            ctx.graph.observe(ENDPOINT, target_url, attrs={"finding": name}, source="apply_template")

        # Earned, not downloaded: only a template that actually proved out is persisted.
        skill_id = None
        if ctx.skills is not None:
            try:
                s = ctx.skills.register(name=name, description=desc, requests=requests_t,
                                        conditions=conditions, params=[TARGET], cwe=cwe,
                                        source="proven-template")
                skill_id = s.id
                ctx.audit.record("skill.promoted", skill_id=s.id, name=name)
            except Exception:
                pass
        return json.dumps({"verdict": "confirmed", "recorded": True, "finding_id": f.id,
                           "skill_saved": skill_id, "control": control_note})
