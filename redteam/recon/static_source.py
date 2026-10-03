"""Static source-code recon: when a local copy of the target's source is available
(whitebox engagements, CTF/benchmark challenge directories with compose_dir), read the
route definitions directly instead of paying an LLM to guess them by probing. This is
strictly free — no network call, no token cost — and exact where guessing is probabilistic.

Covers the frameworks actually seen in this codebase's benchmark fleet: Flask/FastAPI
(Python decorators), Express (JS router calls), and Spring (Java annotations). Anything
else silently yields nothing — this is a bonus signal, not a required path.
"""

from __future__ import annotations

import re
from pathlib import Path
from urllib.parse import urljoin

_SOURCE_GLOBS = ("*.py", "*.js", "*.ts", "*.java")
_MAX_FILES = 2000  # a runaway source tree (vendored deps, node_modules) shouldn't hang this

# (pattern, path-group-index) — each matches one framework's route-declaration syntax.
_ROUTE_PATTERNS = [
    re.compile(r"@(?:app|bp|blueprint)\.route\(\s*['\"]([^'\"]+)['\"]"),        # Flask
    re.compile(r"@(?:app|router)\.(?:get|post|put|delete|patch)\(\s*['\"]([^'\"]+)['\"]"),  # FastAPI
    re.compile(r"(?:app|router)\.(?:get|post|put|delete|patch|all)\(\s*['\"]([^'\"]+)['\"]"),  # Express
    re.compile(r'@(?:Get|Post|Put|Delete|Patch|Request)Mapping\(\s*(?:value\s*=\s*)?"([^"]+)"'),  # Spring
]

_SKIP_DIRS = {"node_modules", ".git", "venv", ".venv", "__pycache__", "dist", "build", "vendor"}


def _iter_source_files(root: Path):
    count = 0
    for path in root.rglob("*"):
        if count >= _MAX_FILES:
            return
        if path.is_dir():
            continue
        if any(part in _SKIP_DIRS for part in path.parts):
            continue
        if path.suffix in (".py", ".js", ".ts", ".java"):
            count += 1
            yield path


def extract_routes(source_dir: str | Path) -> list[str]:
    """Grep route decorators/registrations out of a local source tree. Returns raw route
    path strings (e.g. "/api/users/<id>") as found in source — not yet resolved against a
    base URL, since this function doesn't know one."""
    root = Path(source_dir)
    if not root.exists():
        return []
    routes: set[str] = set()
    for path in _iter_source_files(root):
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for pattern in _ROUTE_PATTERNS:
            for m in pattern.finditer(text):
                route = m.group(1).strip()
                if route:
                    routes.add(route)
    return sorted(routes)


def seed_from_source(source_dir: str | Path, base_url: str, graph, attack_tree=None,
                     audit=None) -> dict:
    """Resolve extracted routes against base_url and seed them into the knowledge graph /
    attack tree, same as passive_recon's discoveries. Separate from extract_routes() so
    callers (and tests) can inspect raw routes without needing a graph."""
    from ..knowledge import ENDPOINT

    routes = extract_routes(source_dir)
    for route in routes:
        # Route params like <id>/:id/{id} don't correspond to one concrete URL; seed the
        # literal pattern anyway — it's still useful surface-shape signal for the planner,
        # and verify_tool-style checks substitute real values at proof time, not now.
        url = urljoin(base_url.rstrip("/") + "/", route.lstrip("/"))
        graph.observe(ENDPOINT, url, attrs={"source": "static_analysis"}, source="static_source")
        if attack_tree is not None:
            attack_tree.seed_endpoint(url)

    if audit is not None:
        audit.record("recon.static_source", routes=len(routes), source_dir=str(source_dir))

    return {"routes_found": len(routes)}
