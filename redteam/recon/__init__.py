"""Deterministic (zero-LLM-cost) reconnaissance — map the surface before spending tokens.

Per the project's own standing rule: learn from code and public metadata before ever
burning a model call. A scanner guesses with an LLM from turn one; an operator reads
robots.txt, sitemap.xml, and the API schema first, because those are free and exact.
"""

from __future__ import annotations


def run_deterministic_recon(engagement, graph, attack_tree=None, audit=None,
                            source_dir: str = "") -> dict:
    """Run every zero-LLM-cost recon step once, before either driver (single-agent or
    orchestrator) starts: passive fetches (robots.txt/sitemap.xml/API schema) always, plus
    static source-route extraction when a local source tree is given. One call site
    (cli.py) means single-agent and multi-agent runs get identical treatment."""
    from .passive import run_passive_recon

    summary = run_passive_recon(engagement, graph, attack_tree, audit=audit)

    if source_dir:
        from .static_source import seed_from_source
        routes_found = 0
        for scheme in (engagement.allowed_schemes or ["https"]):
            for host in engagement.allowed_hosts:
                if host.startswith("*.") or "/" in host:
                    continue
                routes_found += seed_from_source(
                    source_dir, f"{scheme}://{host}", graph, attack_tree,
                    audit=audit)["routes_found"]
        summary["static_routes_found"] = routes_found

    return summary
