"""Tests for static source-code recon — grepping route decorators out of a local source
tree is free (no network, no LLM call) and exact where probing is a guess."""

from __future__ import annotations

from redteam.attack_tree import AttackTree
from redteam.knowledge import ENDPOINT, KnowledgeGraph
from redteam.recon.static_source import extract_routes, seed_from_source


def test_extracts_flask_routes(tmp_path):
    (tmp_path / "app.py").write_text(
        "@app.route('/login')\ndef login(): ...\n\n"
        "@bp.route(\"/api/users/<id>\")\ndef user(id): ...\n",
        encoding="utf-8")
    routes = extract_routes(tmp_path)
    assert "/login" in routes
    assert "/api/users/<id>" in routes


def test_extracts_fastapi_routes(tmp_path):
    (tmp_path / "main.py").write_text(
        "@app.get('/v1/items')\nasync def list_items(): ...\n"
        "@router.post(\"/v1/items\")\nasync def create_item(): ...\n",
        encoding="utf-8")
    routes = extract_routes(tmp_path)
    assert "/v1/items" in routes


def test_extracts_express_routes(tmp_path):
    (tmp_path / "routes.js").write_text(
        "app.get('/health', (req, res) => res.send('ok'));\n"
        "router.post(\"/api/login\", handler);\n",
        encoding="utf-8")
    routes = extract_routes(tmp_path)
    assert "/health" in routes
    assert "/api/login" in routes


def test_extracts_spring_routes(tmp_path):
    (tmp_path / "Controller.java").write_text(
        '@GetMapping("/accounts")\npublic List<Account> list() { return null; }\n',
        encoding="utf-8")
    routes = extract_routes(tmp_path)
    assert "/accounts" in routes


def test_skips_vendored_directories(tmp_path):
    vendored = tmp_path / "node_modules" / "pkg"
    vendored.mkdir(parents=True)
    (vendored / "index.js").write_text("app.get('/should-not-appear', h);\n", encoding="utf-8")
    (tmp_path / "server.js").write_text("app.get('/real', h);\n", encoding="utf-8")
    routes = extract_routes(tmp_path)
    assert "/real" in routes
    assert "/should-not-appear" not in routes


def test_missing_source_dir_returns_empty_no_crash(tmp_path):
    assert extract_routes(tmp_path / "does-not-exist") == []


def test_seed_from_source_resolves_against_base_url_and_seeds_graph(tmp_path):
    (tmp_path / "app.py").write_text("@app.route('/admin')\ndef admin(): ...\n", encoding="utf-8")
    graph = KnowledgeGraph()
    tree = AttackTree()
    summary = seed_from_source(tmp_path, "https://example.com", graph, tree)
    keys = {n.key for n in graph.nodes(ENDPOINT)}
    assert "https://example.com/admin" in keys
    assert summary["routes_found"] == 1
    actionable_targets = {n.target for n in tree.actionable(limit=50)}
    assert "https://example.com/admin" in actionable_targets
