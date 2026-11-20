from types import SimpleNamespace

from redteam.recon_v2.adapters import ProjectDiscoveryAdapter
from redteam.recon_v2.evidence_store import EvidenceStore
from redteam.recon_v2.observations import SCOPE_OUT
from redteam.recon_v2.pipeline import _domain_roots, _same_origin_urls


def test_domain_roots_extracts_exact_and_wildcard_roots():
    assert _domain_roots((
        "example.com", "*.staging.example.com", "127.0.0.1",
        "10.0.0.0/8", "*.example.org",
    )) == ["example.com", "example.org", "staging.example.com"]


def test_same_origin_url_extraction_rejects_third_party_and_strips_fragments():
    urls = _same_origin_urls(
        "https://app.example.com/start",
        [
            "/api/users#section",
            "https://app.example.com/static/app.js",
            "https://cdn.example.net/library.js",
            "javascript:void(0)",
            "mailto:security@example.com",
            "/api/users#another",
        ],
    )
    assert urls == [
        "https://app.example.com/api/users",
        "https://app.example.com/static/app.js",
    ]


class _Scope:
    def host_scope_status(self, host):
        return host == "example.com" or host.endswith(".example.com")


class _Limiter:
    def __init__(self):
        self.used = 0

    def acquire(self):
        self.used += 1


class _Audit:
    def __init__(self):
        self.rows = []

    def record(self, event, **fields):
        self.rows.append({"event": event, **fields})


def test_subfinder_adapter_retains_external_passive_observations():
    commands = []

    def sandbox_exec(command, timeout=None):
        commands.append(command)
        if command.startswith("command -v"):
            return SimpleNamespace(stdout="/usr/bin/subfinder\n", exit_code=0, stderr="")
        return SimpleNamespace(
            stdout=(
                '{"host":"api.example.com","source":"crtsh"}\n'
                '{"host":"vendor.example.net","source":"cert"}\n'
            ),
            exit_code=0,
            stderr="",
        )

    scope = _Scope()
    store = EvidenceStore(scope=scope)
    limiter = _Limiter()
    audit = _Audit()
    adapter = ProjectDiscoveryAdapter(
        store, scope, limiter, audit, sandbox_exec=sandbox_exec,
    )

    result = adapter.run(
        "subfinder", ["-d", "example.com", "-silent", "-json"],
        target="example.com", authorized=True,
    )

    assert result["recorded"] == 2
    assert result["subjects"] == ["api.example.com", "vendor.example.net"]
    external = store.query(subject_contains="vendor.example.net")
    assert len(external) == 1
    assert external[0].scope_status == SCOPE_OUT
    assert limiter.used == 0  # passive enumeration does not spend active request budget
    assert commands[0].startswith("command -v subfinder")
    assert "subfinder -d example.com -silent -json" in commands[1]


def test_active_adapter_does_not_store_out_of_scope_hosts():
    def sandbox_exec(command, timeout=None):
        if command.startswith("command -v"):
            return SimpleNamespace(stdout="/usr/bin/httpx\n", exit_code=0, stderr="")
        return SimpleNamespace(
            stdout='{"url":"https://vendor.example.net/","status_code":200}\n',
            exit_code=0, stderr="",
        )

    scope = _Scope()
    store = EvidenceStore(scope=scope)
    audit = _Audit()
    adapter = ProjectDiscoveryAdapter(
        store, scope, _Limiter(), audit, sandbox_exec=sandbox_exec,
    )
    result = adapter.run(
        "httpx", ["-u", "https://example.com"], target="example.com",
        authorized=True,
    )
    assert result["recorded"] == 0
    assert result["skipped_out_of_scope"] == 1
    assert store.query(subject_contains="vendor.example.net") == []



def test_root_domain_pipeline_crawls_and_extracts_javascript_endpoints(monkeypatch):
    from types import SimpleNamespace

    import redteam.recon_v2.pipeline as pipeline
    from redteam.recon_v2.assets import AssetIntelligence
    from redteam.recon_v2.evidence_store import EvidenceStore

    class Scope:
        def host_scope_status(self, host):
            return host == "example.com"

        def check(self, url):
            assert url.startswith("https://example.com")
            return None

    class Limiter:
        def __init__(self):
            self.used = 0

        def acquire(self):
            self.used += 1

    class Audit:
        def __init__(self):
            self.events = []

        def record(self, event, **fields):
            self.events.append({"event": event, **fields})

    scope = Scope()
    limiter = Limiter()
    audit = Audit()
    store = EvidenceStore(scope=scope)
    assets = AssetIntelligence(store, scope=scope)
    bundle = SimpleNamespace(store=store, assets=assets, adapter=None)
    responses = {
        "https://example.com": (
            200,
            '<html><head><title>Example</title></head><body>'
            '<a href="/users">Users</a><script src="/app.js"></script>'
            '</body></html>',
        ),
        "https://example.com/users": (
            200, '<html><head><title>Users</title></head><body>ok</body></html>',
        ),
        "https://example.com/app.js": (200, 'const api = "/api/orders";'),
    }

    monkeypatch.setattr(pipeline, "crtsh_subdomains", lambda domain, fetch: [])
    monkeypatch.setattr(pipeline, "dns_bruteforce", lambda *args: {})
    monkeypatch.setattr(
        pipeline, "fetch_once",
        lambda ctx, req, tool="": (
            *responses.get(req["url"], (404, "")), 1.0, {},
        ),
    )
    ctx = SimpleNamespace(
        scope=scope, limiter=limiter, audit=audit, events=None, sandbox=None,
    )
    engagement = SimpleNamespace(
        allowed_hosts=("example.com",),
        allowed_schemes=("https",),
        allowed_ports=(443,),
    )

    result = pipeline.run_domain_recon(ctx, bundle, engagement)

    assert result["domains"] == ["example.com"]
    assert result["active_hosts"] == 1
    assert result["pages"] == 2
    assert result["js_files"] == 1
    assert store.query(kind="page")
    assert store.query(kind="js_endpoint", subject_contains="/api/orders")
