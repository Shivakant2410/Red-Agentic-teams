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

    def sandbox_exec(command):
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
    def sandbox_exec(command):
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
