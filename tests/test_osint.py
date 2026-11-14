"""OSINT module: pluggable, passive, fail-open-to-empty — and RoE-gated.

The fetch/resolver/cert callables are injected, so NO test touches the
network. The engine gate (is_osint_eligible) keeps labs and IP literals out.
"""
from redteam.osint import (DNS_WORDLIST, cert_san, crtsh_subdomains,
                           dns_bruteforce, is_osint_eligible,
                           merge_candidates)

# ---------------------------------------------------------------- gating ----

def test_osint_eligibility_domain_vs_lab():
    assert is_osint_eligible("example.com")
    assert is_osint_eligible("api.customer.co.uk")
    # everything a lab or an internal net looks like: NOT eligible
    for host in ("localhost", "127.0.0.1", "10.0.0.5", "192.168.1.10",
                 "", "[::1]", "host:8897"):
        assert not is_osint_eligible(host), host


# ---------------------------------------------------------------- crt.sh ----

def test_crtsh_parses_name_value_lines_and_wildcards():
    payload = """[
     {"name_value": "*.example.com\\napi.example.com\\nexample.com"},
     {"name_value": "dev.example.com"},
     {"name_value": "unrelated.org"}
    ]"""
    status_text = iter([(200, payload), (200, payload)])
    got = crtsh_subdomains("example.com", lambda url, t: next(status_text))
    assert got == ["api.example.com", "dev.example.com"]


def test_crtsh_fails_open_to_empty():
    for resp in (None, (500, "boom"), (200, "<html>not json</html>"),
                 (200, '{"not": "a list"}')):
        fetch = (lambda url, t: resp) if resp else \
                (lambda url, t: (_ for _ in ()).throw(IOError("down")))
        assert crtsh_subdomains("example.com", fetch) == []


# ------------------------------------------------------------------- DNS ----

def test_dns_bruteforce_resolves_only_existing():
    zone = {"api.example.com": "203.0.113.7"}

    def resolve(host, timeout):
        return zone.get(host)

    hits = dns_bruteforce("example.com", ["api", "www", "nope", "a.b"],
                          resolve)
    assert hits == {"api.example.com": "203.0.113.7"}


def test_dns_bruteforce_survives_resolver_errors():
    def resolve(host, timeout):
        raise OSError("resolver down")
    assert dns_bruteforce("example.com", ["api"], resolve) == {}


def test_dns_wordlist_is_sane():
    # no dots (they would break the sub.<domain> join), no empties
    assert all(w and "." not in w and w == w.lower() for w in DNS_WORDLIST)


# ------------------------------------------------------------------- SAN ----

def test_cert_san_parses_openssl_output():
    pem = b"-----BEGIN CERTIFICATE-----fake-----END CERTIFICATE-----"
    def get_cert(host, port, timeout):
        return pem
    import subprocess, types
    fake = types.SimpleNamespace(stdout=(
        b"X509v3 Subject Alternative Name: \n"
        b"    DNS:example.com, DNS:*.api.example.com, DNS:other.org\n"))
    def run(*a, **k):
        return fake
    import redteam.osint as mod
    orig = subprocess.run
    subprocess.run = run
    try:
        got = cert_san("api.example.com", get_cert=get_cert)
    finally:
        subprocess.run = orig
    # exact queried host excluded; apex + stripped wildcard + other domains kept
    assert got == ["example.com", "other.org"]


# ------------------------------------------------------------------ merge ----

def test_merge_candidates_unions_and_normalizes():
    out = merge_candidates("example.com",
                           ["api.example.com", "*.dev.example.com",
                            "example.com", "elsewhere.org"],
                           ["dev.example.com"])
    assert out == ["api.example.com", "dev.example.com"]
