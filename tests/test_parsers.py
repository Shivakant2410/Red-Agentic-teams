"""Tests for structured tool-output parsers and graph ingestion."""

from __future__ import annotations

from redteam.knowledge import ENDPOINT, HOST, SERVICE, TECHNOLOGY, KnowledgeGraph
from redteam.parsers import (ingest, parse_by_command, parse_dir, parse_http_headers,
                             parse_httpx, parse_nikto, parse_nmap, parse_nuclei,
                             parse_sqlmap, parse_whatweb)

NMAP = """Starting Nmap 7.94
Nmap scan report for api.acme.example (203.0.113.5)
Host is up (0.010s latency).
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.9p1
443/tcp  open  https   nginx 1.24.0
8080/tcp closed http
"""


def test_parse_nmap_hosts_services_tech():
    obs = parse_nmap(NMAP)
    kinds = {o.kind for o in obs}
    assert HOST in kinds and SERVICE in kinds and TECHNOLOGY in kinds
    services = [o for o in obs if o.kind == SERVICE]
    keys = {o.key for o in services}
    assert "203.0.113.5:443" in keys
    assert "203.0.113.5:8080" not in keys        # closed port ignored
    https = next(o for o in services if o.key == "203.0.113.5:443")
    assert https.attrs["service"] == "https" and "nginx" in https.attrs["version"]


def test_parse_dir_gobuster():
    text = "/admin (Status: 200)\n/login (Status: 302)\n/secret (Status: 403)\n"
    obs = parse_dir(text, base_url="https://api.acme.example")
    urls = {o.key: o.attrs["status"] for o in obs}
    assert urls["https://api.acme.example/admin"] == 200
    assert urls["https://api.acme.example/login"] == 302


def test_parse_nuclei_jsonl():
    line = ('{"template-id":"tech-detect","matched-at":"https://api.acme.example",'
            '"info":{"name":"nginx","severity":"info"}}')
    obs = parse_nuclei(line)
    assert obs and obs[0].kind == ENDPOINT
    assert obs[0].attrs["nuclei_severity"] == "info"


def test_parse_http_headers_tech():
    text = "HTTP/1.1 200 OK\nServer: nginx/1.24.0\nX-Powered-By: Express\n\n"
    obs = parse_http_headers(text, url="https://api.acme.example/")
    techs = {o.key for o in obs if o.kind == TECHNOLOGY}
    assert "nginx/1.24.0" in techs and "Express" in techs


def test_parse_sqlmap_flags_injection():
    text = "sqlmap identified the following injection point(s)\nParameter: id (GET)\nis vulnerable"
    obs = parse_sqlmap(text, base_url="https://api.acme.example/p?id=1")
    assert obs and obs[0].attrs["sqli"] is True and "id" in obs[0].attrs["parameters"]


def test_parse_sqlmap_ignores_clean_output():
    assert parse_sqlmap("all parameters appear to be not injectable", base_url="x") == []


def test_parse_nikto_server_and_paths():
    text = "+ Server: nginx/1.24.0\n+ /admin/: Admin login page found\n"
    obs = parse_nikto(text, base_url="https://api.acme.example")
    techs = {o.key for o in obs if o.kind == TECHNOLOGY}
    eps = {o.key for o in obs if o.kind == ENDPOINT}
    assert "nginx/1.24.0" in techs
    assert "https://api.acme.example/admin/" in eps


def test_parse_whatweb_tech():
    obs = parse_whatweb("http://x [200 OK] nginx[1.24.0], JQuery[3.6.0], Country[US]")
    keys = {o.key for o in obs}
    assert "nginx 1.24.0" in keys and "JQuery 3.6.0" in keys
    assert not any("Country" in k for k in keys)   # noise filtered


def test_parse_httpx_json():
    line = '{"url":"https://api.acme.example","status_code":200,"tech":["nginx","PHP"]}'
    obs = parse_httpx(line)
    assert any(o.kind == ENDPOINT for o in obs)
    assert any(o.key == "nginx" for o in obs) and any(o.key == "PHP" for o in obs)


def test_dispatch_extracts_url_from_command():
    # sqlmap needs the target URL; it should be pulled from the command automatically.
    obs = parse_by_command("sqlmap -u https://api.acme.example/p?id=1 --batch",
                           "Parameter: id (GET)\nis vulnerable")
    assert obs and obs[0].key == "https://api.acme.example/p?id=1"


def test_ingest_folds_into_graph():
    g = KnowledgeGraph()
    added = ingest(g, "nmap -sV 203.0.113.5", NMAP, source="kali_exec")
    assert added
    # The service should be attached to its host in the graph.
    svc = g.neighbors("host:203.0.113.5", "runs")
    assert any(s.key == "203.0.113.5:443" for s in svc)
