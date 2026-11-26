"""The extension/ asset pack: manifest hygiene and the no-values guarantee.

The whole point of the extension is that input VALUES never leave the browser.
These tests pin the shape so a future edit cannot silently turn the capture
helper into an OTP exfiltrator:

1. Manifest V3, minimal permissions (no <all_urls>, no tabs-wide reads).
2. background.js posts to /api/traffic/ingest and nothing else.
3. The page-collect function reads getAttribute() only — a `.value` read on a
   form field fails the suite.
"""

from __future__ import annotations

import json
from pathlib import Path

EXT_DIR = Path(__file__).resolve().parents[1] / "extension"


def _manifest() -> dict:
    return json.loads((EXT_DIR / "manifest.json").read_text(encoding="utf-8"))


def test_manifest_is_mv3_with_minimal_permissions():
    m = _manifest()
    assert m["manifest_version"] == 3
    perms = set(m.get("permissions", []))
    assert perms <= {"activeTab", "scripting", "storage"}
    for pattern in m.get("host_permissions", []):
        assert pattern.startswith("http://127.0.0.1/") or pattern.startswith("http://localhost/")


def test_background_posts_only_to_the_ingest_endpoint():
    js = (EXT_DIR / "background.js").read_text(encoding="utf-8")
    assert "/api/traffic/ingest" in js
    # No other network sink sneaks in:
    for forbidden in ("XMLHttpRequest", "ws://", "wss://", "https://hooks", "webhook"):
        assert forbidden not in js


def test_collect_is_attribute_only_never_reads_values():
    js = (EXT_DIR / "background.js").read_text(encoding="utf-8")
    collect_start = js.index("function collectPageShape")
    collect_end = js.index("chrome.runtime.onMessage")
    collect = js[collect_start:collect_end]
    assert "getAttribute" in collect
    assert ".value" not in collect, "the collector must never read input VALUES"
    assert "innerText" not in collect and "textContent" not in collect


def test_popup_prompts_for_endpoint_and_run():
    html = (EXT_DIR / "popup.html").read_text(encoding="utf-8")
    js = (EXT_DIR / "popup.js").read_text(encoding="utf-8")
    assert 'id="endpoint"' in html and 'id="runId"' in html
    assert "api/traffic/ingest" not in js  # path lives in background.js, single source
