"""WAF/Cloudflare block detection — the behavioral fix for "model gets stuck at
Cloudflare and scans in a loop". A block must be recognised and the agent told
to switch to the browser; a normal 403/page must NOT be flagged (no false
positives that would wrongly derail the agent)."""
from redteam.waf import detect_waf_block, looks_like_waf

CF_INTERSTITIAL = ("<html><head><title>Just a moment...</title></head>"
                   "<body><div id='challenge-platform'></div>cf-chl</body></html>")
CF_1020 = "<title>Attention Required! | Cloudflare</title> Enable JavaScript and cookies to continue"


def test_cloudflare_interstitial_detected():
    note = detect_waf_block(CF_INTERSTITIAL, 403)
    assert note and "browser_navigate" in note and "Cloudflare" in note


def test_cloudflare_1020_block_detected():
    assert looks_like_waf(CF_1020, 403)


def test_challenge_detected_even_on_200():
    # the interstitial is served with 200 while it "checks your browser"
    assert looks_like_waf("Just a moment... checking your browser", 200)


def test_plain_403_not_flagged():
    # a legitimate authorization 403 must be reasoned about normally, not treated
    # as a WAF wall
    assert detect_waf_block('{"error":"forbidden: insufficient role"}', 403) == ""


def test_normal_page_not_flagged():
    assert detect_waf_block("<html><body>Welcome to the shop</body></html>", 200) == ""


def test_empty_safe():
    assert detect_waf_block("", None) == ""
    assert detect_waf_block(None, 403) == ""


def test_guidance_says_dont_loop():
    note = detect_waf_block(CF_INTERSTITIAL, 503)
    assert "do NOT repeat" in note or "keep being blocked" in note
    assert "human must warm" in note  # the escalation path when browser also blocked
