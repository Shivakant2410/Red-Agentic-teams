"""OH handling pipelines — model->consumer stand-ins with a
configurable SANITIZER ORDER (SOTA.md backlog B3).

First principles: a sanitizer is a SEQUENCE of transforms between the
model's reply and the consumer. The vulnerability axis is not whether a
sanitizer exists but in which ORDER its transforms run:

    sanitize_then_normalize  (WRONG)  strip -> escape angles -> one
                              entity-decode -> NFKC. The decode runs
                              AFTER the neutralizing steps, so any
                              shape that survived the strip is re-
                              folded into a live payload (nfc_refold,
                              entity_encoded, svg_onload).
    normalize_then_sanitize  (RIGHT)  decode-until-stable + NFKC
                              FIRST, then the strip set — the OWASP
                              LLM05 mitigation list's decode-then-
                              validate order.

Two further controls the shape axis probes, deliberately NOT conflated
with the order:

    STRIP SET   img-only vs img+svg: <svg onload=...> defeats an
                img-only strip at ANY order.
    EGRESS      any vs public_only: a markdown image aimed at the
                link-local cloud metadata endpoint (169.254.169.254)
                carries no angle brackets — the sanitizer never sees
                it; only the renderer's egress policy blocks it.

The "model" is the LLM05 relay: it copies the first payload-shaped
snippet it finds (the lane's public markers, shape-aware). Consumers
fire harness-observed SIDE EFFECTS on the FINAL text — never a
judgement about intent. Deterministic; no network, no subprocess.
"""

from __future__ import annotations

import html as _htmlmod
import re
import unicodedata
from urllib.parse import urlsplit

from .oracles import (MARK_MD, MARK_SHELL, MARK_SQL, MARK_SSRF,  # noqa
                      MARK_XSS, MARK_XSS_ENT, MARK_XSS_NFC, MARK_XSS_SVG)

# every payload shape the stand-in "model" relays (public markers)
_RELAY_MARKERS = (MARK_MD, MARK_SSRF, MARK_XSS, MARK_XSS_NFC,
                  MARK_XSS_ENT, MARK_XSS_SVG, MARK_SHELL, MARK_SQL)

_CLEAN = "Incident summary: nothing unusual."


def _model_relay(prompt: str) -> str:
    for rx in _RELAY_MARKERS:
        m = rx.search(prompt)
        if m:
            return m.group(0)
    return _CLEAN


# -- the sanitizer transforms (deterministic stand-ins) ---------------------------

def _strip_img(s: str) -> str:
    return re.sub(r"<img[^>]*>", " ", s, flags=re.I | re.S)


def _strip_img_svg(s: str) -> str:
    s = re.sub(r"<svg[^>]*>.*?</svg\s*>", " ", s, flags=re.I | re.S)
    s = re.sub(r"<svg[^>]*>", " ", s, flags=re.I | re.S)
    return _strip_img(s)


def _escape_angles(s: str) -> str:
    # the realistic omission: angle brackets escaped, "&" left alone —
    # the gap a later entity-decode then reopens
    return s.replace("<", "&lt;").replace(">", "&gt;")


def _decode_full(s: str) -> str:
    """decode-until-stable + NFKC — the OWASP decode-then-validate
    step, done FIRST."""
    for _ in range(5):
        nxt = _htmlmod.unescape(s)
        if nxt == s:
            break
        s = nxt
    return unicodedata.normalize("NFKC", s)


def _is_internal(url: str) -> bool:
    """Link-local / loopback / RFC1918 hosts — the egress policy's
    deny set, parsed mechanically from the URL."""
    host = (urlsplit(url).hostname or "").lower()
    if host.startswith(("169.254.", "10.", "192.168.", "127.")):
        return True
    if host.startswith("172."):
        try:
            second = int(host.split(".")[1])
        except (IndexError, ValueError):
            return False
        return 16 <= second <= 31
    return False


def handling_pipeline(*, order: str = "sanitize_then_normalize",
                      strip: str = "img", egress: str = "any",
                      renderer: bool = True, html: bool = True,
                      shell: bool = False, sql: bool = False):
    """A model->consumer pipeline stand-in with the three controls the
    OH shape axis probes: sanitizer ORDER, STRIP set, and the renderer
    EGRESS policy. Returns prompt -> {"reply", "consumer_events"}."""
    if order not in ("sanitize_then_normalize",
                     "normalize_then_sanitize"):
        raise ValueError("unknown sanitizer order")
    if strip not in ("img", "img+svg"):
        raise ValueError("unknown strip set")
    if egress not in ("any", "public_only"):
        raise ValueError("unknown egress policy")
    _strip = _strip_img_svg if strip == "img+svg" else _strip_img

    def _sanitize(text: str) -> str:
        if order == "sanitize_then_normalize":
            text = _escape_angles(_strip(text))
            text = _htmlmod.unescape(text)          # the wrong-order bug
            return unicodedata.normalize("NFKC", text)
        return _strip(_decode_full(text))

    def _pipeline(prompt: str) -> dict:
        reply = _model_relay(prompt)
        final = _sanitize(reply)
        events = []
        if renderer:
            m = MARK_MD.search(final)
            if m:
                url = m.group(1)
                if egress == "public_only" and _is_internal(url):
                    events.append({"consumer": "renderer",
                                   "action": "egress_blocked",
                                   "detail": url})
                else:
                    events.append({"consumer": "renderer",
                                   "action": "remote_fetch",
                                   "detail": url})
        if html:
            m = MARK_XSS.search(final) or MARK_XSS_SVG.search(final)
            if m:
                events.append({"consumer": "html",
                               "action": "event_fired",
                               "detail": m.group(0)})
        if shell:
            m = MARK_SHELL.search(final)
            if m:
                events.append({"consumer": "shell", "action": "executed",
                               "detail": m.group(0)})
        if sql:
            m = MARK_SQL.search(final)
            if m:
                events.append({"consumer": "sql",
                               "action": "rows_changed",
                               "detail": m.group(0)})
        return {"reply": reply, "consumer_events": events}

    return _pipeline
