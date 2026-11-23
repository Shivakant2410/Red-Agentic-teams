"""The evidence proxy must DECODE Content-Encoding bodies before storing them,
so a verbatim-quote / body_regex proof matches the real plaintext — not the
compressed bytes a modern server (Vinted, most sites) actually returns.
Regression guard for the gzip-blind evidence bug."""
import gzip
import zlib

import redteam.proxy as P

# _decode_body lives on the request-handler class.
_decode = next(getattr(P, n)._decode_body for n in dir(P)
               if isinstance(getattr(P, n), type) and hasattr(getattr(P, n), "_decode_body"))

PLAIN = b'{"flag":"admin dashboard SECRET token-42"}'


def test_gzip_body_is_decoded():
    assert _decode(gzip.compress(PLAIN), {"Content-Encoding": "gzip"}) == PLAIN


def test_zlib_deflate_is_decoded():
    assert _decode(zlib.compress(PLAIN), {"Content-Encoding": "deflate"}) == PLAIN


def test_raw_deflate_is_decoded():
    co = zlib.compressobj(wbits=-zlib.MAX_WBITS)
    raw = co.compress(PLAIN) + co.flush()
    assert _decode(raw, {"Content-Encoding": "deflate"}) == PLAIN


def test_header_case_insensitive():
    assert _decode(gzip.compress(PLAIN), {"content-encoding": "GZIP"}) == PLAIN


def test_identity_and_missing_pass_through():
    assert _decode(PLAIN, {"Content-Encoding": "identity"}) == PLAIN
    assert _decode(PLAIN, {}) == PLAIN
    assert _decode(PLAIN, None) == PLAIN


def test_malformed_body_never_raises_returns_raw():
    # a lying Content-Encoding must not crash recording — fall back to raw bytes
    assert _decode(b"this is not gzip", {"Content-Encoding": "gzip"}) == b"this is not gzip"


def test_empty_body():
    assert _decode(b"", {"Content-Encoding": "gzip"}) == b""
    assert _decode(None, {"Content-Encoding": "gzip"}) == b""


def test_decoded_body_is_quote_matchable():
    # the point of the fix: a proof's verbatim quote now appears in the stored body
    decoded = _decode(gzip.compress(PLAIN), {"Content-Encoding": "gzip"})
    assert b"admin dashboard SECRET" in decoded          # would FAIL on gzip bytes
    import re
    assert re.search(rb"token-\d+", decoded)
