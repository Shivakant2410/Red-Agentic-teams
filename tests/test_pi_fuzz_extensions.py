"""Fuzz-target EXTENSIONS for the cipher matrix — tests written FIRST.

The existing target (kernel/fuzz/fuzz_scan.py) hunted the six original
smuggle layers. The matrix adds four cipher layers; the extension contract:

  COVERAGE   sandwich corpus embeds cipher-layer needles; both engines must
             see them (differential + slice-match invariants)
  ADVERSARY  a new cipher-near class: nested encodings, wrong-shift /
             wrong-canary ciphers, half-mirrored strings — engines must agree
             EXACTLY, including on zero hits (the false-positive control)
  REPRO      same seed -> identical stats (the campaign stays deterministic)
"""

from __future__ import annotations

import importlib.util
import os
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parent.parent
_FUZZ = _REPO / "kernel" / "fuzz" / "fuzz_scan.py"
_spec = importlib.util.spec_from_file_location("fuzz_scan_ext", _FUZZ)
fuzz_scan = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(fuzz_scan)

from redteam.kernel_bridge import (  # noqa: E402
    _scan_canaries_py,
    kernel_available,
    scan_canaries,
)
from redteam.pi.oracles import atbash, caesar, canary_hits, make_canary  # noqa: E402

CIPHER_LAYERS = ("atbash", "caesar1", "caesar3", "caesar25")


def test_corpus_layers_include_the_cipher_matrix():
    for layer in CIPHER_LAYERS:
        assert layer in fuzz_scan._SMUGGLE_LAYERS, layer


def test_sandwich_layer_is_found_by_the_oracle():
    canary = make_canary(__import__("random").Random(7))
    for layer in CIPHER_LAYERS:
        blob = fuzz_scan._layer(canary, layer)
        hits = canary_hits("noise " + blob + " tail", canary)
        assert any(v == layer for v, _ in hits), (layer, blob)


def test_cipher_near_nested_encoding_yields_no_hits():
    """caesar3(atbash(c)) and friends are DOUBLE encodings: no single variant
    needle equals them, and BOTH engines must agree on the zero."""
    import random

    rng = random.Random(11)
    canaries = [make_canary(rng) for _ in range(3)]
    for _ in range(200):
        text = fuzz_scan.gen_cipher_near(rng, canaries)
        for c in canaries:
            assert canary_hits(text, c) == [] or _single_layer_present(text, c), \
                "a nested form must never hit unless a real layer survives"
        ref = _scan_canaries_py(text, canaries)
        if kernel_available():
            assert scan_canaries(text, canaries) == ref


def _single_layer_present(text: str, canary: str) -> bool:
    """True iff at least one genuine single-variant needle occurs — the only
    legitimate way a cipher-near string can hit."""
    low = text.lower()
    for name in ("plain", "rot13", "atbash", "caesar1", "caesar3",
                 "caesar25"):
        blob = fuzz_scan._layer(canary, name)
        if blob.lower() in low:
            return True
    return False


def test_cipher_near_generator_direct_expectations():
    import random

    rng = random.Random(23)
    canaries = [make_canary(rng), make_canary(rng)]
    a, b = canaries
    # wrong_shift: b's caesar3 + a's caesar1 -> hits ONLY for those pairs
    text = fuzz_scan._layer(b, "caesar3") + " " + fuzz_scan._layer(a, "caesar1")
    hits = {(h["variant"], h["canary_index"])
            for h in _scan_canaries_py(text, canaries)}
    assert ("caesar1", 0) in hits and ("caesar3", 1) in hits
    assert not any(v == "atbash" for v, _ in hits)
    # half_atbash: mirrored half -> no full atbash needle
    text = atbash(a[:max(1, len(a) // 2)]) + a[len(a) // 2:]
    assert canary_hits(text, a) == [] or \
        any(v != "atbash" for v, _ in canary_hits(text, a))


def test_near_miss_cipher_kinds_never_hit_the_mutated_blob():
    import random
    import string as _s

    rng = random.Random(31)
    canary = make_canary(rng)
    for _ in range(100):
        blob = atbash(canary)
        i = rng.randrange(len(blob))
        repl = rng.choice([ch for ch in _s.ascii_lowercase
                           if ch != blob[i].lower()])
        blob = blob[:i] + repl + blob[i + 1:]
        assert not any(v == "atbash" for v, _ in canary_hits(blob, canary)), blob
        off = caesar(canary, 2)
        assert not any(v.startswith("caesar") for v, _ in canary_hits(off, canary))


@pytest.mark.skipif(not kernel_available(), reason="kernel binary not built")
def test_campaign_reproducible_and_cipher_covering():
    """Same seed -> identical stats; a campaign WITH the cipher-near class
    still passes differential + invariants for both engines."""
    s1 = fuzz_scan.run_burst(300, seed=2026)
    s2 = fuzz_scan.run_burst(300, seed=2026)
    assert s1 == s2
    assert s1["iterations"] == 300 and s1["hits"] > 0
