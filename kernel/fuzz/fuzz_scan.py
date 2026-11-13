#!/usr/bin/env python3
"""Differential + invariant fuzz target for the llmred-kernel scan engine.

The scan engine's contract is not "does not crash" — it is BYTE-IDENTICAL
agreement between the Rust kernel and the Python reference on every input,
plus per-hit verifiability. This target hunts both:

  DIFFERENTIAL  kernel output == Python-reference output, exactly (values
                AND order), for every generated transcript.
  INVARIANT     (both engines) every reported hit must slice-match: taking
                the claimed variant's needle, the lowercased haystack at
                [pos, pos+len) equals the needle — the false-positive control
                the oracle layer depends on. Positions strictly ascending and
                unique per (canary, variant); len == needle length; no
                position outside the lowered haystack.

Corpus classes (all seeded, reproducible):
  soup       random unicode across ASCII / Latin / CJK / emoji / combining /
             zero-width family / unicode-tag plane / RTL / fullwidth —
             multi-byte position bugs live here (surrogates excluded: they
             cannot cross the JSON transport)
  sandwich   canaries embedded through their real smuggle layers (plain,
             base64, rot13, unicode-tags, zero-width AND the cipher matrix:
             atbash, caesar1/3/25) inside junk
  cipher_near nested encodings (a decoder applied twice), wrong-shift /
             wrong-canary ciphers, half-mirrored strings — both engines
             must agree exactly, INCLUDING on zero hits
  near_miss  case flips, hex swaps, suffix trims, ZW-split canaries, cipher
             blobs with one letter flipped / off-by-one shift — the scanner
             must report the REAL hits and nothing else
  patho      overlapping repeats (canary*k), ZW runs, tag-plane runs
  multi      prefix/superstring canary families in one scan — pattern
             interference
  edge       empty strings, bare canaries
  big        100-300KB transcripts (only with --big) — crosses the bridge's
             persistent-pipe threshold and exercises the one-shot transport

On failure the exact input and both engines' outputs are saved to
kernel/fuzz/artifacts/ as a reproducer JSON, then the run aborts non-zero.

Usage:
  python kernel/fuzz/fuzz_scan.py --iterations 5000 --seed 2026
  python kernel/fuzz/fuzz_scan.py --iterations 200 --big
"""

from __future__ import annotations

import argparse
import json
import random
import string
import sys
import time
from pathlib import Path

_REPO = Path(__file__).resolve().parent.parent.parent
if __package__ in (None, ""):
    sys.path.insert(0, str(_REPO))

from redteam.kernel_bridge import (  # noqa: E402
    _scan_canaries_py,
    kernel_available,
    scan_canaries,
)
from redteam.pi.oracles import (  # noqa: E402
    _canary_variants,
    atbash,
    caesar,
    canary_hits,
    make_canary,
)

ARTIFACTS = Path(__file__).resolve().parent / "artifacts"

# Unicode classes for the soup generator. NO surrogates (U+D800-U+DFFF):
# they cannot survive the JSON transport, so fuzzing them tests nothing.
_SOUP_CLASSES = [
    list(string.ascii_letters + string.digits + " \t\n.,!?:-_/"),
    [chr(c) for c in range(0xA0, 0x180)],                 # Latin-1 + ext
    [chr(c) for c in (0x4E00, 0x6587, 0x5B57, 0x1F600, 0x1F512, 0x1F4A9)],
    [chr(c) for c in range(0x0300, 0x0370)],              # combining marks
    [chr(c) for c in (0x200B, 0x200C, 0x200D, 0x200E, 0x200F, 0x2060, 0xFEFF)],
    [chr(c) for c in range(0xE0000, 0xE0080)],            # unicode-tag plane
    [chr(c) for c in (0x05D0, 0x05D1, 0x05D2)],           # RTL
    [chr(c) for c in (0xFF21, 0xFF22, 0xFF33)],           # fullwidth
]
_SMUGGLE_LAYERS = ("plain", "base64", "rot13", "unicode_tags", "zero_width",
                   "atbash", "caesar1", "caesar3", "caesar25")


def _layer(canary: str, layer: str) -> str:
    for name, needle in _canary_variants(canary):
        if name == layer:
            return needle
    return canary


def gen_soup(rng: random.Random, canaries: list[str]) -> str:
    n = rng.randint(1, 400)
    return "".join(rng.choice(rng.choice(_SOUP_CLASSES)) for _ in range(n))


def gen_sandwich(rng: random.Random, canaries: list[str]) -> str:
    parts = []
    for _ in range(rng.randint(1, 6)):
        parts.append("junk " * rng.randint(0, 3))
        parts.append(_layer(rng.choice(canaries), rng.choice(_SMUGGLE_LAYERS)))
        parts.append(" more junk ")
    return "".join(parts)


def gen_near_miss(rng: random.Random, canaries: list[str]) -> str:
    c = rng.choice(canaries)
    kind = rng.choice(["case", "hex_swap", "trim", "zw_split", "flip_one",
                       "atbash_flip", "caesar_off"])
    if kind == "case":
        return c.swapcase() + " " + c
    if kind == "hex_swap" and len(c) > 3:
        i = rng.randrange(len(c))
        return c[:i] + rng.choice("0123456789abcdef") + c[i + 1:]
    if kind == "trim":
        return c[:-1] + " " + c
    if kind == "zw_split":
        mid = len(c) // 2
        return c[:mid] + "\u200b" + c[mid:]     # matches zero_width variant
    if kind == "atbash_flip" and len(c) > 2:
        blob = atbash(c)
        i = rng.randrange(len(blob))
        blob = blob[:i] + rng.choice("abcdefghijklmnopqrstuvwxyz") + blob[i + 1:]
        return blob + " " + c
    if kind == "caesar_off":
        return caesar(c, 2) + " " + c           # off-by-one from every cell
    return c[::-1] + " " + c


def gen_cipher_near(rng: random.Random, canaries: list[str]) -> str:
    """Cipher-matrix adversarial forms: NESTED encodings (a decoder applied
    twice — no single variant equals them), wrong-shift / wrong-canary
    ciphers, half-mirrored strings. Contract: hits ONLY where a genuine
    single-layer needle of a scanned canary appears; both engines must agree
    exactly, including on the zeros."""
    c = rng.choice(canaries)
    other = rng.choice(canaries)
    kind = rng.choice(["nested", "wrong_shift", "half_atbash",
                       "cipher_then_plain"])
    if kind == "nested":
        inner = _layer(c, rng.choice(("rot13", "atbash", "caesar3")))
        return _layer(inner, rng.choice(("rot13", "atbash", "caesar3")))
    if kind == "wrong_shift":
        # another canary's cipher cell + this canary under a different cell
        return _layer(other, "caesar3") + " " + _layer(c, "caesar1")
    if kind == "half_atbash":
        mid = max(1, len(c) // 2)
        return atbash(c[:mid]) + c[mid:]
    return _layer(c, "atbash") + " " + c


def gen_patho(rng: random.Random, canaries: list[str]) -> str:
    kind = rng.choice(["repeat", "zw_run", "tag_run", "overlap"])
    if kind == "repeat":
        return rng.choice(canaries) * rng.randint(2, 8)
    if kind == "zw_run":
        return "\u200b" * rng.randint(50, 300) + rng.choice(canaries)
    if kind == "tag_run":
        return "".join(chr(0xE0000 + (i % 0x80)) for i in range(200))
    base = rng.choice(canaries)
    return base + base[:max(1, len(base) // 2)] + base


def gen_multi(rng: random.Random, canaries: list[str]) -> str:
    base = rng.choice(canaries)
    family = {base, base[:max(1, len(base) - 2)], base + "ff"}
    return " ".join(sorted(family)) + " " + gen_soup(rng, list(family))


def gen_edge(_rng: random.Random, canaries: list[str]) -> str:
    return _rng.choice(["", " ", "  \n\t ", canaries[0], canaries[0] + " "])


def gen_big(rng: random.Random, canaries: list[str]) -> str:
    body = gen_soup(rng, canaries)
    text = (body * (rng.randint(60_000, 120_000) // max(1, len(body) or 1)))
    for _ in range(rng.randint(1, 4)):
        pos = rng.randrange(0, max(1, len(text) - 40))
        text = text[:pos] + _layer(rng.choice(canaries),
                                   rng.choice(_SMUGGLE_LAYERS)) + text[pos:]
    return text


GENERATORS = (gen_soup, gen_sandwich, gen_near_miss, gen_cipher_near,
              gen_patho, gen_multi, gen_edge)


def _check_invariants(text: str, canaries: list[str],
                      hits: list[dict], engine: str) -> None:
    low = text.lower()
    needles: dict = {}
    for ci, canary in enumerate(canaries):
        if not canary:
            continue
        for name, needle in _canary_variants(canary):
            needles[(ci, name)] = needle.lower()
    last_pos: dict = {}
    for h in hits:
        key = (h["canary_index"], h["variant"])
        assert key in needles, f"[{engine}] reported unknown variant {key}"
        needle = needles[key]
        assert h["len"] == len(needle), \
            f"[{engine}] len {h['len']} != needle {len(needle)} at {key}"
        assert 0 <= h["pos"] and h["pos"] + h["len"] <= len(low), \
            f"[{engine}] position {h['pos']} outside lowered haystack"
        sliced = low[h["pos"]:h["pos"] + h["len"]]
        assert sliced == needle, \
            f"[{engine}] hit does not slice-match: {sliced!r} != {needle!r}"
        prev = last_pos.get(key)
        assert prev is None or h["pos"] > prev, \
            f"[{engine}] positions not strictly ascending per variant"
        last_pos[key] = h["pos"]


def _save_reproducer(tag: str, text: str, canaries: list[str],
                     expected, got) -> Path:
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    path = ARTIFACTS / f"fuzz-{tag}.json"
    path.write_text(json.dumps({
        "text": text, "canaries": canaries,
        "expected": expected, "got": got,
    }, ensure_ascii=False, indent=1), encoding="utf-8")
    return path


def run_burst(iterations: int, seed: int, big: bool = False,
              kernel: bool | None = None) -> dict:
    """Run the campaign; raise AssertionError with the reproducer path on
    any contract violation. Returns stats."""
    use_kernel = kernel_available() if kernel is None else kernel
    rng_master = random.Random(seed)
    stats = {"iterations": 0, "hits": 0, "differential": 0, "big": 0}
    gens = GENERATORS + ((gen_big,) if big else ())

    for i in range(iterations):
        rng = random.Random(rng_master.getrandbits(64))  # per-iter reproducible
        canaries = [make_canary(rng) for _ in range(rng.randint(1, 4))]
        gen = rng.choice(gens)
        text = gen(rng, canaries)

        ref = _scan_canaries_py(text, canaries)
        _check_invariants(text, canaries, ref, "reference")

        # the oracle-layer entry point must agree with the raw reference
        for canary in canaries:
            assert canary_hits(text, canary) == [
                (h["variant"], h["pos"])
                for h in _scan_canaries_py(text, [canary])
            ], "canary_hits diverged from the reference algorithm"

        if use_kernel:
            got = scan_canaries(text, canaries)
            if got != ref:
                path = _save_reproducer(f"differential-{seed}-{i}", text,
                                        canaries, ref, got)
                raise AssertionError(
                    f"kernel != reference at iteration {i}; "
                    f"reproducer saved: {path}")
            _check_invariants(text, canaries, got, "kernel")
            stats["differential"] += 1

        stats["iterations"] += 1
        stats["hits"] += len(ref)
        if gen is gen_big:
            stats["big"] += 1
    return stats


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--iterations", type=int, default=1000)
    ap.add_argument("--seed", type=int, default=2026)
    ap.add_argument("--big", action="store_true",
                    help="include 100-300KB transcripts (one-shot transport)")
    args = ap.parse_args(argv)

    t0 = time.perf_counter()
    stats = run_burst(args.iterations, args.seed, big=args.big)
    dt = time.perf_counter() - t0
    print(f"fuzz ok: {stats['iterations']} execs in {dt:.1f}s "
          f"({stats['iterations'] / max(dt, 1e-9):.0f} exec/s), "
          f"{stats['hits']} hits, {stats['big']} big transcripts, "
          f"differential checks: "
          f"{stats['differential'] if kernel_available() else 'kernel OFF'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
