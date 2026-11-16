"""CI wrapper for the scan-engine fuzz target (kernel/fuzz/fuzz_scan.py).

Every test run exercises a short deterministic campaign: differential
kernel-vs-reference equality plus the slice-match invariants over the
adversarial corpus classes. A failing input is saved as a reproducer JSON
under kernel/fuzz/artifacts/ by the target itself.

Long campaigns are an operator step:
    python kernel/fuzz/fuzz_scan.py --iterations 20000 --seed <n> --big
"""

from __future__ import annotations

import importlib.util
import os
from pathlib import Path

import pytest

_FUZZ = Path(__file__).resolve().parent.parent / "kernel" / "fuzz" / "fuzz_scan.py"
_spec = importlib.util.spec_from_file_location("fuzz_scan", _FUZZ)
fuzz_scan = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(fuzz_scan)

from redteam.kernel_bridge import kernel_available  # noqa: E402

DEFAULT_ITERS = int(os.environ.get("FUZZ_ITERS", "250"))


def test_fuzz_scan_short_campaign():
    stats = fuzz_scan.run_burst(DEFAULT_ITERS, seed=2026)
    assert stats["iterations"] == DEFAULT_ITERS
    # corpus sanity: the generators must actually produce hits to scan for
    assert stats["hits"] > 0


@pytest.mark.skipif(not kernel_available(), reason="kernel binary not built")
def test_fuzz_scan_differential_actually_ran():
    """Guard against silent degradation: with the kernel present the burst
    MUST have run differential checks, not fallen back unnoticed."""
    stats = fuzz_scan.run_burst(40, seed=99)
    assert stats["differential"] == stats["iterations"]


def test_fuzz_scan_reference_only_mode_matches_bridge_disable(monkeypatch):
    """LLMRED_KERNEL=off must not change the reference's own invariants —
    the reference is the contract anchor and stands alone."""
    monkeypatch.setattr(fuzz_scan, "kernel_available", lambda: False)
    stats = fuzz_scan.run_burst(60, seed=7)
    assert stats["differential"] == 0
    assert stats["hits"] > 0


def test_fuzz_scan_big_transcript_crosses_the_transport_threshold():
    """One 100KB+ differential case on every CI run: the one-shot
    communicate() path must be byte-identical too."""
    import random

    from redteam.kernel_bridge import _scan_canaries_py, scan_canaries
    rng = random.Random(2026)
    canaries = [f"PIC-{rng.getrandbits(64):016x}" for _ in range(3)]
    text = (fuzz_scan.gen_soup(rng, canaries) * 400)[:120_000]
    pos = rng.randrange(1000, len(text) - 100)
    text = text[:pos] + canaries[0] + text[pos:]
    ref = _scan_canaries_py(text, canaries)
    assert ref, "big corpus must contain the planted canary"
    if kernel_available():
        assert scan_canaries(text, canaries) == ref
