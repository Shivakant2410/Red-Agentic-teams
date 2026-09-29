"""Tests for finding deduplication (repeated proof of the same bug must not inflate counts)."""

from __future__ import annotations

from redteam.findings import Finding, FindingStore


def _f(**kw):
    base = dict(title="x", severity="high", target="http://x/a", summary="s")
    base.update(kw)
    return Finding(**base)


def test_same_target_same_cwe_is_deduped(tmp_path):
    s = FindingStore(tmp_path / "f.json")
    s.add(_f(cwe="CWE-284", target="http://x/ftp/"))
    s.add(_f(cwe="CWE-284", target="http://x/ftp/"))
    assert len(s.all()) == 1


def test_prose_in_target_still_dedupes(tmp_path):
    s = FindingStore(tmp_path / "f.json")
    s.add(_f(cwe="CWE-22", target="http://x/ftp/ (path traversal)"))
    s.add(_f(cwe="CWE-22", target="http://x/ftp/ (path traversal -> dir listing)"))
    assert len(s.all()) == 1        # normalized target collapses the near-duplicate


def test_distinct_targets_kept(tmp_path):
    s = FindingStore(tmp_path / "f.json")
    s.add(_f(cwe="CWE-89", target="http://x/login"))
    s.add(_f(cwe="CWE-89", target="http://x/search"))
    assert len(s.all()) == 2        # different endpoints are distinct findings


def test_dedup_keeps_higher_reproductions(tmp_path):
    s = FindingStore(tmp_path / "f.json")
    s.add(_f(cwe="CWE-284", target="http://x/ftp/", reproductions=3, trials=5))
    s.add(_f(cwe="CWE-284", target="http://x/ftp/", reproductions=5, trials=5))
    assert len(s.all()) == 1
    assert s.all()[0].reproductions == 5
