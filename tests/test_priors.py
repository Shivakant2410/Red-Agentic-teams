"""Tests for EPSS/KEV/nuclei prior injection (docs/multi-gambit.md §7.4).

The contracts under test:
  - seed()/prior_provider turn public intel into informative Beta pseudo-counts;
  - DATA WINS: a prior never overrides observed evidence (seed refuses, records wash out);
  - EVIDENCE-ONLY export: priors are local, never broadcast — federation between two
    peers that seeded the SAME snapshot must not double-count it;
  - intel parsing tolerates junk (a feed is untrusted input, like a peer payload);
  - policy gate: only EPSS_YIELD_CLASSES may steer probes (IDOR's ~0.009 EPSS must
    never suppress the technique that confirms most on numeric-id endpoints).
"""

from __future__ import annotations

import json

import pytest

from redteam.bandit import BanditStore
from redteam.priors import (
    EPSS_YIELD_CLASSES,
    builtin_prior_provider,
    class_priors,
    cwe_cves_from_templates,
    invert_kev,
    load_epss,
    load_kev,
    make_provider,
)
from redteam.attack_tree import CWE_TO_TECHNIQUE


# -- seed(): the Bayesian warm start ---------------------------------------------------

def test_seed_gives_informative_belief_and_draws():
    store = BanditStore()
    assert store.seed("injection.sqli", "generic", p=0.9, strength=12.0, source="epss")
    arm = store._get("injection.sqli", "generic")
    assert arm.mean == pytest.approx(11.8 / 14.0)          # Beta(1+10.8, 1+1.2)
    assert arm.prior_source == "epss"
    assert arm.observed == 0                                # prior is not evidence
    draws = [store.sample("injection.sqli", "generic") for _ in range(500)]
    assert sum(draws) / len(draws) > 0.8                    # probes sqli FIRST now


def test_unseeded_technique_keeps_uniform_ignorance():
    store = BanditStore()
    store.seed("injection.sqli", "generic", p=0.9, strength=12.0)
    draws = [store.sample("xss.reflected", "generic") for _ in range(300)]
    assert 0.35 < sum(draws) / len(draws) < 0.65            # Beta(1,1), centered


def test_local_evidence_washes_the_prior_out():
    """Data wins: 30 losses against a p=0.9 prior collapse the mean below 0.3 — the
    intel shaped where we probed FIRST, never what we concluded."""
    store = BanditStore()
    store.seed("injection.sqli", "generic", p=0.9, strength=12.0)
    for _ in range(30):
        store.record("injection.sqli", "generic", won=False)
    assert store._get("injection.sqli", "generic").mean < 0.3


def test_seed_refuses_arms_with_observed_evidence():
    store = BanditStore()
    for _ in range(3):
        store.record("access.idor", "numeric-id", won=True)
    arm = store._get("access.idor", "numeric-id")
    assert store.seed("access.idor", "numeric-id", p=0.99, strength=20.0) is False
    assert (arm.alpha, arm.beta) == (4.0, 1.0)              # untouched
    assert not arm.has_prior


def test_seed_refuses_arms_with_merged_evidence():
    """Merged peer evidence is observed evidence — a prior may not sneak in behind it."""
    store = BanditStore()
    store.merge_state([{"technique": "ssrf", "bucket": "generic",
                        "alpha": 5.0, "beta": 1.0}])
    assert store.seed("ssrf", "generic", p=0.9, strength=12.0) is False


def test_reseeding_virgin_arm_replaces_prior_idempotently():
    """Re-importing a refreshed intel snapshot must not stack pseudo-counts."""
    store = BanditStore()
    store.seed("ssrf", "generic", p=0.9, strength=12.0, source="epss@day1")
    store.seed("ssrf", "generic", p=0.5, strength=4.0, source="epss@day2")
    arm = store._get("ssrf", "generic")
    assert arm.alpha == pytest.approx(3.0)                  # 1 + 0.5*4, not 1 + 10.8 + 2
    assert arm.beta == pytest.approx(3.0)
    assert arm.prior_source == "epss@day2"


def test_seed_validates_inputs():
    store = BanditStore()
    for bad_p in (0.0, 1.0, 1.2, -0.1):
        with pytest.raises(ValueError):
            store.seed("ssrf", "generic", p=bad_p)
    with pytest.raises(ValueError):
        store.seed("ssrf", "generic", p=0.5, strength=0.5)


# -- prior provider: class intel -> any-bucket warm start --------------------------------

def test_provider_seeds_new_arms_in_any_bucket():
    def provider(technique):
        return (0.8, 10.0, "test-intel") if technique == "access.idor" else None

    store = BanditStore(prior_provider=provider)
    store.sample("access.idor", "numeric-id")               # first touch creates + seeds
    arm = store._get("access.idor", "numeric-id")
    assert arm.has_prior and arm.prior_source == "test-intel"
    assert arm.mean == pytest.approx(0.75)                  # Beta(1+8, 1+2)
    store.sample("access.idor", "auth-wall")                # any bucket, same class intel
    assert store._get("access.idor", "auth-wall").has_prior
    assert not store._get("xss.reflected", "generic").has_prior


def test_provider_records_count_as_observed_once_evidence_arrives():
    def provider(technique):
        return (0.9, 12.0, "test-intel") if technique == "ssrf" else None

    store = BanditStore(prior_provider=provider)
    store.record("ssrf", "generic", won=False)
    arm = store._get("ssrf", "generic")
    assert arm.observed == 1.0                              # real trial, prior excluded
    assert arm.mean < 0.9                                   # the loss moved the belief


def test_raising_provider_is_isolated():
    def hostile(technique):
        raise RuntimeError("intel feed exploded")

    store = BanditStore(prior_provider=hostile)
    assert 0.0 <= store.sample("ssrf", "generic") <= 1.0
    assert not store._get("ssrf", "generic").has_prior


def test_provider_returning_junk_is_isolated():
    for junk in ((2.0, 12.0, "x"), (0.5, 0.2, "x"), None, "nope", ()):
        store = BanditStore(prior_provider=lambda t, j=junk: j)
        store.sample("ssrf", "generic")
        assert not store._get("ssrf", "generic").has_prior, f"junk {junk!r} seeded!"


# -- federation: priors are local, evidence pools ------------------------------------------

def test_export_strips_prior_and_broadcasts_observed_only():
    store = BanditStore()
    store.seed("injection.sqli", "generic", p=0.9, strength=12.0)
    store.record("injection.sqli", "generic", won=True)
    store.record("injection.sqli", "generic", won=True)
    store.record("injection.sqli", "generic", won=False)
    rows = store.export_state(min_trials=1)
    assert len(rows) == 1
    row = rows[0]
    assert row["alpha"] == pytest.approx(3.0)               # 1 + 2 real wins
    assert row["beta"] == pytest.approx(2.0)                # 1 + 1 real loss
    assert row["prior_alpha"] == pytest.approx(10.8)        # audit fields ride along
    assert row["prior_source"] == "epss"


def test_untried_seeded_arm_is_not_broadcast():
    """export_state(min_trials=1) is the orchestrator's per-round broadcast; a prior
    alone is not evidence and must not ride the bus."""
    store = BanditStore()
    store.seed("ssrf", "generic", p=0.9, strength=12.0)
    store.sample("ssrf", "generic")
    assert store.export_state(min_trials=1) == []


def test_federation_does_not_double_count_shared_prior():
    """A and B both seed from the SAME public snapshot (the normal case). After A
    records 5 real wins and syncs, B's belief is 1 + its own prior + 5 observed —
    the intel is counted exactly once.\""""
    provider = make_provider({"CWE-89": (0.9, 12.0)}, cwe_to_technique=CWE_TO_TECHNIQUE)
    a = BanditStore(prior_provider=provider)
    b = BanditStore(prior_provider=provider)
    for _ in range(5):
        a.record("injection.sqli", "generic", won=True)
    b.merge_state(a.export_state())
    arm = b._get("injection.sqli", "generic")
    assert arm.alpha == pytest.approx(1.0 + 10.8 + 5.0)     # NOT 1 + 2*10.8 + 5
    assert arm.beta == pytest.approx(1.0 + 1.2)
    assert arm.observed == pytest.approx(5.0)


def test_export_of_prior_free_arms_is_unchanged_legacy():
    """No prior -> raw (alpha, beta) broadcast exactly as before this feature."""
    store = BanditStore()
    for _ in range(7):
        store.record("access.idor", "numeric-id", won=True)
    for _ in range(3):
        store.record("access.idor", "numeric-id", won=False)
    (row,) = store.export_state()
    assert row["alpha"] == 8.0 and row["beta"] == 4.0


def test_persisted_prior_arm_survives_roundtrip(tmp_path):
    path = tmp_path / "bandit.json"
    s1 = BanditStore(path)
    s1.seed("ssrf", "generic", p=0.8, strength=10.0)
    s2 = BanditStore(path)
    arm = s2._get("ssrf", "generic")
    assert arm.prior_alpha == pytest.approx(8.0)
    assert arm.prior_source == "epss"
    assert arm.mean == pytest.approx(0.75)                  # Beta(9, 3)


def test_summary_reports_prior_provenance():
    store = BanditStore()
    store.seed("ssrf", "generic", p=0.9, strength=12.0)
    entry = store.summary()["ssrf@generic"]
    assert entry["observed"] == 0
    assert entry["prior"] == {"source": "epss", "strength": 12.0}


# -- intel feed parsing: untrusted input, tolerated ------------------------------------------

def test_load_epss_tolerates_junk(tmp_path):
    feed = {"_meta": {"fetched": "2026-10-29", "source": "first.org", "count": 2},
            "CVE-2021-44228": {"cve": "CVE-2021-44228", "epss": "0.97448"},
            "CVE-2023-34362": {"epss": 0.96},
            "CVE-JUNK": {"epss": "not-a-number"},
            "CVE-2020-0001": {"epss": "7.0"},                # out of range -> dropped
            "not-a-cve": {"epss": 0.5},
            "CVE-2020-0002": "0.42"}                         # bare string form
    path = tmp_path / "epss.json"
    path.write_text(json.dumps(feed), encoding="utf-8")
    out = load_epss(path)
    assert out == {"CVE-2021-44228": pytest.approx(0.97448),
                   "CVE-2023-34362": pytest.approx(0.96),
                   "CVE-2020-0002": pytest.approx(0.42)}


def test_load_epss_survives_corrupt_file(tmp_path):
    path = tmp_path / "epss.json"
    path.write_text("{not json at all", encoding="utf-8")
    assert load_epss(path) == {}


def test_load_kev_slim_and_raw_cisa_shapes(tmp_path):
    slim = {"_meta": {"fetched": "x"}, "CVE-2021-44228": ["CWE-917", "CWE-502"],
            "CVE-2020-1472": ["CWE-306"]}
    p1 = tmp_path / "kev_slim.json"
    p1.write_text(json.dumps(slim), encoding="utf-8")
    assert load_kev(p1) == {"CVE-2021-44228": ["CWE-502", "CWE-917"],
                            "CVE-2020-1472": ["CWE-306"]}

    raw = {"vulnerabilities": [
        {"cveID": "CVE-2021-44228", "cwes": ["CWE-917"]},
        {"cveID": "not-a-cve", "cwes": ["CWE-1"]},
        {"cveID": "CVE-2020-0001", "cwes": "CWE-78"},        # bare string form
        {"cveID": "CVE-2020-0002"},                          # no cwes -> empty list
        "junk",
    ]}
    p2 = tmp_path / "kev_raw.json"
    p2.write_text(json.dumps(raw), encoding="utf-8")
    assert load_kev(p2) == {"CVE-2021-44228": ["CWE-917"],
                            "CVE-2020-0001": ["CWE-78"],
                            "CVE-2020-0002": []}


def test_invert_kev_transposes_cve_to_cwe():
    out = invert_kev({"CVE-1": ["CWE-89", "CWE-74"], "CVE-2": ["CWE-89"], "CVE-3": []})
    assert out == {"CWE-89": {"CVE-1", "CVE-2"}, "CWE-74": {"CVE-1"}}


# -- aggregation + policy gate -----------------------------------------------------------------

def test_class_priors_aggregates_top_k_and_caps():
    epss = {"CVE-1": 0.97, "CVE-2": 0.90, "CVE-3": 0.40, "CVE-4": 0.01,
            "CVE-5": 0.5, "CVE-6": 0.2}
    cwe_cves = {"CWE-89": {"CVE-1", "CVE-2", "CVE-3", "CVE-4", "CVE-5", "CVE-6"},
                "CWE-639": {"CVE-7"}}                        # member without EPSS -> no prior
    out = class_priors(cwe_cves, epss, top_k=3, strength=12.0)
    assert out["CWE-89"] == pytest.approx((min(0.95, (0.97 + 0.90 + 0.50) / 3), 12.0))
    assert "CWE-639" not in out


def test_class_priors_keeps_every_class_for_the_policy_gate_to_filter():
    """class_priors is pure aggregation; suppression policy lives in make_provider."""
    epss = {"CVE-1": 0.009}
    out = class_priors({"CWE-639": {"CVE-1"}}, epss)
    assert out["CWE-639"] == pytest.approx((0.009, 12.0))


def test_make_provider_policy_gate_blocks_logic_classes():
    priors = {"CWE-639": (0.009, 12.0), "CWE-89": (0.95, 12.0)}
    gated = make_provider(priors, cwe_to_technique=CWE_TO_TECHNIQUE)
    assert gated("access.idor") is None                     # EPSS must not starve IDOR
    assert gated("injection.sqli")[0] == pytest.approx(0.95)
    ungated = make_provider(priors, cwe_to_technique=CWE_TO_TECHNIQUE, allow=None)
    assert ungated("access.idor")[0] == pytest.approx(0.009)


def test_make_provider_maps_via_repo_technique_taxonomy():
    provider = make_provider({"CWE-918": (0.8, 10.0)}, cwe_to_technique=CWE_TO_TECHNIQUE)
    p, s, source = provider("ssrf")
    assert p == pytest.approx(0.8) and s == pytest.approx(10.0)
    assert "CWE-918" in source
    assert provider("injection.sqli") is None


def test_make_provider_prefers_most_exploited_allowed_class():
    """info.sensitive <- CWE-200 (not allowed), CWE-22 (0.95), CWE-98 (0.72): the
    most-exploited ALLOWED class wins and names itself in the source tag."""
    priors = {"CWE-200": (0.99, 12.0), "CWE-22": (0.95, 12.0), "CWE-98": (0.72, 12.0)}
    p, _s, source = make_provider(priors, cwe_to_technique=CWE_TO_TECHNIQUE)("info.sensitive")
    assert p == pytest.approx(0.95) and "CWE-22" in source


def test_yield_class_allowlist_maps_into_repo_technique_taxonomy():
    """The scanner classes we warm-start TODAY must resolve through the repo's CWE
    map — a typo'd CWE would silently warm-start nothing. (The allowlist may also
    carry classes ahead of the taxonomy — deserialization, upload — which is fine.)"""
    mapped = EPSS_YIELD_CLASSES & set(CWE_TO_TECHNIQUE)
    for required in ("CWE-89", "CWE-78", "CWE-79", "CWE-918", "CWE-22", "CWE-98"):
        assert required in mapped, f"{required} missing from mapped allowlist"


# -- nuclei corpus ------------------------------------------------------------------------------

def test_cwe_cves_from_templates(tmp_path):
    import yaml
    t1 = tmp_path / "cves" / "CVE-2021-44228.yaml"
    t1.parent.mkdir(parents=True)
    t1.write_text(yaml.safe_dump({
        "id": "CVE-2021-44228",
        "info": {"name": "Log4Shell", "severity": "critical",
                 "classification": {"cve-id": "CVE-2021-44228", "cwe-id": "CWE-502"}}}),
        encoding="utf-8")
    t2 = tmp_path / "cves" / "custom-sqli.yaml"
    t2.write_text(yaml.safe_dump({
        "id": "custom-sqli-cve-2023-34362",                  # CVE regex fallback over id
        "info": {"name": "MOVEit", "classification": {"cwe-id": ["CWE-89", "CWE-999X"]}}}),
        encoding="utf-8")
    t3 = tmp_path / "cves" / "no-metadata.yaml"
    t3.write_text(yaml.safe_dump({"id": "bare", "info": {"name": "nothing"}}), encoding="utf-8")
    (tmp_path / "cves" / "broken.yaml").write_text("{unclosed", encoding="utf-8")

    out = cwe_cves_from_templates(tmp_path)
    assert out["CWE-502"] == {"CVE-2021-44228"}
    assert out["CWE-89"] == {"CVE-2023-34362"}              # 'CWE-999X' filtered, CVE from id
    assert "bare" not in json.dumps(out, default=list)      # metadata-less template skipped


# -- builtin provider (bundled snapshots) ------------------------------------------------------

def test_builtin_provider_from_synthetic_snapshots(tmp_path):
    kev = {"CVE-2023-34362": ["CWE-89"]}
    epss = {"CVE-2023-34362": 0.96}
    (tmp_path / "kev_snapshot.json").write_text(json.dumps(kev), encoding="utf-8")
    (tmp_path / "epss_snapshot.json").write_text(json.dumps(epss), encoding="utf-8")
    provider = builtin_prior_provider(tmp_path)
    assert provider is not None
    p, _s, source = provider("injection.sqli")
    assert p == pytest.approx(0.95)                         # capped, real score used
    assert "CWE-89" in source


def test_builtin_provider_absent_snapshots_is_none(tmp_path):
    assert builtin_prior_provider(tmp_path) is None


def test_builtin_provider_corrupt_snapshots_is_none(tmp_path):
    (tmp_path / "kev_snapshot.json").write_text("junk{", encoding="utf-8")
    (tmp_path / "epss_snapshot.json").write_text("junk{", encoding="utf-8")
    assert builtin_prior_provider(tmp_path) is None


# -- bundled snapshots sanity (real intel, committed to the repo) --------------------------------

def test_bundled_snapshots_produce_a_working_provider():
    """The repo ships real EPSS+KEV snapshots; they must keep yielding a usable
    provider. Statistical assertion kept loose: it pins the SHAPE (signature classes
    warm, logic classes intel-free), not daily feed values."""
    provider = builtin_prior_provider()
    if provider is None:
        pytest.skip("bundled snapshots not present")
    sqli = provider("injection.sqli")
    assert sqli is not None and 0.5 < sqli[0] < 1.0
    assert provider("access.idor") is None                  # logic class stays intel-free
    store = BanditStore(prior_provider=provider)
    assert store._get("injection.sqli", "generic").has_prior
