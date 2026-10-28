"""Tests for importing nuclei templates as executable skills (faithful-or-skip)."""

from __future__ import annotations

import yaml

from redteam.importers.nuclei import TARGET, parse_template
from redteam.skills import SkillLibrary, substitute

SINGLE_MATCHER = yaml.safe_load("""
id: git-config
info:
  name: Git Config Exposure
  severity: medium
  description: Detects exposed .git/config
  classification:
    cwe-id: CWE-200
http:
  - method: GET
    path:
      - "{{BaseURL}}/.git/config"
    matchers:
      - type: word
        words:
          - "[core]"
        part: body
""")

AND_MATCHERS = yaml.safe_load("""
id: panel
info:
  name: Admin Panel
  severity: low
http:
  - method: GET
    path:
      - "{{BaseURL}}/admin"
    matchers-condition: and
    matchers:
      - type: status
        status:
          - 200
      - type: word
        words:
          - "Administration"
        part: body
""")

OR_MATCHERS = yaml.safe_load("""
id: loose
info:
  name: Loose OR template
http:
  - method: GET
    path: ["{{BaseURL}}/x"]
    matchers:
      - type: status
        status: [200]
      - type: word
        words: ["hello"]
""")

DSL_MATCHER = yaml.safe_load("""
id: dsl
info:
  name: DSL template
http:
  - method: GET
    path: ["{{BaseURL}}/y"]
    matchers:
      - type: dsl
        dsl: ["len(body) > 100"]
""")


def test_single_matcher_template_imports():
    requests, conditions, name, desc, cwe = parse_template(SINGLE_MATCHER)
    assert requests["payload"]["url"] == "{{%s}}/.git/config" % TARGET
    assert conditions == [{"type": "body_regex", "request": "payload",
                           "pattern": r"\[core\]", "present": True}]
    assert cwe == "CWE-200" and "Git Config" in name


def test_and_matchers_become_all_conditions():
    requests, conditions, *_ = parse_template(AND_MATCHERS)
    types = [c["type"] for c in conditions]
    assert "status" in types and "body_regex" in types
    assert len(conditions) == 2          # AND -> every condition must hold


def test_or_across_matchers_is_skipped_not_faked():
    # nuclei defaults to OR; we refuse rather than mis-import (false-positive safety)
    assert parse_template(OR_MATCHERS) is None


def test_unsupported_matcher_type_skipped():
    assert parse_template(DSL_MATCHER) is None


def test_multi_word_or_becomes_alternation():
    doc = yaml.safe_load("""
id: alt
info: {name: Alt}
http:
  - method: GET
    path: ["{{BaseURL}}/z"]
    matchers:
      - type: word
        words: ["alpha", "beta"]
        part: body
""")
    _, conditions, *_ = parse_template(doc)
    assert conditions[0]["pattern"] == "(?:alpha|beta)"   # exact OR semantics preserved


def test_imported_skill_is_executable_with_one_param(tmp_path):
    lib = SkillLibrary(tmp_path / "s.json")
    requests, conditions, name, desc, cwe = parse_template(SINGLE_MATCHER)
    skill = lib.register(name=name, description=desc, requests=requests,
                         conditions=conditions, params=[TARGET], cwe=cwe, source="nuclei")
    assert skill.params == [TARGET] and skill.source == "nuclei"
    concrete = substitute(skill.requests, {TARGET: "https://app.example"})
    assert concrete["payload"]["url"] == "https://app.example/.git/config"


def test_register_is_idempotent(tmp_path):
    lib = SkillLibrary(tmp_path / "s.json")
    r, c, n, d, w = parse_template(SINGLE_MATCHER)
    a = lib.register(n, d, r, c, [TARGET], w, "nuclei")
    b = lib.register(n, d, r, c, [TARGET], w, "nuclei")
    assert a.id == b.id and lib.summary()["skills"] == 1
