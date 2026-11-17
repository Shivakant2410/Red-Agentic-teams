"""redteam.sid — OWASP LLM02:2025 Sensitive Information Disclosure lane.

The second OWASP category lane, built on the abstraction the PI lane
established (three verdicts exactly, earned resistance, masked evidence,
compute never decides) and deliberately ISOLATED: nothing here imports the
app-engagement red-team package. What is structurally different from LLM01,
and why a separate lane exists:

  - the harm is CLASS-shaped, not token-shaped (deterministic detectors);
  - the plant lives in the TARGET'S context, never in the payload
    (a payload-carried secret echoed back is a fake success);
  - training-data extraction cannot be planted at all — it is probed with
    research-anchored elicitation shapes and verified against stored
    public-domain canon.

Boundary honesty: system-prompt extraction is LLM07 (separate lane);
embedding-store leakage is LLM08; membership inference is statistical and
declared known-uncovered. See techniques.coverage_audit().
"""
