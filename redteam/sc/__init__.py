"""redteam.sc — OWASP LLM03:2025 Supply Chain lane.

The third OWASP category lane. The harm here is BYTE- and METADATA-shaped
and the target is not a chat surface but the artifact supply chain itself:
serialized model weights, dependency names, version pins, provenance
metadata. The lane is fully isolated (no imports from the pi/sid lanes)
and keeps the house abstraction: deterministic oracles, facts before
verdicts, verdicts minted only by the lane's runner with controls.

What is structurally different from LLM01/LLM02:

  - there is no attacker loop over a conversation — the "probe" is a
    static adjudication of artifacts, so the oracle family is a scanner;
  - the scanner must NEVER deserialize (a pickle's __reduce__ executes on
    load — loading IS the attack); it walks opcodes with pickletools;
  - the field's own lesson (JFrog 2024-2025 picklescan bypasses, Cisco
    'Breaking the Jar' 2025) is encoded as findings: trailing payload
    bytes after STOP (pickle.loads executes the prefix and ignores the
    rest) and malformed streams are first-class evidence, not parse noise;
  - control artifacts (benign twins) are generated deterministically per
    seed — the negative control the earned-resistance semantics will
    require.
"""
