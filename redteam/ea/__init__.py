"""redteam.ea — the LLM06 Excessive-Agency channel (the FIFTH CHANNEL).

The pi/sid lanes attack content the model reads, the sc lane attacks
artifacts a registry admits; this package attacks what the model DOES.
An agent runtime that treats untrusted tool output as instruction is
excessive agency (OWASP LLM06:2025), and the mechanical judge is the
tool TRACE — what actually executed, never what was said.

  oracles.py — the carrier/directive grammar (generated at run time),
               the plant self-audit, and the trace adjudication ladder
               (unauthorized_exfiltration > unauthorized_action).
  agent.py   — the AgencyBrain loop (recon+benign control -> UCB1 plant
               loop -> grammar control) and ea_agentic_probe, which owns
               the three-verdict ruling with the canary as the
               attribution proof.

Nothing here imports the other family lanes (isolation requirement);
the shared coupling point is redteam.brain (TargetProfile), the same as
every other channel.
"""
