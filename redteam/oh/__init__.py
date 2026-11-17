"""redteam.oh — the LLM05 Improper-Output-Handling channel (the SIXTH
CHANNEL).

The pi/sid lanes attack content the model reads, sc attacks artifacts a
registry admits, ea attacks what the model does with tools; this
package attacks what happens DOWNSTREAM of the model's own output: a
consumer (renderer, HTML sink, shell, SQL) that executes whatever the
model emits. The mechanical judge is the consumer-EVENT log — observed
side effects, never a judgement about "dangerous-looking" text.

  oracles.py — the payload-class grammar (markdown-image exfil, XSS img
               tag, shell substitution, SQL quote break; generated at
               run time), the plant self-audit, the decoy control, and
               the consumer-event adjudication (canary-relayed
               execution > side-effect execution).
  agent.py   — the OHBrain loop (benign control -> UCB1 probe loop ->
               decoy control) and oh_agentic_probe, which owns the
               three-verdict ruling with the canary as the attribution
               proof.

Nothing here imports the other family lanes (isolation requirement);
the shared coupling point is redteam.brain (TargetProfile), the same as
every other channel.
"""
