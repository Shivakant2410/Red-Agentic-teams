# Prototype Pollution

**CWE-1321** · 1 skill(s) · folder `categories/prototype_pollution/`

## Skills in this shelf

- `elite/Prototype pollution Node status gadget` (CWE-1321)

## Technique

Query/JSON merge gadgets write into Object.prototype (`__proto__[key]=value`), then a SECOND request observes the pollution through a gadget that inherits the polluted key.

## Proof design (why it is falsifiable)

Two-request design: pollute, then observe via a gadget (response splits on a polluted value, status-code gadget 510 Not Extended). Benign pollution of an unused key leaves the gadget inert.

## Bypass variants / escalation ("think more beats level")

- constructor.prototype spelling past __proto__ filters
- JSON body merge gadgets (lodash.merge / deepAssign families)
- Client-side PP -> DOM XSS via gadget chaining
- PP -> RCE in Node tools (child_process spawn env gadgets)
- Sync-trigger pairs when pollution requires a restart of a cached object

## Sources (copied & rewritten into our proof-first DSL)

- swisskyrepo/PayloadsAllTheThings — Prototype Pollution
- HackTricks book — Prototype Pollution gadget lists

## False positives to rule out

Frameworks that ignore __proto__ entirely — gadget observation request is what fails on them.
