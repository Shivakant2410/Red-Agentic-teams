# statefuzz — Phase B prototype (Red-Agentic-teams registry tool)

State-machine business-logic fuzzer implementing the S9 spec of the
*Autonomous Offensive Security — Research Dossier* (Phase A). It points at a
**real HTTP scope** (loopback), induces the FSM by observation, mutates
transitions with 8 operators, and checks 5 invariant classes as executable
oracles — including the async/deferred column that the Phase-A survey found
empty across all 13 surveyed systems.

## Quickstart

```bash
pip install flask requests pytest
python run_demo.py --port 8377          # spawns the target, fuzzes, scores
python -m pytest tests/ -q              # 25 tests, ~3s
```

The demo target (`target/app.py`, "dvlba-shop") is a deliberately vulnerable
e-commerce API with 8 seeded business-logic bugs (`target/seeds.py` is ground
truth for scoring only — the fuzzer never imports it at runtime).

## Result of the shipped run (`results/`)

- **8/8 seeded bug classes discovered** in **87 real HTTP requests / 1.0s**
- All 5 invariant classes fired: I1 (3), I2 (2), I3 (2), I4 (1), I5 (1)
- 3 capability chains via the confused-deputy reachability search, 2 critical
- 9 findings + full replay transcript in `results/traffic.jsonl` (80 exchanges)

| Finding | Sev | Invariant | Operator | Endpoint |
|---|---|---|---|---|
| SF-REFUND-CROSS | critical | I3 | CROSS-USER | POST /api/orders/{id}/refund |
| SF-REFUND-REPLAY | critical | I1 | REPLAY+IDEMPOTENCE | POST /api/orders/{id}/refund |
| SF-ASYNC-DBL | critical | I1 | INTERRUPT+REPLAY (deferred) | POST /api/refunds/async |
| SF-NEG-QTY | high | I4 | NEGATIVE | POST /api/cart/items |
| SF-STACK-DISC | high | I1 | REPLAY | POST /api/coupon/apply |
| SF-SHIP-UNPAID | high | I2 | SKIP | POST /api/orders/{id}/ship |
| SF-IDOR-ORDER | high | I3 | CROSS-USER | GET /api/orders/{id} |
| SF-RACE-REDEEM | high | I5 | INTERRUPT (last-byte sync ×8) | POST /api/coupon/redeem |
| SF-CKOUT-REPLAY | medium | I2 | REPLAY | POST /api/checkout/init |

## Architecture ↔ dossier S9 map

| Module | Spec section | What it does |
|---|---|---|
| `statefuzz/model.py` | S9.2 `appmodel.py` | OpenAPI action inventory, multi-principal bootstrap, lawful walk → transition table, α-abstraction |
| `statefuzz/invariants.py` | S9.2 `invariants.py` | I1–I5 as pure oracle functions over observed evidence |
| `statefuzz/mutants.py` | S9.2 `mutants.py` | 8 pure plan transforms (SKIP, REPLAY, REORDER, PARTIAL, NEGATIVE, CROSS-USER, INTERRUPT, IDEMPOTENCE) |
| `statefuzz/executor.py` | S9.2 `executor.py` | Real-HTTP executor: budget, STOP kill-file, `traffic.jsonl`, last-byte-synchronised race primitive |
| `statefuzz/oracle.py` | S9.2 `oracle.py` | HypothesisLedger: deferred metamorphic verification across the async callback window |
| `statefuzz/chains.py` | S9.2 `chains.py` | findings-as-capabilities reachability (preconditions × grants) |
| `statefuzz/registry_tool.py` | S9.6 | `build_registry()` → `{"statefuzz_run": {schema(), run(ctx)}}`, LocalScopeGuard, approval tier, findings.json |

## Platform integration seams (`# Seam:` comments in code)

- `LocalScopeGuard` → swap for the platform ScopeGuard (fail-closed: loopback
  and RFC 5737 TEST-NET-1 only; public IPs refused).
- `approvals="lab"|"none"` → maps to the platform's approval gates; write-shaped
  mutants (NEGATIVE/REPLAY/INTERRUPT on state) require the lab tier.
- `results/findings.json` → same shape the orchestrator's verify pipeline
  consumes; findings carry `preconditions`, `grants`, `chain_ids`, evidence
  and curl reproductions.
- STOP kill file: creating `<out_dir>/STOP` halts the run cleanly (SF-STOP
  finding, no crash — covered by `test_stop_file_halts_cleanly`).

## Notes from execution (honest engineering log)

1. **Cross-probe state contamination**: the first run scored 7/8 because the
   negative-qty probe left `SKU-CABLE: -3` in the shared cart (checkout never
   clears it — which is itself bug B3), so the refund probe inherited a
   negative order total and its positive-delta gate failed. Fix: fresh
   principal per probe (state hygiene ≈ per-probe sandbox reset). This is
   exactly the probe-isolation rule argued in dossier S9.
2. **Race reliability**: the check-then-act window is 30 ms; the last-byte
   primitive lands all 8 writes inside it deterministically (8/8 winners in
   every run). Raw curl loops lose the window — that's the tradecraft point.
3. The single-use coupon `ONCE-9K4T` is consumed by the race probe; one lab
   run per server process (tests use a dedicated server fixture on :8399).

## Safety

- Targets only `127.0.0.1` / `localhost` / `192.0.2.0/24` (TEST-NET-1);
  anything else is refused by the scope guard before a single packet.
- The vulnerable target is our own code, spawned locally, terminated after
  each run. No external traffic.
