"""Ground truth: the 10 fortress seeds. EVALUATION ONLY — the tools never
import this file at runtime; the runner loads it AFTER a run to score
discovery. Tiers: MEDIUM < HARD < BRUTAL."""

SEEDS = [
    {"id": "F1", "tier": "HARD", "class": "I5",
     "endpoint": "POST /api/promo/claim",
     "bug": "promo quota check-then-act (35ms window): a last-byte race of 8 "
            "fresh principals claims past quota 3",
     "detect_with": "multi-principal synchronized race, then force-exhaust "
                    "the code to learn the quota; successful claims > quota"},
    {"id": "F2", "tier": "HARD", "class": "I4",
     "endpoint": "POST /api/subscriptions/{id}/seats",
     "bug": "asymmetric proration rounding (credit ceil / charge floor): each "
            "down->up resize cycle drifts +1 cent, invisible per event",
     "detect_with": "cycle resize N times on one subscription; net wallet "
                    "delta of a round-trip must be <= 0, observed +N"},
    {"id": "F3", "tier": "BRUTAL", "class": "I2",
     "endpoint": "POST /api/subscriptions/{id}/seats",
     "bug": "seat resize accepted on a CANCELED subscription: re-credits the "
            "full prorated remainder after cancel already credited it",
     "detect_with": "lawful walk to terminal state (cancel), then resize; "
                    "unmodeled transition accepted + wallet credited again"},
    {"id": "F4", "tier": "BRUTAL", "class": "I1/I4",
     "endpoint": "POST /api/payouts",
     "bug": "payout debits at async settle (0.6s) with no balance re-check: "
            "transfer the full balance out during the window -> negative",
     "detect_with": "request payout -> transfer full balance to accomplice -> "
                    "await settle event -> wallet balance below zero"},
    {"id": "F5", "tier": "MEDIUM", "class": "I3",
     "endpoint": "GET /api/audit",
     "bug": "global audit trail has no tenant filter: any account reads every "
            "other tenant's subscription/payout identifiers",
     "detect_with": "victim creates objects; fresh principal reads audit; "
                    "victim's object ids appear in the response"},
    {"id": "F6", "tier": "BRUTAL", "class": "I3",
     "endpoint": "POST /api/subscriptions/{id}/seats",
     "bug": "no ownership check on seat resize and the proration credit lands "
            "in the CALLER's balance (chain enabler: F5 leaks victim ids)",
     "detect_with": "downgrade a leaked victim subscription as the attacker; "
                    "attacker wallet increases, victim unaffected"},
    {"id": "F7", "tier": "HARD", "class": "I4",
     "endpoint": "POST /api/subscriptions",
     "bug": "mass assignment: client-supplied unit_cents overrides the "
            "official unit price (documented nowhere)",
     "detect_with": "schema transplantation probe: inject unit_cents=1 into "
                    "create; invoice total differs from identical lawful create"},
    {"id": "F8", "tier": "HARD", "class": "I2/I4",
     "endpoint": "POST /api/subscriptions/{id}/seats",
     "bug": "mass assignment: undocumented 'plan' field on the seats endpoint "
            "upgrades the plan without repricing",
     "detect_with": "resize with extra plan field; readback plan changed but "
                    "wallet delta equals the old-plan resize delta"},
    {"id": "F9", "tier": "BRUTAL", "class": "I1",
     "endpoint": "POST /api/subscriptions/{id}/cancel",
     "bug": "cancel dedupe is keyed by (subscription, reason): replaying with "
            "a different reason string re-credits the full remainder",
     "detect_with": "cancel (credit) -> replay same body (409, guarded) -> "
                    "replay with mutated reason (200, credited again)"},
    {"id": "F10", "tier": "BRUTAL", "class": "I1",
     "endpoint": "POST /api/payouts/{id}/cancel",
     "bug": "no status guard on payout cancel: canceling an already-SETTLED "
            "payout refunds the balance while the external transfer stands "
            "(hidden /api/payouts/{id}/release accelerates settlement)",
     "detect_with": "payout -> settle (release or await worker) -> cancel -> "
                    "wallet delta is 0 while amount_cents went external"},
]

TIER_ORDER = {"MEDIUM": 1, "HARD": 2, "BRUTAL": 3}
