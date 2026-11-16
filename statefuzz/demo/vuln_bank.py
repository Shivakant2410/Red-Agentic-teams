# -*- coding: utf-8 -*-
"""demo/vuln_bank.py — the DVLBA-style reference target for statefuzz.

A small in-process banking API (Mealy machine over account entities) with
FIVE SEEDED LOGIC BUGS, each toggled by the `bugs` mask. The same codebase
instantiates vulnerable or fixed; the truth is machine-checkable by
construction — this is what makes oracle precision measurable (dossier 10.1).

  bug mask          seeded logic bug (invariant it violates)
  ---------------   ------------------------------------------------
  "neg_amount"      amount domain not enforced: negative/zero amounts
                    accepted on deposit/withdraw/transfer (I4)
  "no_idem"         Idempotency-Key ignored: retries apply effects twice (I5)
  "xsu_read"        statement endpoint skips the owner check (I3, read)
  "xsu_write"       deposit/withdraw/transfer skip the owner check on the
                    debited account (I3, write — funds extraction)
  "race_rmw"        withdraw does an unsynchronized read-modify-write with a
                    50ms window: synchronized requests all read the same
                    balance, one debit is recorded, n payouts leave (I1)
  "illegal_reopen"  deposit to a CLOSED account succeeds and flips it back to
                    open, bypassing the re-open flow (I2)

Endpoints:
  POST /accounts/{id}/deposit    {amount}     (mint edge)
  POST /accounts/{id}/withdraw   {amount}     (burn edge)
  POST /transfers                {from,to,amount}
  GET  /accounts/{id}/statement               (owner-checked read)
  POST /accounts/{id}/close                   (open -> closed)

Principals: "A" (alice, account acc:A1, balance 1000) and "B" (bob, account
acc:B1, balance 50). The adapter satisfies the platform contract: it is the
only component that touches app state; statefuzz sees only plans/responses
and snapshots (the alpha input).
"""
from __future__ import annotations

import threading
import time
from typing import Dict, List, Optional, Set

from ..appmodel import ObservedState, RequestPlan, Response

PRINCIPALS = {"A": "alice", "B": "bob"}
RACE_WINDOW_S = 0.05


class BankApp:
    """In-process target. bugs=frozenset() -> fixed build."""

    def __init__(self, bugs: Optional[Set[str]] = None):
        self.bugs: Set[str] = set(bugs or ())
        self._lock = threading.Lock()
        self._idem: Dict[str, dict] = {}
        self.reset()

    def reset(self) -> None:
        self.accounts: Dict[str, dict] = {
            "acc:A1": {"owner": "A", "status": "open", "balance": 1000.0},
            "acc:B1": {"owner": "B", "status": "open", "balance": 50.0},
        }
        self.events: List[dict] = []
        self._idem.clear()

    # -- adapter contract ---------------------------------------------------
    def adapter(self, plan: RequestPlan) -> Response:
        principal = plan.principal if plan.principal in PRINCIPALS else None
        if principal is None:
            return Response(401, {"error": "unknown principal"})
        segs = [s for s in plan.path.split("/") if s]
        try:
            if plan.method == "POST" and len(segs) == 3 and segs[1] and \
                    segs[0] == "accounts" and segs[2] == "deposit":
                return self._deposit(principal, segs[1], plan)
            if plan.method == "POST" and len(segs) == 3 and \
                    segs[0] == "accounts" and segs[2] == "withdraw":
                return self._withdraw(principal, segs[1], plan)
            if plan.method == "POST" and segs == ["transfers"]:
                return self._transfer(principal, plan)
            if plan.method == "GET" and len(segs) == 3 and \
                    segs[0] == "accounts" and segs[2] == "statement":
                return self._statement(principal, segs[1])
            if plan.method == "POST" and len(segs) == 3 and \
                    segs[0] == "accounts" and segs[2] == "close":
                return self._close(principal, segs[1])
        except (KeyError, TypeError, ValueError):
            return Response(500, {"error": "internal"})
        return Response(404, {"error": "not-found"})

    def observe(self) -> ObservedState:
        with self._lock:
            facts = {f"account:{k}": dict(v) for k, v in self.accounts.items()}
            events = [dict(e) for e in self.events]
        label = "acct:closed" if any(
            a.get("status") == "closed" for a in facts.values()) else "acct:open"
        return ObservedState(facts=facts, events=events, state_label=label)

    # -- handlers -------------------------------------------------------------
    def _amount(self, plan: RequestPlan) -> Optional[float]:
        body = plan.body or {}
        v = body.get("amount")
        if isinstance(v, bool) or not isinstance(v, (int, float)):
            return None
        return float(v)

    def _domain_ok(self, amt: float) -> bool:
        if "neg_amount" in self.bugs:
            return True                       # SEEDED BUG: domain not enforced
        return 0.0 < amt <= 1_000_000

    def _record(self, key: Optional[str], route: str, principal: str) -> None:
        self.events.append({"kind": "applied_effect", "idempotency_key": key,
                            "route": route, "principal": principal,
                            "ts": round(time.time(), 3)})

    def _idem_replay(self, plan: RequestPlan) -> Optional[Response]:
        key = (plan.headers or {}).get("Idempotency-Key")
        if not key:
            return None
        if "no_idem" in self.bugs:
            return None                       # SEEDED BUG: key ignored
        cached = self._idem.get((key, plan.path, plan.principal))
        if cached is not None:
            return Response(200, {**cached, "replayed": True})
        return None

    def _remember(self, plan: RequestPlan, body: dict) -> None:
        key = (plan.headers or {}).get("Idempotency-Key")
        if key and "no_idem" not in self.bugs:
            self._idem[(key, plan.path, plan.principal)] = dict(body)

    def _deposit(self, principal: str, acct_id: str, plan: RequestPlan) -> Response:
        acct = self.accounts.get(acct_id)
        if acct is None:
            return Response(404, {"error": "no-account"})
        replay = self._idem_replay(plan)
        if replay is not None:
            return replay
        amt = self._amount(plan)
        if amt is None or not self._domain_ok(amt):
            return Response(422, {"error": "amount-domain"})
        # owner check — SEEDED BUG xsu_write skips it
        if "xsu_write" not in self.bugs and acct["owner"] != principal:
            return Response(403, {"error": "not-owner"})
        if acct["status"] != "open":
            if "illegal_reopen" not in self.bugs:
                return Response(409, {"error": "account-closed"})
            # SEEDED BUG: deposit reopens a closed account
            acct["status"] = "open"
        with self._lock:
            acct["balance"] = round(acct["balance"] + amt, 6)
            self._record((plan.headers or {}).get("Idempotency-Key"),
                         "deposit", principal)
        self._remember(plan, {"deposited": amt})
        return Response(200, {"account": acct_id, "deposited": amt,
                              "balance": acct["balance"]})

    def _withdraw(self, principal: str, acct_id: str, plan: RequestPlan) -> Response:
        acct = self.accounts.get(acct_id)
        if acct is None:
            return Response(404, {"error": "no-account"})
        replay = self._idem_replay(plan)
        if replay is not None:
            return replay
        amt = self._amount(plan)
        if amt is None or not self._domain_ok(amt):
            return Response(422, {"error": "amount-domain"})
        if "xsu_write" not in self.bugs and acct["owner"] != principal:
            return Response(403, {"error": "not-owner"})
        if acct["status"] != "open":
            return Response(409, {"error": "account-closed"})
        if "race_rmw" in self.bugs:
            # SEEDED BUG: unsynchronized RMW — every concurrent caller reads
            # the same balance; n payouts leave, one debit is recorded.
            bal = acct["balance"]
            if bal < amt:
                return Response(409, {"error": "insufficient-funds"})
            time.sleep(RACE_WINDOW_S)
            acct["balance"] = round(bal - amt, 6)
            self._record((plan.headers or {}).get("Idempotency-Key"),
                         "withdraw", principal)
            self._remember(plan, {"withdrawn": amt})
            return Response(200, {"account": acct_id, "withdrawn": amt,
                                  "balance": acct["balance"]})
        with self._lock:
            if acct["balance"] < amt:
                return Response(409, {"error": "insufficient-funds"})
            acct["balance"] = round(acct["balance"] - amt, 6)
            self._record((plan.headers or {}).get("Idempotency-Key"),
                         "withdraw", principal)
        self._remember(plan, {"withdrawn": amt})
        return Response(200, {"account": acct_id, "withdrawn": amt,
                              "balance": acct["balance"]})

    def _transfer(self, principal: str, plan: RequestPlan) -> Response:
        body = plan.body or {}
        src, dst = body.get("from"), body.get("to")
        src_acct, dst_acct = self.accounts.get(src), self.accounts.get(dst)
        if src_acct is None or dst_acct is None:
            return Response(404, {"error": "no-account"})
        replay = self._idem_replay(plan)
        if replay is not None:
            return replay
        amt = self._amount(plan)
        if amt is None or not self._domain_ok(amt):
            return Response(422, {"error": "amount-domain"})
        # owner check on the DEBITED side — SEEDED BUG xsu_write skips it
        if "xsu_write" not in self.bugs and src_acct["owner"] != principal:
            return Response(403, {"error": "not-owner"})
        if src_acct["status"] != "open" and "xsu_write" not in self.bugs:
            return Response(409, {"error": "account-closed"})
        with self._lock:
            if src_acct["balance"] < amt:
                return Response(409, {"error": "insufficient-funds"})
            src_acct["balance"] = round(src_acct["balance"] - amt, 6)
            dst_acct["balance"] = round(dst_acct["balance"] + amt, 6)
            self._record((plan.headers or {}).get("Idempotency-Key"),
                         "transfer", principal)
        self._remember(plan, {"transferred": amt})
        return Response(200, {"from": src, "to": dst, "transferred": amt})

    def _statement(self, principal: str, acct_id: str) -> Response:
        acct = self.accounts.get(acct_id)
        if acct is None:
            return Response(404, {"error": "no-account"})
        # owner check — SEEDED BUG xsu_read skips it
        if "xsu_read" not in self.bugs:
            if acct["owner"] != principal:
                return Response(403, {"error": "not-owner"})
            if acct["status"] != "open":
                return Response(410, {"error": "account-closed"})
        return Response(200, {"account": acct_id, "owner": acct["owner"],
                              "status": acct["status"],
                              "balance": acct["balance"]})

    def _close(self, principal: str, acct_id: str) -> Response:
        acct = self.accounts.get(acct_id)
        if acct is None:
            return Response(404, {"error": "no-account"})
        if acct["owner"] != principal:
            return Response(403, {"error": "not-owner"})
        if acct["status"] != "open":
            return Response(409, {"error": "already-closed"})
        acct["status"] = "closed"
        return Response(200, {"account": acct_id, "status": "closed"})


# --------------------------------------------------------------------------
# The induced-machine spec the extractor consumes (dossier 9.1: evidence
# source 1 — OpenAPI-lite; guards/effects normally arrive via the LLM
# labeler, here annotated directly).
# --------------------------------------------------------------------------

BANK_SPEC = {
    "name": "vuln-bank",
    "initial_state": "acct:open",
    "abstraction_rules": [["\"status\": \"closed\"", "acct:closed"]],
    "transitions": [
        {"id": "T1", "method": "POST", "path": "/accounts/{id}/deposit",
         "source": "acct:open", "target": "acct:open", "writes": True,
         "idempotent": True,
         "params": {"path_defaults": {"id": "acc:A1"}, "body": {"amount": 100},
                    "owner_checked": ["path:id"], "boundary": "mint"},
         "guard": "caller owns the account and it is open",
         "effect": "credits amount (mint edge)",
         "requires": ["auth:low", "knows:account_id:own"],
         "grants": ["account:written:own"]},
        {"id": "T2", "method": "POST", "path": "/accounts/{id}/withdraw",
         "source": "acct:open", "target": "acct:open", "writes": True,
         "idempotent": True,
         "params": {"path_defaults": {"id": "acc:A1"}, "body": {"amount": 500},
                    "owner_checked": ["path:id"], "boundary": "burn"},
         "guard": "caller owns the account, open, sufficient funds",
         "effect": "debits amount (burn edge)",
         "requires": ["auth:low", "knows:account_id:own"],
         "grants": ["account:written:own", "move:funds"]},
        {"id": "T3", "method": "POST", "path": "/transfers",
         "source": "acct:open", "target": "acct:open", "writes": True,
         "idempotent": True,
         "params": {"path_defaults": {},
                    "body": {"from": "acc:A1", "to": "acc:B1", "amount": 50},
                    "owner_checked": ["body:from"]},
         "guard": "caller owns the source account; counterparty known",
         "effect": "moves amount between accounts",
         "requires": ["auth:low", "knows:account_id:other"],
         "grants": ["account:written:own", "move:funds"]},
        {"id": "T4", "method": "GET", "path": "/accounts/{id}/statement",
         "source": "acct:open", "target": "acct:open", "writes": False,
         "params": {"path_defaults": {"id": "acc:A1"},
                    "owner_checked": ["path:id"]},
         "guard": "caller owns the account",
         "effect": "returns balance and status",
         "requires": ["auth:low", "knows:account_id:own"],
         "grants": ["knows:account_id:other", "read:account_snapshot:other"]},
        {"id": "T5", "method": "POST", "path": "/accounts/{id}/close",
         "source": "acct:open", "target": "acct:closed", "writes": True,
         "params": {"path_defaults": {"id": "acc:A1"},
                    "owner_checked": ["path:id"],
                    "requires_requests": [
                        {"method": "GET",
                         "path": "/accounts/acc:A1/statement"}]},
         "guard": "caller owns the open account (compliance check done)",
         "effect": "open -> closed",
         "requires": ["auth:low", "knows:account_id:own"],
         "grants": ["account:closed"]},
    ],
}

DEMO_PRIORS = {  # platform-tunable bandit priors: races and reorders probe
    "SF-SKIP": 10.0, "SF-REPLAY": 10.0, "SF-REORDER": 13.0,  # state-divergence early
    "SF-PARTIAL": 10.0, "SF-NEGATIVE": 12.0, "SF-CROSSUSER": 12.0,
    "SF-RACE": 14.0, "SF-IDEM": 10.0,
}

VULNERABLE_BUGS = {"neg_amount", "no_idem", "xsu_read", "xsu_write",
                   "race_rmw", "illegal_reopen"}
