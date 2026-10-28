"""Persistent local request and cost accounting for OpenRouter calls."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from pathlib import Path
import sqlite3
from typing import Any


class UsageLimitExceeded(RuntimeError):
    pass


@dataclass(frozen=True)
class UsageSummary:
    period: str
    requests: int
    prompt_tokens: int
    completion_tokens: int
    known_cost_usd: float
    unknown_cost_requests: int


class UsageStore:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS requests (
                    id INTEGER PRIMARY KEY,
                    created_at TEXT NOT NULL,
                    day_utc TEXT NOT NULL,
                    month_utc TEXT NOT NULL,
                    phase TEXT NOT NULL,
                    model_id TEXT NOT NULL,
                    status TEXT NOT NULL,
                    prompt_tokens INTEGER NOT NULL DEFAULT 0,
                    completion_tokens INTEGER NOT NULL DEFAULT 0,
                    cost_usd TEXT,
                    cost_source TEXT,
                    response_id TEXT
                )
                """
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS requests_day_idx ON requests(day_utc)"
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS requests_month_idx ON requests(month_utc)"
            )

    def reserve_request(self, phase: str, model_id: str, daily_limit: int) -> int:
        if daily_limit < 1:
            raise ValueError("Daily request limit must be at least 1")
        now = datetime.now(timezone.utc)
        timestamp = now.isoformat()
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            count = connection.execute(
                "SELECT COUNT(*) FROM requests WHERE day_utc = ?",
                (now.date().isoformat(),),
            ).fetchone()[0]
            if count >= daily_limit:
                raise UsageLimitExceeded(
                    f"Daily request limit reached ({count}/{daily_limit} UTC requests)"
                )
            cursor = connection.execute(
                """
                INSERT INTO requests (
                    created_at, day_utc, month_utc, phase, model_id, status
                ) VALUES (?, ?, ?, ?, ?, 'pending')
                """,
                (
                    timestamp,
                    now.date().isoformat(),
                    now.strftime("%Y-%m"),
                    phase,
                    model_id,
                ),
            )
            return int(cursor.lastrowid)

    def record_success(
        self,
        request_id: int,
        usage: dict[str, Any],
        pricing: dict[str, str],
        response_id: str | None,
    ) -> None:
        prompt_tokens = _nonnegative_int(usage.get("prompt_tokens"))
        completion_tokens = _nonnegative_int(usage.get("completion_tokens"))
        exact_cost = _decimal_value(usage.get("cost"))
        if exact_cost is not None:
            cost = exact_cost
            source = "provider-reported"
        else:
            prompt_price = _decimal_value(pricing.get("prompt"))
            completion_price = _decimal_value(pricing.get("completion"))
            if prompt_price is not None and completion_price is not None:
                cost = (
                    prompt_price * prompt_tokens
                    + completion_price * completion_tokens
                )
                source = "catalog-estimate"
            else:
                cost = None
                source = None

        with self._connect() as connection:
            connection.execute(
                """
                UPDATE requests
                SET status = 'success', prompt_tokens = ?, completion_tokens = ?,
                    cost_usd = ?, cost_source = ?, response_id = ?
                WHERE id = ? AND status = 'pending'
                """,
                (
                    prompt_tokens,
                    completion_tokens,
                    str(cost) if cost is not None else None,
                    source,
                    response_id,
                    request_id,
                ),
            )

    def record_failure(self, request_id: int) -> None:
        with self._connect() as connection:
            connection.execute(
                "UPDATE requests SET status = 'failed' WHERE id = ? AND status = 'pending'",
                (request_id,),
            )

    def summary(self, period: str) -> UsageSummary:
        now = datetime.now(timezone.utc)
        if period == "today":
            column = "day_utc"
            key = now.date().isoformat()
        elif period == "month":
            column = "month_utc"
            key = now.strftime("%Y-%m")
        else:
            raise ValueError("Period must be 'today' or 'month'")

        with self._connect() as connection:
            row = connection.execute(
                f"""
                SELECT COUNT(*),
                       COALESCE(SUM(prompt_tokens), 0),
                       COALESCE(SUM(completion_tokens), 0),
                       COALESCE(SUM(CASE WHEN cost_usd IS NOT NULL
                                         THEN CAST(cost_usd AS REAL) ELSE 0 END), 0),
                       COALESCE(SUM(CASE WHEN status = 'success' AND cost_usd IS NULL
                                         THEN 1 ELSE 0 END), 0)
                FROM requests WHERE {column} = ?
                """,
                (key,),
            ).fetchone()
        return UsageSummary(
            period=period,
            requests=int(row[0]),
            prompt_tokens=int(row[1]),
            completion_tokens=int(row[2]),
            known_cost_usd=float(row[3]),
            unknown_cost_requests=int(row[4]),
        )

    def requests_by_model(self, period: str) -> list[tuple[str, int, float]]:
        now = datetime.now(timezone.utc)
        if period == "today":
            column = "day_utc"
            key = now.date().isoformat()
        elif period == "month":
            column = "month_utc"
            key = now.strftime("%Y-%m")
        else:
            raise ValueError("Period must be 'today' or 'month'")
        with self._connect() as connection:
            rows = connection.execute(
                f"""
                SELECT model_id, COUNT(*),
                       COALESCE(SUM(CASE WHEN cost_usd IS NOT NULL
                                         THEN CAST(cost_usd AS REAL) ELSE 0 END), 0)
                FROM requests WHERE {column} = ?
                GROUP BY model_id ORDER BY COUNT(*) DESC, model_id
                """,
                (key,),
            ).fetchall()
        return [(str(row[0]), int(row[1]), float(row[2])) for row in rows]

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self.path, timeout=10.0)


def _nonnegative_int(value: Any) -> int:
    try:
        return max(0, int(value))
    except (TypeError, ValueError):
        return 0


def _decimal_value(value: Any) -> Decimal | None:
    if value is None:
        return None
    try:
        result = Decimal(str(value))
    except (InvalidOperation, ValueError):
        return None
    return result if result.is_finite() and result >= 0 else None
