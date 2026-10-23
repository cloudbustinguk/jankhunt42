"""Ledger access for the synthetic demo payments service."""
import os

import psycopg

DSN = os.environ["DATABASE_URL"]


def balance(account_id: int) -> int:
    with psycopg.connect(DSN) as conn:
        row = conn.execute("SELECT balance FROM accounts WHERE id = %s", (account_id,)).fetchone()
        return row[0] if row else 0


def purge(before: str) -> None:
    with psycopg.connect(DSN) as conn:
        conn.execute("DELETE FROM ledger_entries WHERE created_at < %s", (before,))
