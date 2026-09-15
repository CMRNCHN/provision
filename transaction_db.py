"""
Transaction Database Module
Local storage for company card transactions, encrypted at rest via SQLCipher
(owner-only file permissions on top).
"""

from __future__ import annotations

import logging
import os
import re
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from sqlcipher3 import dbapi2 as sqlcipher

DB_PATH = Path.home() / ".provision_transactions.db"

# sqlcipher3's exception hierarchy is its own C extension's classes, not a
# subclass of sqlite3's — every `except` in this module needs both, or a
# real failure (e.g. the wrong key) propagates uncaught instead of being
# logged and handled the way this module's callers expect.
DB_ERRORS = (sqlite3.Error, sqlcipher.Error)

_HEX_KEY_RE = re.compile(r"^[0-9a-f]+$")


def _pragma_key_sql(key: str) -> str:
    """Build `PRAGMA key = "x'<hex>'"` — SQLCipher's raw-hex-key syntax.

    Used (rather than a passphrase-style `PRAGMA key = '...'`, which runs an
    extra KDF pass) because the key is already high-entropy random hex from
    integrations.get_or_create_db_key(). PRAGMA statements don't support `?`
    parameter binding, so this is built as a string — restricted to hex
    digits only, so there's nothing to escape.
    """
    if not key or not _HEX_KEY_RE.match(key):
        raise ValueError("Transaction DB encryption key must be non-empty hex.")
    return f"PRAGMA key = \"x'{key}'\""


class TransactionDatabase:
    """SQLCipher-encrypted transaction storage with owner-only file permissions."""

    def __init__(self, db_path: Optional[Path] = None, *, encryption_key: str):
        self.db_path = Path(db_path) if db_path else DB_PATH
        self.encryption_key = encryption_key
        self._migrate_plaintext_db_if_needed()
        self._init_db()

    def _get_connection(self) -> sqlcipher.Connection:
        try:
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
            if not self.db_path.exists():
                try:
                    fd = os.open(self.db_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
                    os.close(fd)
                except FileExistsError:
                    pass
            self._ensure_permissions()
            conn = sqlcipher.connect(str(self.db_path))
            conn.execute(_pragma_key_sql(self.encryption_key))
            # SQLCipher doesn't validate the key at PRAGMA time — a wrong
            # key silently "succeeds" here and only fails later, on the
            # first real read, as a garbled low-level error (a MemoryError
            # has been observed) instead of a clean one. Force validation
            # now so a bad key always fails the same clean, obvious way.
            conn.execute("SELECT count(*) FROM sqlite_master")
            return conn
        except DB_ERRORS as e:
            logging.error("Database connection error: %s", e)
            raise

    def _migrate_plaintext_db_if_needed(self) -> None:
        """One-time upgrade path: a DB written before SQLCipher was added is
        plain, readable SQLite. Detect that, copy every row into a freshly
        encrypted file, and replace the plaintext one. Safe to call on every
        startup — it's a no-op once the file is already encrypted (or
        doesn't exist yet).
        """
        if not self.db_path.exists() or self.db_path.stat().st_size == 0:
            return

        try:
            probe = sqlcipher.connect(str(self.db_path))
            probe.execute(_pragma_key_sql(self.encryption_key))
            probe.execute("SELECT count(*) FROM sqlite_master")
            probe.close()
            return  # already encrypted with the current key — nothing to do
        except DB_ERRORS:
            pass

        try:
            legacy = sqlite3.connect(str(self.db_path))
            legacy.execute("SELECT count(*) FROM sqlite_master")
        except sqlite3.Error:
            # Not plaintext SQLite either (e.g. encrypted with a lost key).
            # Don't guess — leave it alone and let _init_db() surface a
            # clear error rather than silently discarding data.
            logging.error(
                "Transaction DB at %s is neither plaintext SQLite nor "
                "readable with the current key; leaving it untouched.",
                self.db_path,
            )
            return

        logging.info("Migrating plaintext transaction DB at %s to SQLCipher encryption.", self.db_path)
        tmp_path = self.db_path.with_suffix(self.db_path.suffix + ".migrating")
        tmp_path.unlink(missing_ok=True)
        try:
            # sqlite3.Connection.backup() rejects a foreign sqlcipher3
            # connection as its target (cross-module type check), so copy
            # by hand: replay each table's own CREATE TABLE, then its rows.
            # Table structure comes straight from the legacy DB's own
            # sqlite_master rather than a second, separately-maintained
            # copy of the schema, so this can't drift out of sync with it.
            encrypted = sqlcipher.connect(str(tmp_path))
            encrypted.execute(_pragma_key_sql(self.encryption_key))

            tables = legacy.execute(
                "SELECT name, sql FROM sqlite_master "
                "WHERE type = 'table' AND sql IS NOT NULL AND name NOT LIKE 'sqlite\\_%' ESCAPE '\\'"
            ).fetchall()
            row_count = 0
            for table_name, create_sql in tables:
                encrypted.execute(create_sql)
                rows = legacy.execute(f"SELECT * FROM {table_name}").fetchall()
                if rows:
                    placeholders = ",".join("?" * len(rows[0]))
                    encrypted.executemany(
                        f"INSERT INTO {table_name} VALUES ({placeholders})", rows
                    )
                    row_count += len(rows)

            encrypted.commit()
            encrypted.close()
            legacy.close()
            os.chmod(tmp_path, 0o600)
            tmp_path.replace(self.db_path)
            logging.info(
                "Transaction DB migration to SQLCipher complete: %d table(s), %d row(s).",
                len(tables),
                row_count,
            )
        except Exception:
            logging.error("Transaction DB migration to SQLCipher failed; leaving plaintext file in place.", exc_info=True)
            tmp_path.unlink(missing_ok=True)
            try:
                legacy.close()
            except Exception:
                pass
            raise

    def _ensure_permissions(self) -> None:
        """Restrict DB file to owner read/write only (0o600)."""
        if self.db_path.exists():
            try:
                os.chmod(self.db_path, 0o600)
            except OSError as e:
                raise PermissionError(
                    f"Could not restrict database permissions on {self.db_path}"
                ) from e

    def _init_db(self):
        try:
            conn = self._get_connection()
            cursor = conn.cursor()

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS transactions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    date TEXT NOT NULL,
                    amount REAL NOT NULL,
                    merchant TEXT NOT NULL,
                    employee_name TEXT NOT NULL,
                    card_number TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    employee_file_date TEXT,
                    employee_id TEXT
                )
            """)
            cursor.execute("PRAGMA table_info(transactions)")
            if "employee_id" not in {row[1] for row in cursor.fetchall()}:
                cursor.execute("ALTER TABLE transactions ADD COLUMN employee_id TEXT")

            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_employee
                ON transactions(employee_name)
            """)

            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_date
                ON transactions(date)
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_employee_id
                ON transactions(employee_id)
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS employee_budgets (
                    employee_id TEXT PRIMARY KEY,
                    employee_name TEXT NOT NULL,
                    opening_spend REAL NOT NULL DEFAULT 0,
                    spend_limit REAL NOT NULL,
                    updated_at TEXT NOT NULL
                )
            """)

            conn.commit()
            conn.close()
            self._ensure_permissions()
            logging.info("Transaction database initialized")
        except DB_ERRORS as e:
            logging.error("Database initialization error: %s", e)
            raise

    def add_transaction(
        self,
        date: str,
        amount: float,
        merchant: str,
        employee_name: str,
        card_number: str,
        employee_file_date: Optional[str] = None,
        employee_id: Optional[str] = None,
    ) -> bool:
        try:
            conn = self._get_connection()
            cursor = conn.cursor()

            created_at = datetime.now().isoformat()
            cursor.execute(
                """
                INSERT INTO transactions
                (date, amount, merchant, employee_name, card_number, created_at,
                 employee_file_date, employee_id)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    date,
                    amount,
                    merchant,
                    employee_name,
                    card_number,
                    created_at,
                    employee_file_date,
                    employee_id,
                ),
            )

            conn.commit()
            conn.close()
            self._ensure_permissions()
            logging.info("Added transaction: %s - $%.2f for %s", merchant, amount, employee_name)
            return True
        except DB_ERRORS as e:
            logging.error("Failed to add transaction: %s", e)
            return False

    def get_all_transactions(self) -> List[Dict[str, Any]]:
        try:
            conn = self._get_connection()
            cursor = conn.cursor()

            cursor.execute("""
                SELECT id, date, amount, merchant, employee_name, card_number,
                       created_at, employee_file_date, employee_id
                FROM transactions
                ORDER BY date DESC
            """)

            transactions = []
            for row in cursor.fetchall():
                transactions.append({
                    "id": row[0],
                    "date": row[1],
                    "amount": row[2],
                    "merchant": row[3],
                    "employee_name": row[4],
                    "card_number": row[5],
                    "created_at": row[6],
                    "employee_file_date": row[7],
                    "employee_id": row[8],
                })

            conn.close()
            return transactions
        except DB_ERRORS as e:
            logging.error("Failed to retrieve transactions: %s", e)
            return []

    def get_transactions_by_employee(self, employee_name: str) -> List[Dict[str, Any]]:
        try:
            conn = self._get_connection()
            cursor = conn.cursor()

            cursor.execute(
                """
                SELECT id, date, amount, merchant, employee_name, card_number,
                       created_at, employee_file_date, employee_id
                FROM transactions
                WHERE employee_name = ?
                ORDER BY date DESC
                """,
                (employee_name,),
            )

            transactions = []
            for row in cursor.fetchall():
                transactions.append({
                    "id": row[0],
                    "date": row[1],
                    "amount": row[2],
                    "merchant": row[3],
                    "employee_name": row[4],
                    "card_number": row[5],
                    "created_at": row[6],
                    "employee_file_date": row[7],
                    "employee_id": row[8],
                })

            conn.close()
            return transactions
        except DB_ERRORS as e:
            logging.error("Failed to retrieve employee transactions: %s", e)
            return []

    def get_employee_names(self) -> List[str]:
        try:
            conn = self._get_connection()
            cursor = conn.cursor()

            cursor.execute("""
                SELECT DISTINCT employee_name
                FROM transactions
                ORDER BY employee_name
            """)

            employees = [row[0] for row in cursor.fetchall()]
            conn.close()
            return employees
        except DB_ERRORS as e:
            logging.error("Failed to retrieve employee names: %s", e)
            return []

    def link_employee(self, employee_name: str, employee_id: str) -> int:
        """Backfill immutable employee linkage while retaining the name snapshot."""
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            cursor.execute(
                """
                UPDATE transactions
                SET employee_id = ?
                WHERE employee_name = ? AND employee_id IS NULL
                """,
                (employee_id, employee_name),
            )
            count = cursor.rowcount
            conn.commit()
            conn.close()
            return count
        except DB_ERRORS as e:
            logging.error("Failed to link employee transactions: %s", e)
            return 0

    def get_transactions_by_employee_id(self, employee_id: str) -> List[Dict[str, Any]]:
        return [
            transaction
            for transaction in self.get_all_transactions()
            if transaction.get("employee_id") == employee_id
        ]

    def set_employee_budget(
        self,
        employee_id: str,
        employee_name: str,
        opening_spend: float,
        spend_limit: float,
    ) -> bool:
        if not employee_id or opening_spend < 0 or spend_limit <= 0:
            return False
        try:
            conn = self._get_connection()
            conn.execute(
                """
                INSERT INTO employee_budgets
                    (employee_id, employee_name, opening_spend, spend_limit, updated_at)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(employee_id) DO UPDATE SET
                    employee_name = excluded.employee_name,
                    opening_spend = excluded.opening_spend,
                    spend_limit = excluded.spend_limit,
                    updated_at = excluded.updated_at
                """,
                (
                    employee_id,
                    employee_name,
                    opening_spend,
                    spend_limit,
                    datetime.now().isoformat(),
                ),
            )
            conn.commit()
            conn.close()
            self._ensure_permissions()
            return True
        except DB_ERRORS as e:
            logging.error("Failed to save employee budget: %s", e)
            return False

    def get_employee_budgets(self) -> List[Dict[str, Any]]:
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT
                    b.employee_id,
                    b.employee_name,
                    b.opening_spend,
                    b.spend_limit,
                    b.opening_spend + COALESCE(SUM(ABS(t.amount)), 0) AS total_spent
                FROM employee_budgets b
                LEFT JOIN transactions t ON t.employee_id = b.employee_id
                GROUP BY
                    b.employee_id,
                    b.employee_name,
                    b.opening_spend,
                    b.spend_limit
                ORDER BY b.employee_name
                """
            )
            budgets = [
                {
                    "employee_id": row[0],
                    "employee_name": row[1],
                    "opening_spend": float(row[2]),
                    "spend_limit": float(row[3]),
                    "total_spent": float(row[4]),
                }
                for row in cursor.fetchall()
            ]
            conn.close()
            return budgets
        except DB_ERRORS as e:
            logging.error("Failed to retrieve employee budgets: %s", e)
            return []

    def delete_transaction(self, transaction_id: int) -> bool:
        try:
            conn = self._get_connection()
            cursor = conn.cursor()

            cursor.execute("DELETE FROM transactions WHERE id = ?", (transaction_id,))
            deleted = cursor.rowcount == 1
            conn.commit()
            conn.close()
            if deleted:
                logging.info("Deleted transaction ID: %s", transaction_id)
            else:
                logging.warning("Transaction ID not found: %s", transaction_id)
            return deleted
        except DB_ERRORS as e:
            logging.error("Failed to delete transaction: %s", e)
            return False

    def delete_employee_transactions(self, employee_name: str) -> bool:
        try:
            conn = self._get_connection()
            cursor = conn.cursor()

            cursor.execute("DELETE FROM transactions WHERE employee_name = ?", (employee_name,))
            conn.commit()
            conn.close()
            logging.info("Deleted all transactions for employee: %s", employee_name)
            return True
        except DB_ERRORS as e:
            logging.error("Failed to delete employee transactions: %s", e)
            return False

    def get_spending_summary(self) -> Dict[str, float]:
        try:
            conn = self._get_connection()
            cursor = conn.cursor()

            cursor.execute("""
                SELECT employee_name, SUM(amount) as total
                FROM transactions
                GROUP BY employee_name
                ORDER BY total DESC
            """)

            summary = {row[0]: row[1] for row in cursor.fetchall()}
            conn.close()
            return summary
        except DB_ERRORS as e:
            logging.error("Failed to get spending summary: %s", e)
            return {}

    def secure_delete(self) -> bool:
        try:
            if self.db_path.exists():
                file_size = self.db_path.stat().st_size or 1
                with open(self.db_path, "r+b") as f:
                    for _ in range(3):
                        f.seek(0)
                        f.write(os.urandom(file_size))
                        f.truncate(file_size)
                        f.flush()
                        os.fsync(f.fileno())
                self.db_path.unlink()
                logging.info("Transaction database securely deleted")
                return True
            return False
        except Exception as e:
            logging.error("Failed to securely delete database: %s", e)
            return False
