#!/usr/bin/env python3
"""Database Migration Utility: SQLite to PostgreSQL.

Safely copies all entities from SQLite (webhooks.db) to PostgreSQL (webhook_platform)
in topological dependency order with proper type coercion and row count parity verification.
"""

import argparse
from datetime import UTC, datetime
import logging
import os
import sqlite3
import sys
from typing import Any

import psycopg

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("db_migrate")

# Tables in strict topological insertion order (parents first)
TABLES_ORDER = [
    "organizations",
    "users",
    "password_reset_otps",
    "organization_members",
    "projects",
    "api_keys",
    "organization_invitations",
    "endpoints",
    "endpoint_subscriptions",
    "events",
    "deliveries",
    "delivery_attempts",
    "audit_logs",
]

# Set of columns containing boolean flags
BOOLEAN_COLUMNS = {"enabled", "used"}

# Set of columns containing datetime timestamps
DATETIME_COLUMNS = {
    "created_at",
    "revoked_at",
    "next_attempt_at",
    "lease_expires_at",
    "completed_at",
    "started_at",
    "finished_at",
    "expires_at",
    "password_changed_at",
}


def parse_datetime_val(val: Any) -> datetime | None:
    if val is None:
        return None
    if isinstance(val, datetime):
        if val.tzinfo is None:
            return val.replace(tzinfo=UTC)
        return val
    if isinstance(val, str):
        val_str = val.strip()
        if not val_str:
            return None
        # Handle trailing space or missing tz
        try:
            dt = datetime.fromisoformat(val_str)
        except ValueError:
            # Handle common SQLite formats e.g. "YYYY-MM-DD HH:MM:SS.mmmmmm"
            for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S"):
                try:
                    dt = datetime.strptime(val_str, fmt)
                    break
                except ValueError:
                    dt = None
            if dt is None:
                logger.warning("Could not parse datetime string: %s", val_str)
                return None
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=UTC)
        return dt
    return None


def coerce_row_data(row_dict: dict[str, Any]) -> dict[str, Any]:
    coerced = {}
    for col, val in row_dict.items():
        if col in BOOLEAN_COLUMNS:
            coerced[col] = bool(val) if val is not None else None
        elif col in DATETIME_COLUMNS:
            coerced[col] = parse_datetime_val(val)
        else:
            coerced[col] = val
    return coerced


def migrate(sqlite_path: str, pg_url: str, clean: bool = False, dry_run: bool = False) -> bool:
    if not os.path.exists(sqlite_path):
        logger.error("SQLite database file not found: %s", sqlite_path)
        return False

    # Connect to SQLite
    logger.info("Opening SQLite database: %s", sqlite_path)
    s_conn = sqlite3.connect(sqlite_path)
    s_conn.row_factory = sqlite3.Row

    # Standardize connection string for psycopg
    # Strip SQLAlchemy dialect prefix if present (postgresql+psycopg:// -> postgresql://)
    standard_pg_url = pg_url.replace("postgresql+psycopg://", "postgresql://")

    logger.info("Connecting to PostgreSQL: %s", standard_pg_url)
    try:
        p_conn = psycopg.connect(standard_pg_url)
    except Exception as exc:
        logger.error("Failed to connect to PostgreSQL: %s", exc)
        s_conn.close()
        return False

    try:
        if clean and not dry_run:
            logger.info("Cleaning existing data in target PostgreSQL tables (CASCADE)...")
            with p_conn.cursor() as cur:
                tables_str = ", ".join(TABLES_ORDER)
                cur.execute(f"TRUNCATE TABLE {tables_str} CASCADE;")
            p_conn.commit()
            logger.info("Target tables successfully truncated.")

        total_migrated = 0
        summary: list[tuple[str, int, int]] = []

        for table in TABLES_ORDER:
            # Check if table exists in SQLite
            s_cur = s_conn.cursor()
            table_check = s_cur.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name=?", (table,)
            ).fetchone()
            if not table_check:
                logger.info("Table '%s' does not exist in SQLite source. Skipping.", table)
                summary.append((table, 0, 0))
                continue

            rows = s_cur.execute(f"SELECT * FROM {table}").fetchall()
            s_count = len(rows)

            if s_count == 0:
                logger.info("Table '%s' has 0 rows in SQLite. Skipping.", table)
                summary.append((table, 0, 0))
                continue

            if dry_run:
                logger.info("[DRY RUN] Would migrate %d rows for table '%s'.", s_count, table)
                summary.append((table, s_count, 0))
                continue

            # Prepare columns and insert statement
            col_names = [col[0] for col in s_cur.description]
            cols_clause = ", ".join(f'"{col}"' for col in col_names)
            placeholders = ", ".join(["%s"] * len(col_names))

            # Conflict handling: ON CONFLICT DO NOTHING if table has a primary key
            insert_sql = f'INSERT INTO "{table}" ({cols_clause}) VALUES ({placeholders}) ' f"ON CONFLICT DO NOTHING"

            # Coerce rows
            batch_params = []
            for r in rows:
                row_dict = dict(r)
                coerced = coerce_row_data(row_dict)
                batch_params.append([coerced[col] for col in col_names])

            with p_conn.cursor() as cur:
                cur.executemany(insert_sql, batch_params)
            p_conn.commit()

            # Query resulting count in PostgreSQL
            with p_conn.cursor() as cur:
                cur.execute(f'SELECT count(*) FROM "{table}"')
                p_count = cur.fetchone()[0]

            logger.info("Table '%s': %d rows read from SQLite -> %d rows in PostgreSQL.", table, s_count, p_count)
            summary.append((table, s_count, p_count))
            total_migrated += s_count

        # Print final verification report
        print("\n" + "=" * 65)
        print("          DATABASE MIGRATION VERIFICATION REPORT")
        print("=" * 65)
        print(f"{'Table Name':<28} | {'SQLite Rows':<14} | {'PostgreSQL Rows':<16} | {'Status':<8}")
        print("-" * 75)
        for tbl, s_cnt, p_cnt in summary:
            status = "MATCH" if (s_cnt == p_cnt or dry_run) else "CHECK"
            print(f"{tbl:<28} | {s_cnt:<14} | {p_cnt:<16} | {status:<8}")
        print("=" * 75)

        if dry_run:
            print(" DRY RUN COMPLETED. No data was written to PostgreSQL.")
        else:
            print(f" SUCCESS! Migrated {total_migrated} entities to PostgreSQL.")
        print("=" * 65 + "\n")
        return True

    except Exception as exc:
        p_conn.rollback()
        logger.exception("Migration failed with error: %s", exc)
        return False
    finally:
        s_conn.close()
        p_conn.close()


def main():
    parser = argparse.ArgumentParser(description="Migrate Webhook Platform data from SQLite to PostgreSQL")
    parser.add_argument("--sqlite-path", default="webhooks.db", help="Path to SQLite database file")
    parser.add_argument(
        "--postgres-url",
        default=os.getenv(
            "DATABASE_URL",
            "postgresql://postgres:postgrespassword@localhost:5432/webhook_platform",
        ),
        help="PostgreSQL connection string",
    )
    parser.add_argument(
        "--clean",
        action="store_true",
        help="Truncate PostgreSQL tables before copying data",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Validate reading and type coercion without writing to PostgreSQL",
    )

    args = parser.parse_args()
    success = migrate(
        sqlite_path=args.sqlite_path,
        pg_url=args.postgres_url,
        clean=args.clean,
        dry_run=args.dry_run,
    )
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
