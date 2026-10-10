# Backup and Disaster Recovery Strategy

## Operational Objectives
* **Recovery Point Objective (RPO):** < 5 minutes (via automated WAL archiving / continuous replication, or daily logical dump for low-throughput environments).
* **Recovery Time Objective (RTO):** < 15 minutes (fully restored instance and running services).

---

## 1. Automated Logical Backups
Nightly logical backups are created via `scripts/backup_postgres.sh`:
* Creates gzip-compressed SQL dumps (`pg_dump | gzip`).
* Calculates SHA-256 checksums (`sha256sum`).
* Validates archive integrity (`gzip -t`).
* Prunes backups exceeding the retention policy (`RETENTION_DAYS=14`).

To run manually (SQLAlchemy `postgresql+psycopg://` URLs are normalized to
libpq `postgresql://` automatically for pg_dump/psql):
```bash
DATABASE_URL="postgresql+psycopg://user:pass@host/db" ./scripts/backup_postgres.sh
```

---

## 2. Restore Drills and Verification
Restores must be drilled quarterly using `scripts/restore_postgres.sh`.
The target is REQUIRED (never defaults to the live database), replays in a
single transaction with `ON_ERROR_STOP` (any rejected statement aborts the
whole restore — no false "completed successfully" over partial data), and
refuses to overwrite `DATABASE_URL` without `--yes`:
```bash
./scripts/restore_postgres.sh /backups/webhook_db_20261008_120000Z.sql.gz "postgresql+psycopg://user:pass@staging-host/staging_db" --yes
```
Non-interactive use (CI/drills) passes `--yes`; otherwise the script prompts
for the target database name. Restore into a clean/fresh database, then run
`alembic upgrade head` if the dump predates the latest migration.
The script automatically verifies checksums and replays schema and data.

---

## 3. Dedicated Encryption Key Backup
* **`SIGNING_SECRET_ENCRYPTION_KEY`** is the master Fernet key encrypting all webhook destination endpoint secrets at rest.
* If this key is lost, destination endpoint secrets become undecryptable and cannot be recovered.
* **Storage Invariant:** Store this key in an enterprise secret manager (AWS Secrets Manager, HashiCorp Vault, or Google Secret Manager) separate from database dumps.
* Never include `SIGNING_SECRET_ENCRYPTION_KEY` inside database backups.

---

## 4. Point-In-Time Recovery (PITR) & Replication
For production environments handling high throughput:
1. Configure PostgreSQL `wal_level = replica` and `archive_mode = on`.
2. Route WAL segments to cloud object storage (e.g. via `pgBackRest` or `WAL-G`).
3. Maintain an active streaming replica in an alternate availability zone.

---

## 5. Manual pg_dump / pg_restore (one-off, without the helper scripts)

For a one-off consistent backup outside the nightly `db_backup` service:

```bash
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
pg_dump -h postgres -U postgres -F c -b -v \
  -f "/backups/webhook_platform_${TIMESTAMP}.dump" \
  webhook_platform
```

Restore into a fresh database, then re-apply migrations:

```bash
psql -h postgres -U postgres -c "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = 'webhook_platform';"
dropdb -h postgres -U postgres webhook_platform
createdb -h postgres -U postgres webhook_platform
pg_restore -h postgres -U postgres -d webhook_platform -v \
  "/backups/webhook_platform_<TIMESTAMP>.dump"
alembic upgrade head
```

> Keep `SIGNING_SECRET_ENCRYPTION_KEY` in a secret manager, never inside DB
> dumps — without it, restored endpoint secrets are undecryptable.
