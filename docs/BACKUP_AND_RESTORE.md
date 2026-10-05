# Database Backup & Disaster Recovery Guide

This guide details operational procedures for backing up, verifying, and restoring the Reliable Webhook Delivery Platform database.

---

## 1. Production PostgreSQL Procedures

### 1.1 Automated Daily Backup (`pg_dump`)

To take a complete, consistent backup of the platform database without downtime:

```bash
# Set credentials
PGHOST="localhost"
PGPORT="5432"
PGUSER="postgres"
PGDATABASE="webhook_platform"
BACKUP_DIR="/var/backups/webhooks"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# Create compressed custom-format dump
pg_dump -h $PGHOST -p $PGPORT -U $PGUSER -F c -b -v \
  -f "${BACKUP_DIR}/webhook_platform_${TIMESTAMP}.dump" \
  $PGDATABASE
```

### 1.2 Database Restoration (`pg_restore`)

To restore from a backup file into a fresh PostgreSQL instance:

```bash
# 1. Terminate active connections (if restoring existing DB)
psql -h $PGHOST -U $PGUSER -c "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = 'webhook_platform';"

# 2. Re-create clean database
dropdb -h $PGHOST -U $PGUSER webhook_platform
createdb -h $PGHOST -U $PGUSER webhook_platform

# 3. Restore schema, data, and constraints
pg_restore -h $PGHOST -p $PGPORT -U $PGUSER -d webhook_platform -v \
  "${BACKUP_DIR}/webhook_platform_20261005_120000.dump"

# 4. Verify Alembic migration version
alembic current
```

---

## 2. Local Development SQLite Procedures

### 2.1 Online SQLite Backup

SQLite supports hot backups without locking the active database:

```powershell
# In PowerShell:
sqlite3 webhooks.db "VACUUM INTO 'webhooks_backup.db';"
```

### 2.2 Restore SQLite

```powershell
Copy-Item -Path "webhooks_backup.db" -Destination "webhooks.db" -Force
```

---

## 3. Disaster Recovery Checklist

1. **Verify Encryption Key Preservation**: The `SIGNING_SECRET_ENCRYPTION_KEY` environment variable must be safely stored in password managers or secrets vaults. If this key is lost, encrypted signing secrets cannot be decrypted upon database restoration.
2. **Point-in-Time Recovery (PITR)**: In enterprise production, enable PostgreSQL WAL archiving (`wal_level = replica`, `archive_mode = on`) to an S3/GCS bucket to allow recovery to any exact second before an incident.
