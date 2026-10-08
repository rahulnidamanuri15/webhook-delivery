#!/usr/bin/env bash
# Automated PostgreSQL backup with gzip compression, checksums, and retention rotation.
set -euo pipefail

BACKUP_DIR="${BACKUP_DIR:-/backups}"
RETENTION_DAYS="${RETENTION_DAYS:-14}"
TIMESTAMP=$(date -u +"%Y%m%d_%H%M%SZ")
BACKUP_FILE="${BACKUP_DIR}/webhook_db_${TIMESTAMP}.sql.gz"
CHECKSUM_FILE="${BACKUP_FILE}.sha256"

mkdir -p "${BACKUP_DIR}"

echo "[$(date -u)] Starting database backup to ${BACKUP_FILE}..."
pg_dump "${DATABASE_URL}" | gzip -c > "${BACKUP_FILE}"

# Generate cryptographic checksum for verification
sha256sum "${BACKUP_FILE}" > "${CHECKSUM_FILE}"
echo "[$(date -u)] Backup created and checksummed successfully."

# Verify archive integrity
gzip -t "${BACKUP_FILE}"
echo "[$(date -u)] Archive integrity verified (gzip test passed)."

# Prune old backups older than retention policy
find "${BACKUP_DIR}" -name "webhook_db_*.sql.gz" -mtime +"${RETENTION_DAYS}" -delete
find "${BACKUP_DIR}" -name "webhook_db_*.sql.gz.sha256" -mtime +"${RETENTION_DAYS}" -delete
echo "[$(date -u)] Retention cleanup completed (> ${RETENTION_DAYS} days removed)."
