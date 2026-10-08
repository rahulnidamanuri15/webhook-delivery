#!/usr/bin/env bash
# Automated PostgreSQL restore verification and disaster recovery drill script.
set -euo pipefail

if [ $# -lt 1 ]; then
    echo "Usage: $0 <backup_file.sql.gz> [target_db_url]"
    exit 1
fi

BACKUP_FILE="$1"
TARGET_URL="${2:-${DATABASE_URL:?DATABASE_URL must be provided}}"
CHECKSUM_FILE="${BACKUP_FILE}.sha256"

if [ ! -f "${BACKUP_FILE}" ]; then
    echo "Error: Backup file ${BACKUP_FILE} not found."
    exit 1
fi

if [ -f "${CHECKSUM_FILE}" ]; then
    echo "Verifying SHA-256 checksum..."
    sha256sum -c "${CHECKSUM_FILE}"
else
    echo "Warning: Checksum file not found, verifying gzip integrity only..."
    gzip -t "${BACKUP_FILE}"
fi

echo "Restoring database from ${BACKUP_FILE}..."
gunzip -c "${BACKUP_FILE}" | psql "${TARGET_URL}"

echo "Database restore completed successfully."
