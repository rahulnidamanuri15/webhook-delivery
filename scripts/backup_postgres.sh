#!/usr/bin/env bash
# Automated PostgreSQL backup with gzip compression, checksums, and retention rotation.
set -euo pipefail

# SQLAlchemy URLs (postgresql+psycopg://, postgresql+psycopg2://, ...) are NOT
# valid libpq connection URIs for pg_dump/psql. Strip any "+driver" suffix so
# the app's DATABASE_URL works directly with native PostgreSQL tooling.
normalize_db_url() {
    local url="$1"
    if [[ "${url}" =~ ^postgresql\+[^:]*:// ]]; then
        url="postgresql://${url#*://}"
    fi
    printf '%s' "${url}"
}

: "${DATABASE_URL:?DATABASE_URL must be provided}"
LIBPQ_URL="$(normalize_db_url "${DATABASE_URL}")"

BACKUP_DIR="${BACKUP_DIR:-/backups}"
RETENTION_DAYS="${RETENTION_DAYS:-14}"
TIMESTAMP=$(date -u +"%Y%m%d_%H%M%SZ")
BACKUP_FILE="${BACKUP_DIR}/webhook_db_${TIMESTAMP}.sql.gz"
CHECKSUM_FILE="${BACKUP_FILE}.sha256"

mkdir -p "${BACKUP_DIR}"

echo "[$(date -u)] Starting database backup to ${BACKUP_FILE}..."
pg_dump "${LIBPQ_URL}" | gzip -c > "${BACKUP_FILE}"

# Restrict perms: dumps contain webhook payloads/PII + Fernet ciphertext.
chmod 600 "${BACKUP_FILE}" || true

# Optional encryption (recommended for prod): if AGE_RECIPIENT is set and
# `age` is installed, produce an additional .age file and remove plaintext.
# Offsite copy is still required (same-disk bind is SPOF).
if [[ -n "${AGE_RECIPIENT:-}" ]]; then
  if command -v age >/dev/null 2>&1; then
    age -r "${AGE_RECIPIENT}" -o "${BACKUP_FILE}.age" "${BACKUP_FILE}" \
      && rm -f "${BACKUP_FILE}" \
      && BACKUP_FILE="${BACKUP_FILE}.age" \
      && echo "[$(date -u)] Backup encrypted with age (recipient ${AGE_RECIPIENT:0:12}...)."
  else
    echo "[$(date -u)] WARNING: AGE_RECIPIENT set but 'age' not installed; leaving unencrypted." >&2
  fi
else
  echo "[$(date -u)] NOTE: unencrypted backup — set AGE_RECIPIENT and copy offsite (see docs/BACKUP_AND_DISASTER_RECOVERY.md)." >&2
fi

# Generate cryptographic checksum for verification
sha256sum "${BACKUP_FILE}" > "${CHECKSUM_FILE}"
echo "[$(date -u)] Backup created and checksummed successfully."

# Verify archive integrity (gzip + logical restore dry-run when psql tools exist).
gzip -t "${BACKUP_FILE}"
echo "[$(date -u)] Archive integrity verified (gzip test passed)."
if command -v pg_restore >/dev/null 2>&1; then
    # Plain-SQL dumps have no pg_restore listing; do a --list dry parse via pg_restore
    # only for custom-format dumps, else a gunzip header sanity check.
    if gunzip -c "${BACKUP_FILE}" | head -c 2048 | grep -q "PostgreSQL database dump"; then
        echo "[$(date -u)] Dump header sanity check passed."
    else
        echo "[$(date -u)] WARNING: dump header not recognized; verify manually." >&2
    fi
fi

# Prune old backups older than retention policy
find "${BACKUP_DIR}" -name "webhook_db_*.sql.gz" -mtime +"${RETENTION_DAYS}" -delete
find "${BACKUP_DIR}" -name "webhook_db_*.sql.gz.sha256" -mtime +"${RETENTION_DAYS}" -delete
find "${BACKUP_DIR}" -name "webhook_db_*.sql.gz.age" -mtime +"${RETENTION_DAYS}" -delete
chmod 600 "${BACKUP_DIR}"/webhook_db_* 2>/dev/null || true
echo "[$(date -u)] Retention cleanup completed (> ${RETENTION_DAYS} days removed)."
