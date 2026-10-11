#!/usr/bin/env bash
# PostgreSQL restore with checksum verification, fail-fast SQL errors, and
# an explicit recovery target (never silently overwrites the live DATABASE_URL).
#
# Usage:
#   scripts/restore_postgres.sh <backup_file.sql.gz> <target_db_url> [--yes]
#
#   <target_db_url> is REQUIRED — there is no default. Restoring into the
#   database named by DATABASE_URL additionally requires --yes (or
#   ALLOW_RESTORE_INPLACE=1) plus an interactive confirmation, so a recovery
#   drill cannot accidentally clobber production. Restore into a clean/fresh
#   database; the dump replays in a single transaction with ON_ERROR_STOP so
#   any rejected statement aborts the whole restore instead of printing a
#   false "completed successfully" over a partially restored database.
#
# SQLAlchemy URLs (postgresql+psycopg://, ...) are normalized to libpq form
# (postgresql://) for psql, matching scripts/backup_postgres.sh.
set -euo pipefail

# SQLAlchemy URL -> libpq URL (strip any "+driver" suffix).
normalize_db_url() {
    local url="$1"
    if [[ "${url}" =~ ^postgresql\+[^:]*:// ]]; then
        url="postgresql://${url#*://}"
    fi
    printf '%s' "${url}"
}

# Redact password for logs: postgresql://user:****@host/db
redact_url() {
    local url="$1"
    printf '%s' "${url}" | sed -E 's#(://[^:/@]+:)[^@]+@#\1****@#'
}

ASSUME_YES=0
ARGS=()
for arg in "$@"; do
    case "${arg}" in
        --yes|-y) ASSUME_YES=1 ;;
        -h|--help) echo "Usage: $0 <backup_file.sql.gz> <target_db_url> [--yes]"; exit 0 ;;
        *) ARGS+=("${arg}") ;;
    esac
done
set -- "${ARGS[@]:-}"

if [ $# -lt 2 ]; then
    echo "Usage: $0 <backup_file.sql.gz> <target_db_url> [--yes]" >&2
    echo "" >&2
    echo "  <target_db_url> is required (e.g. a staging/fresh database URL)." >&2
    echo "  Restoring into DATABASE_URL additionally requires --yes." >&2
    exit 1
fi

BACKUP_FILE="$1"
TARGET_URL_RAW="$2"
CHECKSUM_FILE="${BACKUP_FILE}.sha256"

if [ ! -f "${BACKUP_FILE}" ]; then
    echo "Error: Backup file ${BACKUP_FILE} not found." >&2
    exit 1
fi

TARGET_URL="$(normalize_db_url "${TARGET_URL_RAW}")"
DISPLAY_TARGET="$(redact_url "${TARGET_URL}")"

# Canonicalize for in-place guard: compare host + dbname (not raw string, so
# trailing `/`, ?sslmode=, or +driver variants cannot bypass the LIVE check).
canonical_target_key() {
    local url="$1"
    url="${url%%\?*}"
    url="${url%%\#*}"
    local hostpart="${url#*://}"
    hostpart="${hostpart#*@}"
    local host="${hostpart%%/*}"
    local db="${url##*/}"
    db="${db%%\?*}"
    printf '%s/%s' "$(printf '%s' "${host}" | tr '[:upper:]' '[:lower:]')" "${db}"
}

# Guard: restoring into the live app database must be a deliberate operator
# decision, never a forgotten second argument.
if [ -n "${DATABASE_URL:-}" ]; then
    LIVE_URL="$(normalize_db_url "${DATABASE_URL}")"
    if [ "$(canonical_target_key "${TARGET_URL}")" = "$(canonical_target_key "${LIVE_URL}")" ]; then
        if [ "${ASSUME_YES}" -ne 1 ] && [ "${ALLOW_RESTORE_INPLACE:-0}" != "1" ]; then
            echo "ERROR: target is the live DATABASE_URL (${DISPLAY_TARGET})." >&2
            echo "Refusing to overwrite it without --yes (or ALLOW_RESTORE_INPLACE=1)." >&2
            echo "Restore into a clean database instead, or re-run with --yes to confirm." >&2
            exit 1
        fi
        echo "WARNING: target is the live DATABASE_URL — proceeding with in-place restore." >&2
    fi
fi

if [ -f "${CHECKSUM_FILE}" ]; then
    echo "Verifying SHA-256 checksum..."
    sha256sum -c "${CHECKSUM_FILE}"
else
    # Fail closed unless explicitly allowed: a missing .sha256 means the dump
    # is unverified (bit-rot / partial copy passes gzip -t).
    if [ "${ALLOW_MISSING_CHECKSUM:-0}" != "1" ]; then
        echo "ERROR: Checksum file ${CHECKSUM_FILE} not found. Refusing to restore unverified dump." >&2
        echo "Re-run with ALLOW_MISSING_CHECKSUM=1 to allow gzip-only verification." >&2
        exit 1
    fi
    echo "Warning: Checksum file not found (ALLOW_MISSING_CHECKSUM=1), verifying gzip integrity only..."
    gzip -t "${BACKUP_FILE}"
fi

if [ "${ASSUME_YES}" -ne 1 ]; then
    echo "About to restore ${BACKUP_FILE} into ${DISPLAY_TARGET}."
    printf "Type the target database name to confirm: "
    read -r confirmation < /dev/tty || { echo "Aborted (no confirmation)." >&2; exit 1; }
    # Accept either the full URL or its trailing database name.
    target_db="${TARGET_URL##*/}"
    target_db="${target_db%%\?*}"
    if [ "${confirmation}" != "${TARGET_URL}" ] && [ "${confirmation}" != "${target_db}" ]; then
        echo "Aborted: confirmation did not match target database '${target_db}'." >&2
        exit 1
    fi
fi

echo "Restoring database from ${BACKUP_FILE} into ${DISPLAY_TARGET}..."
echo "(single transaction, aborting on first SQL error)"
# --single-transaction (-1) + ON_ERROR_STOP: any rejected statement aborts the
# whole restore and psql exits non-zero, so set -e prevents the false success
# message below. pipefail propagates gunzip failures too.
gunzip -c "${BACKUP_FILE}" | psql "${TARGET_URL}" -v ON_ERROR_STOP=1 --single-transaction

echo "Database restore completed successfully into ${DISPLAY_TARGET}."
echo "Run 'alembic upgrade head' against the restored database if the dump predates the latest migration."
