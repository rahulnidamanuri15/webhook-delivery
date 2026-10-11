#!/usr/bin/env bash
# Cert expiry check for prod TLS (run daily via cron or CI).
# Fails if fullchain.pem expires within WARNING_DAYS (default 21).
set -euo pipefail
CERT="${1:-deploy/tls/fullchain.pem}"
WARNING_DAYS="${WARNING_DAYS:-21}"
if [ ! -f "${CERT}" ]; then
  echo "No cert at ${CERT} (HTTP-only first boot?). Skipping." >&2
  exit 0
fi
if ! command -v openssl >/dev/null 2>&1; then
  echo "openssl not found, cannot check expiry." >&2
  exit 1
fi
if ! openssl x509 -checkend $(( WARNING_DAYS * 86400 )) -noout -in "${CERT}"; then
  echo "CRITICAL: ${CERT} expires within ${WARNING_DAYS} days. Renew via certbot." >&2
  openssl x509 -enddate -noout -in "${CERT}" >&2 || true
  exit 1
fi
echo "OK: ${CERT} valid for > ${WARNING_DAYS} days."
openssl x509 -enddate -noout -in "${CERT}" || true
