#!/usr/bin/env bash
# Production deploy wrapper — ALWAYS uses the prod overlay.
#
# Usage:
#   ./scripts/deploy_prod.sh up --build -d
#   ./scripts/deploy_prod.sh config -q
#   ./scripts/deploy_prod.sh exec web alembic upgrade head
#
# This script is the ONLY blessed way to run compose against production
# (alongside `make deploy-prod` / `make up-prod`, which delegate here or use
# the same fixed `-f compose.yaml -f compose.prod.yaml` overlay).
# It fail-fasts instead of ever booting production without the overlay.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${REPO_ROOT}"

BASE_FILE="compose.yaml"
PROD_FILE="compose.prod.yaml"

usage() {
  cat >&2 <<'EOF'
Usage: scripts/deploy_prod.sh <docker compose args...>

Examples:
  scripts/deploy_prod.sh up --build -d
  scripts/deploy_prod.sh config -q
  scripts/deploy_prod.sh exec web alembic upgrade head

Notes:
  - The prod overlay (-f compose.yaml -f compose.prod.yaml) is fixed and
    always applied; do NOT pass -f/--file yourself.
  - ENV is forced to "production".
  - Set DEPLOY_PROD_ALLOW_MISSING_TLS=1 to bypass the TLS cert check (CI dry-runs).
EOF
}

if [[ $# -eq 0 ]]; then
  usage
  exit 1
fi

# --- 1. Overlay files must exist ------------------------------------------------
if [[ ! -f "${BASE_FILE}" ]]; then
  echo "ERROR: base compose file '${BASE_FILE}' not found in ${REPO_ROOT}." >&2
  exit 1
fi
if [[ ! -f "${PROD_FILE}" ]]; then
  echo "ERROR: prod overlay '${PROD_FILE}' not found — refusing to deploy without it." >&2
  exit 1
fi

# --- 2. Refuse caller-supplied -f/--file (overlay is fixed) ---------------------
for arg in "$@"; do
  case "${arg}" in
    -f|--file|-f=*|--file=*)
      echo "ERROR: do not pass '${arg}' — ${0} always uses '-f ${BASE_FILE} -f ${PROD_FILE}'." >&2
      exit 1
      ;;
  esac
done

# --- 3. Pin production environment ----------------------------------------------
if [[ -z "${ENV:-}" ]]; then
  export ENV=production
elif [[ "${ENV}" != "production" ]]; then
  echo "ERROR: ENV='${ENV}' — production deploys require ENV=production." >&2
  exit 1
fi

if [[ "${DEBUG:-False}" == "True" || "${DEBUG:-False}" == "true" || "${DEBUG:-}" == "1" ]]; then
  echo "ERROR: DEBUG='${DEBUG}' — production deploys require DEBUG=False." >&2
  exit 1
fi

# --- 4. Required production secrets (fail fast, no dev defaults) -----------------
REQUIRED_VARS=(
  SECRET_KEY
  SIGNING_SECRET_ENCRYPTION_KEY
  API_KEY_PEPPER
  METRICS_API_KEY
  POSTGRES_PASSWORD
  ALLOWED_RECEIVER_DOMAINS
  PUBLIC_BASE_URL
  SMTP_HOST
  SMTP_PASSWORD
  SMTP_FROM_EMAIL
)
missing=()
for var in "${REQUIRED_VARS[@]}"; do
  if [[ -z "${!var:-}" ]]; then
    missing+=("${var}")
  fi
done
if [[ -z "${REDIS_URL:-}" && -z "${REDIS_PASSWORD:-}" ]]; then
  missing+=("REDIS_URL (or REDIS_PASSWORD)")
fi
if [[ ${#missing[@]} -gt 0 ]]; then
  echo "ERROR: missing required production secrets:" >&2
  for var in "${missing[@]}"; do
    echo "  - ${var}" >&2
  done
  echo "Provide them via environment or .env; refusing to deploy." >&2
  exit 1
fi

# --- 5. Refuse demo/seed profiles against production ------------------------------
for arg in "$@"; do
  case "${arg}" in
    --profile|--profile=*|demo|seed)
      echo "ERROR: demo/seed profiles must never run against production (got '${arg}')." >&2
      exit 1
      ;;
  esac
done
if [[ "${COMPOSE_PROFILES:-}" == *"demo"* || "${COMPOSE_PROFILES:-}" == *"seed"* ]]; then
  echo "ERROR: COMPOSE_PROFILES='${COMPOSE_PROFILES}' must not include demo/seed in production." >&2
  exit 1
fi

# --- 6. TLS certs required for (re)starting the public stack ----------------------
needs_tls=0
for arg in "$@"; do
  case "${arg}" in
    up|start|restart|create)
      needs_tls=1
      ;;
  esac
done
if [[ "${needs_tls}" -eq 1 && "${DEPLOY_PROD_ALLOW_MISSING_TLS:-0}" != "1" ]]; then
  tls_missing=()
  [[ -f "deploy/tls/fullchain.pem" ]] || tls_missing+=("deploy/tls/fullchain.pem")
  [[ -f "deploy/tls/privkey.pem" ]] || tls_missing+=("deploy/tls/privkey.pem")
  if [[ ${#tls_missing[@]} -gt 0 ]]; then
    echo "ERROR: missing production TLS certificates:" >&2
    for f in "${tls_missing[@]}"; do
      echo "  - ${f}" >&2
    done
    echo "Place real (Let's Encrypt) certs there, or set DEPLOY_PROD_ALLOW_MISSING_TLS=1 for a dry-run." >&2
    exit 1
  fi
fi

# --- 7. Deploy with the fixed prod overlay -----------------------------------------
echo "Deploying production with overlay: -f ${BASE_FILE} -f ${PROD_FILE} (ENV=production)"
exec docker compose -f "${BASE_FILE}" -f "${PROD_FILE}" "$@"
