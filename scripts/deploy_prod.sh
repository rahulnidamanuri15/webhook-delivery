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

# --- 0. Load .env (documented prod path: cp .env.example .env) -------------------
# Checks below validate exported variables; without this, a file-only deploy
# (the documented flow) would always fail. CI has no .env file and injects
# dummy secrets via environment, so this is a no-op there.
if [[ -f ".env" ]]; then
  set -a
  # shellcheck disable=SC1091
  . ./.env
  set +a
fi

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

# --- 7. Placeholder + consistency guards (fail closed on copy-paste .env.example) --
for var in SECRET_KEY API_KEY_PEPPER METRICS_API_KEY POSTGRES_PASSWORD REDIS_URL REDIS_PASSWORD SMTP_PASSWORD SIGNING_SECRET_ENCRYPTION_KEY; do
  val="${!var:-}"
  if [[ "${val,,}" == *"change_me"* ]]; then
    echo "ERROR: ${var} still contains CHANGE_ME placeholder — generate a real value (see .env.example)." >&2
    exit 1
  fi
done
if [[ "${ALLOW_OPEN_REGISTRATION:-False}" == "True" || "${ALLOW_OPEN_REGISTRATION:-False}" == "true" || "${ALLOW_OPEN_REGISTRATION:-}" == "1" ]]; then
  echo "ERROR: ALLOW_OPEN_REGISTRATION='${ALLOW_OPEN_REGISTRATION}' — must be False in production." >&2
  exit 1
fi
if [[ -n "${REDIS_PASSWORD:-}" && -n "${REDIS_URL:-}" ]]; then
  # REDIS_URL is URL-encoded; decode %xx before comparing.
  _url_pw="$(python3 -c "import urllib.parse,os; print(urllib.parse.unquote(urllib.parse.urlparse(os.environ.get('REDIS_URL','')).password or ''))" 2>/dev/null || true)"
  if [[ -n "${_url_pw}" && "${_url_pw}" != "${REDIS_PASSWORD}" ]]; then
    echo "ERROR: REDIS_URL password does not match REDIS_PASSWORD — set REDIS_URL=redis://:<REDIS_PASSWORD>@redis:6379/0." >&2
    exit 1
  fi
fi
if [[ "${TRUSTED_PROXIES:-}" == *"10.0.0.0/8"* ]]; then
  echo "ERROR: TRUSTED_PROXIES contains 10.0.0.0/8 (too broad for XFF). Set narrow CIDRs, e.g. TRUSTED_PROXIES=127.0.0.1,::1,172.18.0.0/24." >&2
  exit 1
fi

# --- 8. Pre-migration backup gate for mutating commands ---------------------------
needs_mutating=0
for arg in "$@"; do
  case "${arg}" in
    up|start|restart|create|migrate)
      needs_mutating=1
      ;;
  esac
done
if [[ "${needs_mutating}" -eq 1 && "${DEPLOY_PROD_SKIP_BACKUP_CHECK:-0}" != "1" ]]; then
  if [[ -d "./backups" ]]; then
    if ! ls ./backups/*.gz >/dev/null 2>&1; then
      echo "WARNING: no ./backups/*.gz found — run a DB backup before migrating (see docs/BACKUP_AND_DISASTER_RECOVERY.md)." >&2
      echo "Set DEPLOY_PROD_SKIP_BACKUP_CHECK=1 to bypass after taking an offsite backup." >&2
    elif ! find ./backups -maxdepth 1 -name '*.gz' -mtime -2 2>/dev/null | grep -q .; then
      echo "WARNING: latest ./backups/*.gz is older than 48h — take a fresh backup before migrating." >&2
    else
      echo "Pre-migration backup check: fresh dump present."
    fi
  fi
  echo "Reminder: migrations run via 'migrations' service (alembic upgrade head) and gate web/workers."
  echo "Check pending migrations with: docker compose -f ${BASE_FILE} -f ${PROD_FILE} run --rm web alembic check"
fi

# --- 9. Deploy with the fixed prod overlay -----------------------------------------
echo "Deploying production with overlay: -f ${BASE_FILE} -f ${PROD_FILE} (ENV=production)"
exec docker compose -f "${BASE_FILE}" -f "${PROD_FILE}" "$@"
