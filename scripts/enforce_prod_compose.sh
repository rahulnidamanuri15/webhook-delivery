#!/usr/bin/env bash
# CI/local guard: FAIL if production can be built without the prod overlay.
#
# Usage:
#   bash scripts/enforce_prod_compose.sh [--static-only]
#
# Static checks (always run, no docker needed):
#   1. Blessed entrypoints exist (Makefile, scripts/deploy_prod.sh).
#   2. Prod Makefile targets / deploy wrapper pin `-f compose.yaml -f compose.prod.yaml`.
#   3. No blessed path runs `docker compose ... up/build` without the overlay.
#   4. ci.yml contains the `enforce-prod-compose` job.
#   5. compose.prod.yaml statically keeps fail-closed guards
#      (no public DB/Redis/web ports, ENV=production, prod nginx conf, required secrets).
#   6. On production branches (main/master), COMPOSE_FILE must include the overlay.
#
# Render checks (skipped with --static-only or when docker is unavailable):
#   7. `docker compose -f compose.yaml -f compose.prod.yaml config` renders
#      prod-safe (no published 5432/6379/8080, ENV=production, prod nginx conf).
#   8. Bare `docker compose -f compose.yaml config` is NOT prod-safe —
#      proving the overlay is load-bearing (guard would be moot otherwise).
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${REPO_ROOT}"

STATIC_ONLY=0
if [[ "${1:-}" == "--static-only" ]]; then
  STATIC_ONLY=1
fi

fail() {
  echo "ERROR [enforce-prod-compose]: $*" >&2
  exit 1
}
pass() {
  echo "OK [enforce-prod-compose]: $*"
}

# --- 1. Blessed entrypoints exist -------------------------------------------------
[[ -f "Makefile" ]] || fail "Makefile missing — prod targets must live there."
[[ -f "scripts/deploy_prod.sh" ]] || fail "scripts/deploy_prod.sh missing — production wrapper required."
[[ -f "compose.yaml" ]] || fail "compose.yaml missing."
[[ -f "compose.prod.yaml" ]] || fail "compose.prod.yaml missing — production overlay required."
pass "blessed entrypoints exist (Makefile, scripts/deploy_prod.sh, compose files)"

# --- 2. Prod entrypoints pin the overlay -------------------------------------------
grep -q "compose.prod.yaml" Makefile \
  || fail "Makefile prod targets must reference compose.prod.yaml."
grep -qE "^(up-prod|build-prod|deploy-prod|config-prod|migrate-prod):" Makefile \
  || fail "Makefile must define prod targets (up-prod/build-prod/deploy-prod/config-prod/migrate-prod)."
grep -q -- "-f compose.yaml -f compose.prod.yaml" Makefile \
  || fail "Makefile must pin '-f compose.yaml -f compose.prod.yaml'."
grep -q "compose.prod.yaml" scripts/deploy_prod.sh \
  || fail "scripts/deploy_prod.sh must reference compose.prod.yaml."
grep -q -- '-f "${BASE_FILE}" -f "${PROD_FILE}"' scripts/deploy_prod.sh \
  || fail "scripts/deploy_prod.sh must exec docker compose with the fixed overlay."
grep -q "ENV=production" scripts/deploy_prod.sh \
  || fail "scripts/deploy_prod.sh must pin ENV=production."
pass "prod entrypoints pin '-f compose.yaml -f compose.prod.yaml' + ENV=production"

# --- 3. No blessed path builds/starts prod without the overlay ----------------------
# Any literal `docker compose ... up/build` in CI config, Makefile, or the deploy
# wrapper MUST carry compose.prod.yaml. (Dev targets use $(COMPOSE_BASE), not a
# literal `docker compose ... up`, so they are unaffected.)
violations=""
for path in .github/workflows/ci.yml Makefile scripts/deploy_prod.sh; do
  [[ -f "${path}" ]] || continue
  while IFS= read -r line; do
    # Skip comments — documentation may name the forbidden pattern to forbid it.
    # (Pure-bash trim: no forks, fast on all platforms.)
    trimmed="${line#"${line%%[![:space:]]*}"}"
    case "${trimmed}" in
      \#*) continue ;;
    esac
    case "${line}" in
      *"docker compose"*)
        case "${line}" in
          *" up"*|*" build"*)
            case "${line}" in
              *"compose.prod.yaml"*) ;;
              *) violations="${violations}${path}: ${line}"$'\n' ;;
            esac
            ;;
        esac
        ;;
    esac
  done < "${path}"
done
if [[ -n "${violations}" ]]; then
  echo "Bare 'docker compose up/build' without prod overlay found:" >&2
  printf '%s' "${violations}" >&2
  fail "production must never be built/started without -f compose.prod.yaml."
fi
pass "no bare 'docker compose up/build' without overlay in blessed paths"

# --- 4. CI job exists ----------------------------------------------------------------
grep -q "enforce-prod-compose" .github/workflows/ci.yml \
  || fail "ci.yml must contain the 'enforce-prod-compose' job."
grep -q "scripts/enforce_prod_compose.sh" .github/workflows/ci.yml \
  || fail "ci.yml 'enforce-prod-compose' job must invoke scripts/enforce_prod_compose.sh."
pass "ci.yml contains enforce-prod-compose job"

# --- 5. Prod overlay statically keeps fail-closed guards ------------------------------
grep -q "ENV=production" compose.prod.yaml \
  || fail "compose.prod.yaml must force ENV=production."
grep -q "deploy/nginx.conf" compose.prod.yaml \
  || fail "compose.prod.yaml must mount production deploy/nginx.conf."
if grep -q "nginx.dev.conf" compose.prod.yaml; then
  fail "compose.prod.yaml must never reference nginx.dev.conf."
fi
ports_closed_count="$(grep -cE "ports: (!reset )?\[\]" compose.prod.yaml || true)"
if [[ "${ports_closed_count}" -lt 3 ]]; then
  fail "compose.prod.yaml must close public ports (ports: !reset []) for postgres/redis/web (found ${ports_closed_count}, need >=3)."
fi
for secret_var in SECRET_KEY SIGNING_SECRET_ENCRYPTION_KEY API_KEY_PEPPER METRICS_API_KEY \
    POSTGRES_PASSWORD ALLOWED_RECEIVER_DOMAINS PUBLIC_BASE_URL SMTP_HOST SMTP_PASSWORD SMTP_FROM_EMAIL REDIS_URL; do
  grep -q "\${${secret_var}:?" compose.prod.yaml \
    || fail "compose.prod.yaml must require \${${secret_var}:?...} (fail-closed)."
done
pass "compose.prod.yaml static fail-closed guards intact"

# --- 6. Production-branch strictness ----------------------------------------------------
branch="${GITHUB_REF_NAME:-}"
if [[ -z "${branch}" ]]; then
  branch="$(git branch --show-current 2>/dev/null || true)"
fi
case "${branch}" in
  main|master)
    echo "Production branch detected (${branch}): overlay is mandatory."
    if [[ -n "${COMPOSE_FILE:-}" ]]; then
      case "${COMPOSE_FILE}" in
        *compose.prod.yaml*) pass "COMPOSE_FILE includes prod overlay" ;;
        *) fail "COMPOSE_FILE on '${branch}' must include compose.prod.yaml (got: ${COMPOSE_FILE})." ;;
      esac
    else
      pass "no COMPOSE_FILE override on '${branch}' (fixed overlay applies)"
    fi
    ;;
  *)
    echo "Non-production ref ('${branch:-unknown}'): branch gate skipped (static + render checks still apply)."
    ;;
esac

# --- 7-8. Render checks (need docker) ----------------------------------------------------
if [[ "${STATIC_ONLY}" -eq 1 ]]; then
  echo "Static-only mode: skipping docker render checks."
  pass "all static enforcement checks passed"
  exit 0
fi
if ! command -v docker >/dev/null 2>&1 || ! docker compose version >/dev/null 2>&1; then
  echo "WARNING [enforce-prod-compose]: docker compose unavailable — skipping render checks (static checks passed)."
  exit 0
fi

export ENV=production
export SECRET_KEY=dummy_secret_key_for_enforcement_check_only_1234567890
export SIGNING_SECRET_ENCRYPTION_KEY=yFz8s0v81v3G-xG3hV48V7s9uY5pL0tM2wN4bQ6rE8A=
export API_KEY_PEPPER=dummy_pepper_for_enforcement_check
export METRICS_API_KEY=dummy_metrics_key_for_enforcement_check
export POSTGRES_PASSWORD=dummy_postgres_password_for_check
export REDIS_PASSWORD=dummy_redis_password_for_check
export REDIS_URL=redis://:dummy_redis_password_for_check@redis:6379/0
export ALLOWED_RECEIVER_DOMAINS=example.com
export PUBLIC_BASE_URL=https://example.com
export SMTP_HOST=smtp.example.com
export SMTP_PASSWORD=dummy_smtp_password_for_check
export SMTP_FROM_EMAIL=noreply@example.com

prod_render="$(mktemp)"
bare_render="$(mktemp)"
trap 'rm -f "${prod_render}" "${bare_render}"' EXIT

docker compose -f compose.yaml -f compose.prod.yaml config > "${prod_render}" \
  || fail "'docker compose -f compose.yaml -f compose.prod.yaml config' failed."
pass "prod overlay renders (config valid)"

# Prod render must NOT publish DB/Redis/app ports directly ...
for port in '"5432"' '"6379"' '"8080"'; do
  if grep -q "published: ${port}" "${prod_render}"; then
    fail "prod render publishes port ${port} — overlay must keep DB/Redis/web off the host."
  fi
done
# ... but the reverse proxy stays public (80/443).
grep -q 'published: "80"' "${prod_render}" \
  || fail "prod render should still publish reverse-proxy port 80."
# Prod nginx conf, dev conf absent. (Match basename only: Windows renders bind
# sources with backslashes, e.g. D:\...\deploy\nginx.conf.)
grep -q "nginx.conf" "${prod_render}" \
  || fail "prod render must mount deploy/nginx.conf."
if grep -q "nginx.dev.conf" "${prod_render}"; then
  fail "prod render must never mount nginx.dev.conf."
fi
grep -qE "ENV(=|: )production" "${prod_render}" \
  || fail "prod render must set ENV=production."
pass "prod render is prod-safe (no 5432/6379/8080, ENV=production, prod nginx)"

# Bare base file must NOT be prod-safe — proves the overlay is load-bearing.
docker compose -f compose.yaml config > "${bare_render}" 2>/dev/null \
  || fail "bare 'docker compose -f compose.yaml config' failed unexpectedly."
if grep -q 'published: "5432"' "${bare_render}" || grep -q 'published: "6379"' "${bare_render}"; then
  pass "bare compose.yaml exposes DB/Redis ports — overlay confirmed load-bearing"
else
  fail "bare compose.yaml no longer exposes DB/Redis ports; enforcement assumptions changed — review overlay."
fi

pass "all production compose enforcement checks passed"
