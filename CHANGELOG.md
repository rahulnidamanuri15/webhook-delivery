# Changelog

All notable changes to the Reliable Webhook Delivery Platform are documented in this file.
This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Production Compose Enforcement
* Added `Makefile` prod targets (`deploy-prod`, `up-prod`, `build-prod`, ...) that always pin `-f compose.yaml -f compose.prod.yaml`.
* Added `scripts/deploy_prod.sh` wrapper: forces `ENV=production`, fail-fasts on missing prod secrets, refuses `-f/--file` overrides and demo/seed profiles, requires TLS certs for `up`.
* Added `scripts/enforce_prod_compose.sh` + `enforce-prod-compose` CI job: fails builds that run `docker compose up/build` without the prod overlay (branch-gated on `main`/`master`), and asserts the rendered prod config publishes no DB/Redis/app ports.
* Fixed `compose.prod.yaml` port closure: `ports: []` merges (no-op) — now `ports: !reset []` so DB/Redis/web are truly off the host in production (requires Docker Compose v2.24+).

## [1.0.0] - 2026-10-08

### Production Readiness & Security Hardening
* **Secret Management & Zero Committed Fallbacks:**
  * Removed all hardcoded static secrets from `compose.yaml`.
  * Added Docker Secrets and Kubernetes Secrets support via `*_FILE` environment variables.
  * Added fail-fast validation in `app/config.py` rejecting known committed dev keys in production.
  * Required explicit, non-empty `ALLOWED_RECEIVER_DOMAINS` in production.
  * Added `MultiFernet` support with `SIGNING_SECRET_ENCRYPTION_KEYS_FALLBACK` for zero-downtime signing secret key rotation.
  * Added opportunistic re-encryption on delivery and read, automatically upgrading fallback ciphertexts to the primary key.
  * Added `scripts/rotate_or_repair_endpoint_secrets.py` for automated auditing, re-encryption, and secret healing across all database records.
  * Enhanced delivery failure handling and dashboard endpoint detail with informative error diagnosis and 1-click secret rotation.
* **Network & Proxy Hardening:**
  * Configured reverse proxy with mandatory HTTPS, port 80 redirection to 443, and HSTS headers.
  * Added ASGI request-size limit middleware rejecting bodies exceeding `MAX_PAYLOAD_SIZE_BYTES + 64KB` with HTTP 413 prior to deserialization.
  * Restricted `/metrics` endpoint in production to dedicated `METRICS_API_KEY` Bearer tokens.
* **Probes & Observability:**
  * Added `/live` (and `/health`) for process liveness.
  * Added `/ready` for database and Redis dependency connectivity checks.
  * Added `/startup` for database schema migration checks.
* **Worker & Celery Concurrency:**
  * Aligned Celery visibility timeout with `LEASE_DURATION_SECONDS * 2`.
  * Configured Celery task time limits (`task_time_limit` and `task_soft_time_limit`), broker reconnect retries, and task rejection on worker crash (`task_reject_on_worker_lost=True`).
  * Enforced safety margin between HTTP request timeout and lease duration (`HTTP_TIMEOUT_SECONDS + 5 < LEASE_DURATION_SECONDS`).
* **Team Invitation Security:**
  * Hashed invitation tokens at rest via SHA-256 (`token_hash`), ensuring database dumps do not expose active invitation tokens.
  * Added rate limiting for invitation acceptance.
  * Automatically invalidated prior pending invitations upon issuing a new one for the same organization and email.
  * Enforced password verification when accepting an invitation for an existing account.
* **Build Reproducibility & CI:**
  * Pinned exact production dependencies in `requirements.txt`.
  * Enforced blocking Ruff and Black lint/formatting checks in CI.
  * Added secret scanning checks in CI.

---

### Migration & Rollback Procedures
* **Forward Migration:** Run `alembic upgrade head`.
* **Rollback Procedure:** Run `alembic downgrade -1` to roll back the most recent migration step. Database backup must always be captured before executing production migrations.
