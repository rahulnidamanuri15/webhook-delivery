# Hookflow — Reliable Webhook Delivery Platform

[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.142-009688.svg)](https://fastapi.tiangolo.com/)
[![PostgreSQL 16](https://img.shields.io/badge/PostgreSQL-16-336791.svg)](https://www.postgresql.org/)
[![Docker](https://img.shields.io/badge/docker-compose-ready-2496ED.svg)](https://docs.docker.com/compose/)
[![Ruff](https://img.shields.io/badge/lint-ruff-orange.svg)](https://docs.astral.sh/ruff/)
[![Tests](https://img.shields.io/badge/tests-pytest-green.svg)](tests/)

A production-grade, multi-tenant webhook delivery platform. Your application posts an event once — Hookflow durably stores it, fans it out to every subscribed endpoint, signs each delivery with HMAC-SHA256, retries with backoff and jitter, recovers from worker crashes via leases, and gives you a Stripe/Svix-style dashboard to inspect, replay, and audit everything.

> Example: your app reports `payment.succeeded`. Hookflow delivers it to the merchant's server, records the attempt history, retries if the server is down, dead-letters it if it keeps failing, and lets you replay it in one click.

---

## Table of Contents

- [Features](#features)
- [Demo Video](#demo-video)
- [Architecture](#architecture)
- [Tech Stack](#tech-stack)
- [Repository Structure](#repository-structure)
- [Quick Start](#quick-start)
- [Configuration](#configuration)
- [Usage](#usage)
- [API Reference](#api-reference)
- [Dashboard](#dashboard)
- [Security](#security)
- [Observability](#observability)
- [Testing](#testing)
- [Production Deployment](#production-deployment)
- [Operations](#operations)
- [Documentation](#documentation)
- [Known Limitations](#known-limitations)
- [Contributing](#contributing)

---

## Features

**Delivery engine**

- Atomic ingestion: event + per-endpoint deliveries committed in a single PostgreSQL transaction.
- Idempotency: same `Idempotency-Key` + identical payload returns the existing event; conflicting payload returns `409 Conflict`.
- Lease-based dispatch: workers claim deliveries with `lease_token` / `lease_expires_at`; I/O runs outside the DB transaction.
- Crash recovery: a periodic scanner reclaims abandoned `IN_FLIGHT` leases into `RETRY_SCHEDULED` (or `DEAD` when the budget is exhausted).
- Retry policy: `[10s, 30s, 2m, 10m, 30m, 2h]` with ±15% jitter; honors HTTP 429 `Retry-After` (seconds and HTTP-date, clamped to 1–300s). Short demo policy available for recorded demos.
- Dead letters + replay: exhausted deliveries go to `DEAD`; replay creates a new linked delivery (`replay_of_delivery_id`) with a fresh attempt budget, optionally retargeted.

**Security**

- HMAC-SHA256 signing per endpoint (`Webhook-Event-Id`, `Webhook-Delivery-Id`, `Webhook-Timestamp`, `Webhook-Signature: v1=<hex>`); secrets encrypted at rest with Fernet/MultiFernet, never logged.
- SSRF protection: blocks loopback, RFC1918, link-local/cloud-metadata ranges; single-DNS resolve-and-pin (TOCTOU-safe) with pinned transport; optional receiver-domain allowlist.
- Auth: `wh_live_` API keys (HMAC-peppered hash, one-time display), Argon2 passwords, signed sessions with denylist + password-change invalidation.
- RBAC: `owner` / `admin` / `member` roles; members are read-only for mutations; registration closed by default with an approval queue and team invitations.
- CSRF on all dashboard POSTs, rate limiting (Redis Lua with in-memory fallback), request-size limits (`1 MB` + 64 KB margin → `413`), trusted-proxy-aware client IP.

**Platform**

- Multi-tenant: organizations → projects → endpoints / events / deliveries / API keys.
- Dashboard: server-rendered HTML + Tailwind + HTMX (no SPA runtime), live tables, Chart.js traffic + health charts (IST axis), attempt timeline, slide-over inspector, audit log viewer.
- Ops: Prometheus `/metrics`, OpenTelemetry tracing, structured JSON logs, `/live` `/ready` `/startup` probes, nightly DB backups, Alembic-only migrations.

---

## Demo Video

90-second end-to-end flow: register → admin approval → create endpoint → publish event → watch live delivery → retry → dead-letter → one-click replay → audit trail.

<video src="https://github.com/user-attachments/assets/8cdb42dc-b213-4f70-a6be-2a077b4cd3c0" controls preload="metadata" width="100%">
  Your browser cannot play the embedded video — <a href="https://github.com/user-attachments/assets/8cdb42dc-b213-4f70-a6be-2a077b4cd3c0">watch the demo video</a> (also stored as <code>docs/demo.mp4</code>).
</video>


---

## Architecture

### Request lifecycle

```
Producer → POST /api/v1/events → Rate limit → Atomic commit (Event + PENDING Deliveries) → 202 Accepted
Dispatcher → Scan due PENDING / RETRY_SCHEDULED (SKIP LOCKED + Redis dedup)
Worker → Claim with lease → SSRF validate + DNS pin → HMAC sign → HTTP POST (outside txn) → Record attempt
Recovery → Reclaim expired IN_FLIGHT leases → RETRY_SCHEDULED or DEAD
```

### Delivery state machine

```
                +-------------+
                |   PENDING   |
                +------+------+
                       | Claimed by worker (lease assigned)
                       v
                +-------------+
                |  IN_FLIGHT  |
                +--+---+---+--+
                   |   |   |
       +-----------+   |   +-----------------------+
       | HTTP 2xx      | Retryable failure         | 4xx or budget exhausted
       v               v                           v
 +-----------+   +-------------------+       +-----------+
 | SUCCEEDED |   |  RETRY_SCHEDULED  |       |   DEAD    |
 +-----------+   +---------+---------+       +-----+-----+
                           |                       |
                           | Next attempt due      | 1-click replay
                           v                       v
                     [ IN_FLIGHT ]          [ New PENDING delivery ]
```

Full specification: [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

---

## Tech Stack

| Layer | Technology |
|---|---|
| API | FastAPI, Uvicorn, Pydantic v2 + pydantic-settings |
| Persistence | PostgreSQL 16 + SQLAlchemy 2 + Alembic, Redis 7 |
| Workers | Celery 5 (prod) or in-process dispatcher thread (dev) |
| Outbound HTTP | httpx + custom DNS-pinned transport |
| Security | Argon2, Fernet, itsdangerous, Redis token buckets |
| Frontend | Jinja2 + Tailwind CSS 4 + HTMX + Chart.js (vendored, offline-safe) |
| Observability | Prometheus exposition, OpenTelemetry OTLP, JSON logs |
| Deploy | Docker + Compose overlay, Nginx, Postgres-backup-local, Certbot |

---

## Repository Structure

```
app/
  main.py               # App factory, middleware, /live /ready /startup /metrics
  config.py             # Settings + production fail-fast validation
  api/v1/events.py      # Public ingest/query API
  api/deps.py           # API-key + session auth dependencies
  dashboard/views.py    # HTML UI, HTMX partials, RBAC/CSRF guards
  models/               # User, Org, Project, ApiKey, Endpoint, Event, Delivery, Attempt, AuditLog, Invitation
  services/             # event, delivery, ssrf, signing, security, rate_limiter, metrics, tracing, audit, retention, email
  workers/              # dispatcher, Celery app/tasks, runner, recovery
  templates/            # Jinja pages (dashboard, deliveries, events, endpoints, team, auth)
  static/               # Tailwind source + built CSS, vendored htmx/chart.js
migrations/             # Alembic revisions (sole schema owner)
deploy/                 # nginx.conf / nginx.dev.conf / oracle-http.conf, prometheus.yml, alerts.yml, TLS notes
docs/                   # ARCHITECTURE, SECURITY, DEMO, BENCHMARK_REPORT, BACKUP_*, KNOWN_LIMITATIONS
scripts/                # seed, bootstrap_admin, backup/restore, deploy_prod, secret rotation, demos
tests/                  # pytest suite (unit / integration / e2e) + SCENARIO_COVERAGE.md
benchmarks/             # Local throughput harness
demo_receiver/          # Tiny test webhook target (:8001)
compose.yaml            # Base stack (dev)
compose.prod.yaml       # Production overlay (TLS, no public DB/Redis ports, limits, guards)
Dockerfile              # Multi-stage (node CSS build + python runtime, non-root appuser)
Makefile                # Blessed compose entrypoints
```

---

## Quick Start

### Prerequisites

- Python 3.11+
- Docker + Compose plugin (recommended path)
- Node 22+ only if rebuilding Tailwind CSS manually

### Option A — Docker (recommended)

```bash
cp .env.example .env  # or create .env from the Configuration section below
# edit .env: POSTGRES_PASSWORD, SECRET_KEY, SIGNING_SECRET_ENCRYPTION_KEY,
# API_KEY_PEPPER, METRICS_API_KEY, REDIS_PASSWORD

docker compose up --build -d
docker compose up --build migrations   # one-shot alembic upgrade head
curl http://127.0.0.1:8080/ready
```

Open `http://127.0.0.1:8080`.

### Option B — Local Python

```powershell
# PowerShell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt

.\.venv\Scripts\alembic.exe upgrade head
```

Registration is closed by default (`ALLOW_OPEN_REGISTRATION=False`). Recommended paths for the first owner: set `ALLOW_PENDING_REGISTRATION=True` and approve yourself via an existing superadmin at `/dashboard/admin/pending`, or bootstrap directly (no open registration needed):

```powershell
# Start the server
.\.venv\Scripts\python.exe -m uvicorn app.main:app --port 8080 --reload

# Create the first owner (separate terminal, no open registration needed)
.\.venv\Scripts\python.exe scripts/bootstrap_admin.py --email you@example.com --password 'StrongPass123!'
```

Open `http://127.0.0.1:8080/auth/login` and sign in. Everyone else joins via the approval queue or team invitations.

To test deliveries locally, point an endpoint at a public request-bin, or set `ALLOW_LOCAL_RECEIVERS=True` and run the bundled receiver, then use **Publish Test Event** in the dashboard.

> Production CSS is prebuilt (`npm run build:css` → `app/static/css/dist.css`). Do not use the Tailwind browser CDN — Docker builds it automatically.

---

## Configuration

Key environment variables (see `app/config.py` for the full list and `*_FILE` Docker-Secrets variants):

| Variable | Default | Description |
|---|---|---|
| `ENV` | `development` | `production` enables strict guards (Secure cookies, docs hidden, Bearer-only `/metrics`) |
| `DEBUG` | `False` | Never `True` in production |
| `DATABASE_URL` | local Postgres | PostgreSQL (prod) or SQLite (offline dev/test) |
| `REDIS_URL` | `redis://localhost:6379/0` | Broker, rate limits, session denylist |
| `SECRET_KEY` | dev placeholder | Session/cookie signing — must be strong in prod |
| `SIGNING_SECRET_ENCRYPTION_KEY` | dev placeholder | Fernet key for endpoint HMAC secrets; `..._FALLBACK` holds prior keys for rotation |
| `API_KEY_PEPPER` | empty | HMAC pepper for API-key hashes |
| `METRICS_API_KEY` | empty | Bearer token for `/metrics` (≥16 chars, required in prod) |
| `ALLOW_OPEN_REGISTRATION` | `False` | Keep `False` in prod; use invitations or `bootstrap_admin.py` |
| `ALLOW_PENDING_REGISTRATION` | `False` | If `True`, signups become `pending` users with zero access until approved |
| `ALLOW_LOCAL_RECEIVERS` | `False` | `True` only for local loopback testing |
| `ALLOWED_RECEIVER_DOMAINS` | empty | Required in prod, e.g. `merchant.example.com,receiver.example.org` |
| `USE_CELERY` / `ENABLE_INPROCESS_DISPATCHER` | `False` / `False` | Celery+Redis in prod; in-process thread for simple dev |
| `USE_DEMO_RETRY_POLICY` | `True` | `False` in prod (fail-fast guard) |
| `MAX_DELIVERY_ATTEMPTS` | `5` | Attempt budget before `DEAD` |
| `HTTP_TIMEOUT_SECONDS` / `LEASE_DURATION_SECONDS` | `10` / `30` | Timeout must stay well under lease |
| `MAX_PAYLOAD_SIZE_BYTES` | `1048576` | Ingest limit (1 MB) |
| `MAX_ENDPOINTS_PER_PROJECT` | `20` | Endpoint cap per project |
| `INGESTION_RATE_LIMIT_PER_SECOND` | `30.0` | Per-project ingest throttle |
| `DATA_RETENTION_DAYS` / `AUDIT_RETENTION_DAYS` | `90` / `365` | `0` disables purging; legal-hold projects excluded |
| `PUBLIC_BASE_URL` | — | Required in prod, e.g. `https://hooks.example.com` |
| `SMTP_HOST/PORT/USERNAME/PASSWORD/FROM_EMAIL` | — | Required in prod for forgot-password OTP email |
| `TRUSTED_PROXIES` | — | Narrow CIDRs for `X-Forwarded-For` (loopback always trusted) |

Production refuses to boot on weak/placeholder secrets, missing allowlist/SMTP/Redis auth, demo retry policy, or `LEASE <= HTTP_TIMEOUT + 5`.

---

## Usage

### Publish an event

```bash
curl -X POST http://127.0.0.1:8080/api/v1/events \
  -H "Authorization: Bearer wh_live_YOUR_API_KEY" \
  -H "Idempotency-Key: payment-txn-10492" \
  -H "Content-Type: application/json" \
  -d '{
    "type": "payment.succeeded",
    "data": {
      "payment_id": "pay_9841",
      "order_id": "ord_1029",
      "amount_minor": 249900,
      "currency": "INR"
    }
  }'
```

Response (`202 Accepted`):

```json
{
  "event_id": "evt_48a92f085b3149ec",
  "status": "accepted",
  "delivery_count": 1
}
```

- Reusing the same `Idempotency-Key` with the identical type + payload is a no-op returning the original event.
- Reusing it with different content returns `409 Conflict`.
- Payloads over 1 MB return `413`; throttled projects return `429` with `Retry-After`.

### Verify a webhook (receiver side)

Each POST carries `Webhook-Event-Id`, `Webhook-Delivery-Id`, `Webhook-Timestamp`, and `Webhook-Signature: v1=<hex>` where `<hex> = HMAC_SHA256(secret, f"{event_id}.{timestamp}.{raw_body}")`.

```python
import hmac, hashlib

def verify(secret: str, event_id: str, timestamp: str, raw_body: bytes, signature: str) -> bool:
    expected = hmac.new(
        secret.encode(), f"{event_id}.{timestamp}.".encode() + raw_body, hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(f"v1={expected}", signature)
```

Reject timestamps older than 5 minutes to prevent replay.

### Target a subset of endpoints

`POST /dashboard/events/send-test` and the API support publishing to selected `endpoint_ids` (validated against the project); otherwise all enabled endpoints with matching subscriptions (`*` or `prefix.*`) receive the event.

---

## API Reference

Public API (Bearer `wh_live_...`):

| Method & Path | Description |
|---|---|
| `POST /api/v1/events` | Ingest event, fan out deliveries (`202`) |
| `GET /api/v1/events/{event_id}` | Event + deliveries (project-scoped) |
| `GET /api/v1/events/{event_id}/deliveries` | Deliveries for an event |
| `GET /api/v1/deliveries/{delivery_id}` | Delivery + attempts |

Dashboard (cookie `wh_session`, CSRF on POST; `owner`/`admin` required for mutations):

- `/dashboard` overview + HTMX partials (`/dashboard/deliveries/table`, `/dashboard/deliveries/{id}/drawer`, `/dashboard/deliveries/{id}/live`, `/dashboard/metrics/chart?range=1h|24h|7d|30d`)
- `/dashboard/events`, `/dashboard/events/send-test`, `/dashboard/events/{id}`
- `/dashboard/endpoints`, `/dashboard/endpoints/{id}` (+ `toggle` / `disable` / `rotate-secret` / `edit` / `delete` / `ping`)
- `/dashboard/deliveries`, `/dashboard/deliveries/{id}`, `/dashboard/dead-letters` (+ `replay`, `replay-all`)
- `/dashboard/api-keys` (+ `revoke`), `/dashboard/audit-logs`, `/dashboard/projects`, `/dashboard/team`

Health and ops:

| Path | Description |
|---|---|
| `GET /live`, `GET /health` | Liveness (`{"status":"ok"}`) |
| `GET /ready` | DB + migration + Redis readiness |
| `GET /startup` | Schema/migration startup check |
| `GET /metrics` | Prometheus exposition (Bearer `METRICS_API_KEY`; 30s cache) |

---

## Dashboard

- **Overview:** KPI cards (volume, success rate, latency, retries), delivery-performance chart (24h default, IST axis), endpoint-health donut, recent deliveries/events.
- **Deliveries:** searchable, filterable, auto-polled table; row opens a slide-over inspector with envelope, headers, HMAC inputs, wire payload, and the full attempt timeline.
- **Dead letters:** filtered `DEAD` queue with single and bulk (capped at 100) replay.
- **Endpoints:** create/edit/disable/delete, subscription patterns, per-endpoint rate limit, ping, secret rotation with corruption diagnosis.
- **Events:** ingest history, fan-out counts, per-event delivery drill-down, test-event publisher with targeted fan-out.
- **Team & audit:** invitations with expiry/revocation, role pills, approval queue for pending users, full audit trail.

---

## Security

See [`docs/SECURITY.md`](docs/SECURITY.md) for the full threat model. Highlights:

- SSRF deny-by-default + DNS pinning with startup compatibility self-test.
- Secrets encrypted at rest, rotated without downtime (`MultiFernet` + `rotate_or_repair_endpoint_secrets.py`); logs scrub credentials.
- Sessions/CSRF bound and revocable; login/registration/invitation/reset all rate-limited.
- Same-origin back-redirects, bounded pagination, `LIKE`-wildcard escaping, XSS-safe templates, hardened headers (CSP/HSTS/nosniff).

---

## Observability

- **Metrics** (`app/services/metrics.py`): `webhook_events_total`, `webhook_deliveries_total{status}`, `webhook_delivery_attempts_total{outcome}`, `..._by_error{error_code}` (top 20), latency average + histogram buckets, `webhook_deliveries_by_endpoint`, `webhook_backlog_total`. Scrape config rendered via `scripts/render_prometheus.sh`; alerts in `deploy/alerts.yml` (backlog, dead-letter surge, stalled deliveries, unexpected errors).
- **Tracing:** OpenTelemetry spans for ingest, dispatch, HTTP POST, recovery, and retention; `traceparent` injected on outbound webhooks.
- **Logs:** single-line JSON to stdout with `request_id` / `client_ip` correlation.
- **Probes:** `/live` for process, `/ready` for DB/Redis/migrations, `/startup` for schema.

Access `/metrics`:

```bash
curl -H "Authorization: Bearer $METRICS_API_KEY" https://YOUR_DOMAIN/metrics
```

---

## Testing

```powershell
.\.venv\Scripts\python.exe -m pytest -v
```

Coverage includes SSRF/IP validation, HMAC sign/verify + timestamp tampering, atomic ingest + endpoint matching, idempotency conflicts, backoff/jitter + `Retry-After`, lease recovery, dead-letter/replay guards, targeted delivery, RBAC/team/invitations, approval queue, password-reset exposure, audit + secret rotation, rate limits, error pages, prod-compose enforcement, and HTMX partials. See [`tests/SCENARIO_COVERAGE.md`](tests/SCENARIO_COVERAGE.md).

Static checks:

```bash
ruff check app tests scripts
ruff format --check app tests scripts
```

---

## Production Deployment

Base `compose.yaml` is plain HTTP for local dev. Production **must** use the overlay:

```bash
cp .env.example .env  # if present, else create .env per Configuration
# edit .env: SECRET_KEY, SIGNING_SECRET_ENCRYPTION_KEY, API_KEY_PEPPER,
# METRICS_API_KEY, POSTGRES_PASSWORD, REDIS_URL, ALLOWED_RECEIVER_DOMAINS,
# PUBLIC_BASE_URL=https://your.domain, SMTP_HOST/PASSWORD/FROM_EMAIL

cp /etc/letsencrypt/live/YOUR_DOMAIN/fullchain.pem deploy/tls/fullchain.pem
cp /etc/letsencrypt/live/YOUR_DOMAIN/privkey.pem deploy/tls/privkey.pem

make deploy-prod
# equivalent: ./scripts/deploy_prod.sh up --build -d

docker compose -f compose.yaml -f compose.prod.yaml exec web alembic upgrade head
curl https://YOUR_DOMAIN/ready
```

The blessed entrypoints (`make deploy-prod`, `scripts/deploy_prod.sh`) enforce the overlay, `ENV=production`, required secrets, and real TLS — bare `docker compose up` is rejected for production and fails CI (`scripts/enforce_prod_compose.sh`).

**First owner with closed registration:**

```bash
docker compose -f compose.yaml -f compose.prod.yaml run --rm web \
  python scripts/bootstrap_admin.py --email admin@example.com --password 'StrongPass123!'
```

Keep `ALLOW_OPEN_REGISTRATION=False`; further users join via team invitations. Full checklist: [`docs/SECURITY.md`](docs/SECURITY.md) §3. Backups: [`docs/BACKUP_AND_DISASTER_RECOVERY.md`](docs/BACKUP_AND_DISASTER_RECOVERY.md).

**Oracle Cloud Ampere A1 note:** all images are multi-arch (native ARM64 build on the VM). Defaults target 1 OCPU / 6 GB; on 4 OCPU / 24 GB raise `CELERY_CONCURRENCY` to 4–8. For pre-DNS boot, use `NGINX_CONF=./deploy/nginx.oracle-http.conf DEPLOY_PROD_ALLOW_MISSING_TLS=1 ./scripts/deploy_prod.sh up --build -d`, verify `/ready`, bootstrap the admin, then switch to TLS + `make deploy-prod`. Nightly backups land in `./backups/` (14-day keep in prod).

---

## Operations

```bash
make ps-prod / logs-prod / down-prod   # prod status, logs, shutdown
make up-dev / down-dev                 # local dev only (base file, no overlay)
make migrate-prod / migrate-dev        # explicit migration runs
```

Useful scripts: `seed.py` (dev/demo data, refuses prod), `backup_postgres.sh` / `restore_postgres.sh`, `migrate_sqlite_to_postgres.py`, `rotate_or_repair_endpoint_secrets.py`, `check_cert_expiry.sh`, `interactive_demo.py` (live failure → retry → dead → replay walkthrough).

---

## Documentation

| Document | Contents |
|---|---|
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | Lifecycle, leases, retries, guarantees |
| [`docs/SECURITY.md`](docs/SECURITY.md) | Threat model and defenses |
| [`docs/DEMO.md`](docs/DEMO.md) | 8-minute scripted demo |
| [`docs/BENCHMARK_REPORT.md`](docs/BENCHMARK_REPORT.md) | Throughput measurements |
| [`docs/BACKUP_AND_RESTORE.md`](docs/BACKUP_AND_RESTORE.md) | Backup/verify/restore runbook |
| [`docs/BACKUP_AND_DISASTER_RECOVERY.md`](docs/BACKUP_AND_DISASTER_RECOVERY.md) | RPO/RTO strategy |
| [`docs/KNOWN_LIMITATIONS.md`](docs/KNOWN_LIMITATIONS.md) | Trade-offs and scale roadmap |
| [`CHANGELOG.md`](CHANGELOG.md) | Release history (SemVer) |

---

## Known Limitations

- Single-region Postgres as the system of record; horizontal scale is via workers, not multi-primary DB.
- Prometheus cardinality capped (top-20 error codes, 200 endpoint series) by design.
- SQLite path is for offline dev/test only — use Postgres in production.
- Details and roadmap: [`docs/KNOWN_LIMITATIONS.md`](docs/KNOWN_LIMITATIONS.md).

---

## Contributing

1. Create a virtualenv, install `requirements.txt` (+ `pytest`, `ruff`, `black` for dev).
2. Run migrations (`alembic upgrade head`) before starting the server.
3. Rebuild CSS after template/class changes: `npm run build:css`.
4. Keep `ruff check` and `ruff format --check` clean; add/extend tests with every behavior change (`pytest -v`).
5. Never commit secrets — use env vars or `*_FILE` Docker Secrets; production guards fail fast on placeholders.
