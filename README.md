# Reliable Webhook Delivery Platform

A production-grade, multi-tenant webhook delivery platform built with **FastAPI**, **PostgreSQL / SQLAlchemy**, background workers, **HMAC-SHA256 signing**, **lease-based crash recovery**, and a server-rendered **HTML + Tailwind CSS** developer dashboard.

> *"Your application tells our platform that a payment succeeded. We deliver that event to the merchant's server, record what happened, and retry if the server is temporarily unavailable."*

---

## 1. Key Features

- **Durable Event Storage**: Single-transaction atomic event ingestion and delivery generation in PostgreSQL.
- **Idempotency Guarantee**:
  - Reusing the same `Idempotency-Key` with the identical payload returns the existing event without re-triggering duplicate deliveries.
  - Reusing the same `Idempotency-Key` with differing content returns `409 Conflict`.
- **HMAC-SHA256 Request Signing**:
  - Outgoing headers include `Webhook-Event-Id`, `Webhook-Delivery-Id`, `Webhook-Timestamp`, and `Webhook-Signature: v1=<hex>`.
  - Secrets are encrypted at rest using AES-128-CBC / Fernet and never stored in plaintext.
- **Lease-Based Worker Crash Recovery**:
  - Workers claim deliveries using an execution lease (`lease_token` and `lease_expires_at`).
  - Network requests run **outside** database transactions.
  - If a worker crashes or hangs mid-delivery, a periodic recovery scanner restores orphaned deliveries to `RETRY_SCHEDULED`.
- **Exponential Backoff & Jitter**:
  - Configurable retry schedule with jitter to eliminate thundering herd problems.
  - Respects HTTP 429 `Retry-After` headers.
- **SSRF Protection**:
  - Blocks internal, loopback (`127.0.0.0/8`, `::1`), private RFC1918 (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), and cloud metadata (`169.254.169.254`) ranges.
  - Development override toggle allows local controllable demo receivers during development.
- **Dead-Letter Queue & 1-Click Replay**:
  - Failed deliveries that exhaust their attempt budget transition to `DEAD`.
  - Replaying creates a new linked delivery (`replay_of_delivery_id`) preserving original event identity and giving a fresh attempt budget.
- **Team Management & Role-Based Access Control (RBAC)**:
  - Supports `owner`, `admin`, and `member` roles.
  - Organization invitations with expiring tokens, accept flow, and revocation.
- **Prometheus Metrics & OpenTelemetry Tracing**:
  - Prometheus `/metrics` endpoint exporting counters, delivery state gauges, latency, and backlog.
  - OpenTelemetry distributed tracing spans linking ingestion, dispatch, and outbound delivery.
- **Developer Dashboard**:
  - Built with **HTML + Tailwind CSS + HTMX** (zero React/Node runtime required).
  - Real-time auto-refreshing delivery tables via HTMX polling.
  - Delivery attempt timeline showing duration, HTTP status code, and bounded response excerpts.
  - Visual delivery distribution bar and audit log viewer.

---

## 2. Architecture & State Machine

### Delivery State Machine

```
               +-------------+
               |   PENDING   |
               +------+------+
                      |
                      | Claimed by worker (lease token assigned)
                      v
               +-------------+
               |  IN_FLIGHT  |
               +--+---+---+--+
                  |   |   |
      +-----------+   |   +-----------------------+
      | HTTP 2xx      | Retryable failure         | 4xx or Max Attempts
      v               v                           v
+-----------+   +-------------------+       +-----------+
| SUCCEEDED |   |  RETRY_SCHEDULED  |       |   DEAD    |  (Dead Letters)
+-----------+   +---------+---------+       +-----+-----+
                          |                       |
                          | (Next attempt due)    | 1-Click Replay
                          v                       v
                    [ IN_FLIGHT ]          [ New Delivery ]
```

---

## 3. Quick Start (Local Setup)

### Prerequisites
- Python 3.11+
- Virtual environment activated

### 1. Run Migrations & Create the First Owner
```powershell
# In PowerShell:
.\.venv\Scripts\alembic.exe upgrade head
```

Registration is closed by default (`ALLOW_OPEN_REGISTRATION=False`). To create
the first owner account, temporarily allow open registration in `.env`:

```powershell
# .env: set ALLOW_OPEN_REGISTRATION=True, then:
.\.venv\Scripts\python.exe -m uvicorn app.main:app --port 8080 --reload
```

Open `http://127.0.0.1:8080/auth/register`, register your owner account (it is
created as org `owner` with a default project), then set
`ALLOW_OPEN_REGISTRATION=False` again and restart. Further users join via team
invitations.

### 2. Start the Main Platform (Port 8080)
In another terminal:
```powershell
.\.venv\Scripts\python.exe -m uvicorn app.main:app --port 8080 --reload
```
Open [http://127.0.0.1:8080](http://127.0.0.1:8080) in your browser.

To test deliveries locally, point an endpoint at any publicly reachable test
URL (e.g. a request-bin) or run a tiny local receiver with
`ALLOW_LOCAL_RECEIVERS=True`, then publish via **"Publish Test Event"** in the
dashboard.

Production CSS is prebuilt (`npm run build:css` → `app/static/css/dist.css`);
do not use the Tailwind browser CDN. Docker builds it automatically.

See `docs/SECURITY.md` for the retention/allowlist/Redis-fallback policy.

---

## 6. Production Deployment

Base `compose.yaml` runs nginx as plain HTTP (`deploy/nginx.dev.conf`) — for
production you MUST apply the `compose.prod.yaml` overlay (TLS via
`deploy/nginx.conf`, no public DB/Redis ports, resource limits, prod guards):

```bash
# 1. Create your secrets (never reuse dev values — prod refuses to boot with them)
cp .env.example .env
# edit .env: SECRET_KEY, SIGNING_SECRET_ENCRYPTION_KEY, API_KEY_PEPPER,
# METRICS_API_KEY, POSTGRES_PASSWORD, REDIS_URL (redis://:pass@redis:6379/0),
# ALLOWED_RECEIVER_DOMAINS, PUBLIC_BASE_URL (https://your.domain),
# SMTP_HOST, SMTP_PASSWORD, SMTP_FROM_EMAIL

# 2. Place real TLS certs (Let's Encrypt) — dev self-signed files will NOT do
cp /etc/letsencrypt/live/YOUR_DOMAIN/fullchain.pem deploy/tls/fullchain.pem
cp /etc/letsencrypt/live/YOUR_DOMAIN/privkey.pem deploy/tls/privkey.pem

# 3. Launch with the prod overlay (blessed entrypoints enforce it — never
#    run bare `docker compose up` for production; CI fails such builds)
make deploy-prod
# equivalent: ./scripts/deploy_prod.sh up --build -d

# 4. Verify
docker compose -f compose.yaml -f compose.prod.yaml exec web alembic upgrade head
curl -k https://YOUR_DOMAIN/ready
```

Prod requirements enforced at boot (`app/config.py` fail-fast): `ENV=production`,
`DEBUG=False`, `USE_DEMO_RETRY_POLICY=False`, `ALLOW_LOCAL_RECEIVERS=False`,
`ALLOW_OPEN_REGISTRATION` defaulting to `False`, non-empty `ALLOWED_RECEIVER_DOMAINS`, strong
secrets. Full checklist: `docs/SECURITY.md` §3. Backups:
`docs/BACKUP_AND_DISASTER_RECOVERY.md`.

### Oracle Cloud Always Free ARM VM (Ampere A1)

All images (`python:3.11-slim`, `postgres:16-alpine`, `redis:7-alpine`,
`nginx:1.27-alpine`) are multi-arch — building on the ARM VM yields a native
ARM64 image. Resource limits in `compose.prod.yaml` default to the smallest
shape (1 OCPU / 6 GB); on 4 OCPU / 24 GB raise `CELERY_CONCURRENCY` to 4-8.

```bash
# 0. On the VM: Ubuntu 22.04+ ARM, Docker + Compose plugin, ports 80/443 open
#    in the VCN security list AND in iptables/firewalld. Clone lean:
git clone <your-repo-url> webhook-delivery && cd webhook-delivery

# 1. Secrets (same as above)
cp .env.example .env && nano .env

# 2a. STAGE 1 — no domain yet (HTTP-only, ACME/preflight ONLY):
#     The HTTP-only proxy exists so Let's Encrypt can reach
#     /.well-known/acme-challenge/ and so you can curl /ready and /healthz.
#     Do NOT register or log in over plain HTTP: production sets Secure
#     session/CSRF cookies, which browsers never send over HTTP, so the
#     dashboard login cannot work until HTTPS is up. Create the first owner
#     with the bootstrap script instead (no open registration needed):
NGINX_CONF=./deploy/nginx.oracle-http.conf DEPLOY_PROD_ALLOW_MISSING_TLS=1 \
  ./scripts/deploy_prod.sh up --build -d
curl http://<VM_PUBLIC_IP>/ready   # {"status":"ready",...}
curl http://<VM_PUBLIC_IP>/healthz # ok (via reverse_proxy)

# 2b. Create the first owner via bootstrap (registration stays closed):
docker compose -f compose.yaml -f compose.prod.yaml run --rm web \
  python scripts/bootstrap_admin.py --email admin@example.com --password 'StrongPass123!'
# (Refuses to run if users already exist unless --force; never logs the password.)

# 3. STAGE 2 — domain + TLS (once DNS points at the VM):
#    issue certs (see deploy/tls/README.md), copy fullchain.pem + privkey.pem
#    into deploy/tls/, then:
make deploy-prod
curl https://YOUR_DOMAIN/ready
# Now sign in over HTTPS: https://YOUR_DOMAIN/auth/login (owner from step 2b).
# Keep ALLOW_OPEN_REGISTRATION=False in .env; further users join via team
# invitations. Never weaken Secure cookie flags to make HTTP login work.
```

Nightly DB backups land in `./backups/` via the `db_backup` service (7-day
retention). Operate with `make ps-prod / logs-prod / down-prod`.

---

## 4. How to Publish Events via API

### Example cURL Request:
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

### Response (`202 Accepted`):
```json
{
  "event_id": "evt_48a92f085b3149ec",
  "status": "accepted",
  "delivery_count": 1
}
```

---

## 5. Running the Automated Test Suite

Run the full test suite with pytest:
```powershell
.\.venv\Scripts\python.exe -m pytest -v
```

Test coverage includes:
- SSRF prevention & IP range validation
- HMAC-SHA256 signature verification & timestamp tampering
- Atomic event ingestion & endpoint matching
- Idempotency key reuse & conflict handling (`409 Conflict`)
- Retry backoff calculation & jitter
- Worker lease expiration crash recovery
- Dead-letter state transitions & manual replay

---

## 4. How to Publish Events via API
