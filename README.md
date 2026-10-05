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
- **Controllable Demo Receiver**:
  - Built-in simulator app to easily test: Always 200, Fail first N requests, 429 rate limit, or slow timeout.
- **Automated Load Testing & Benchmarking**:
  - Asynchronous load testing tool (`benchmarks/run_benchmark.py`) measuring throughput and p50/p95 latency.

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

### 1. Run Migrations & Seed Sample Data
```powershell
# In PowerShell:
.\.venv\Scripts\alembic.exe upgrade head
.\.venv\Scripts\python.exe scripts/seed.py
```

Demo credentials created:
- **Dashboard URL**: `http://127.0.0.1:8080/auth/login`
- **Email**: `demo@example.com`
- **Password**: `Password123!`
- **Pre-configured API Key**: `wh_live_demo1234567890abcdef123456`

### 2. Start the Controllable Demo Receiver (Port 8001)
In a new terminal:
```powershell
.\.venv\Scripts\python.exe -m uvicorn demo_receiver.app:app --port 8001 --reload
```
Open [http://127.0.0.1:8001](http://127.0.0.1:8001) to view the simulator panel.

### 3. Start the Main Platform (Port 8080)
In another terminal:
```powershell
.\.venv\Scripts\python.exe -m uvicorn app.main:app --port 8080 --reload
```
Open [http://127.0.0.1:8080](http://127.0.0.1:8080) in your browser.

---

## 4. How to Publish Events via API

### Example cURL Request:
```bash
curl -X POST http://127.0.0.1:8080/api/v1/events \
  -H "Authorization: Bearer wh_live_demo1234567890abcdef123456" \
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

Run all 20 unit and integration tests with pytest:
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

## 6. Interview Demonstration Walkthrough

1. **Open the Controllable Receiver** at `http://127.0.0.1:8001`.
   - Set mode to **"Fail First N Requests (then 200)"** with count = `3`.
2. **Open the Platform Dashboard** at `http://127.0.0.1:8080`.
   - Sign in with `demo@example.com` / `Password123!`.
3. **Publish an Event**:
   - Click **"Publish Test Event"** and submit `payment.succeeded`.
4. **Watch Real-Time Retries**:
   - In the Dashboard Overview, observe the delivery status change:
     - Attempt #1: HTTP 500 $\rightarrow$ `RETRY_SCHEDULED`
     - Attempt #2: HTTP 500 $\rightarrow$ `RETRY_SCHEDULED`
     - Attempt #3: HTTP 500 $\rightarrow$ `RETRY_SCHEDULED`
     - Attempt #4: HTTP 200 OK $\rightarrow$ `SUCCEEDED`
5. **Inspect Attempt Timeline**:
   - Click into the delivery to see the step-by-step visual timeline with latency, HTTP codes, and response excerpts.
6. **Simulate a Dead Letter & Replay**:
   - Change receiver mode to **HTTP 400 Bad Request** (permanent client error).
   - Publish an event $\rightarrow$ immediately marked as `DEAD`.
   - Click **"Replay Delivery"** $\rightarrow$ a new linked delivery is created preserving the original event ID with a reset attempt budget.
