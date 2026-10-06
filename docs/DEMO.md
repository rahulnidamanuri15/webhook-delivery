# Reproducible Demo (replaces recorded video until one is published)

This is the scripted 8-minute interview demonstration from the spec (§16).
It runs fully locally with `compose.yaml` or two `uvicorn` processes.

## 0. Prerequisites

```powershell
alembic upgrade head
python scripts/seed.py
# terminal 1:
python -m uvicorn demo_receiver.app:app --port 8001 --reload
# terminal 2:
python -m uvicorn app.main:app --port 8080 --reload
```

Demo login: `demo@example.com` / `Password123!`
Demo API key: `wh_live_demo1234567890abcdef123456`
Receiver: `http://127.0.0.1:8001/webhook` (secret in seed output)

Set receiver admin token for remote use (optional locally):
```powershell
$env:DEMO_RECEIVER_ADMIN_TOKEN="demo-local-token-change-me"
```

## 1. Register the demo receiver (1 min)

Dashboard → Endpoints → URL `http://127.0.0.1:8001/webhook`, subscriptions `*`.
Copy the endpoint signing secret into the receiver's "Endpoint Signing Secret" field.

## 2. Fail-first-3 then recover (3 min)

1. Receiver → mode **Fail First N Requests**, N=`3`, code `500`.
2. Publish `payment.succeeded` (Dashboard → Publish Test Event, or `POST /api/v1/events`).
3. Delivery timeline shows:
   - Attempt #1 `HTTP 500` → `RETRY_SCHEDULED`
   - Attempt #2 `HTTP 500` → `RETRY_SCHEDULED`
   - Attempt #3 `HTTP 500` → `RETRY_SCHEDULED`
   - Attempt #4 `HTTP 200` → `SUCCEEDED`
4. Point out backoff + jitter and fresh `Webhook-Timestamp`/`Webhook-Signature` per attempt.

## 3. Dead letter + replay (2 min)

1. Receiver → mode **HTTP 400 Bad Request** (non-retryable) or `fail_n` with N≥max attempts.
2. Publish event → delivery goes `DEAD` immediately (400) or after budget exhaustion.
3. Dead-letters page → **Replay** → new delivery with same `Webhook-Event-Id`,
   new `Webhook-Delivery-Id`, `replay_of_delivery_id` link, fresh 5-attempt budget.
4. Receiver deduplicates on `Webhook-Event-Id` if it already processed the event.

## 4. Crash-after-processing duplicate (2 min, whiteboard + logs)

> Receiver returns 200 but the worker crashes before recording success →
> lease expires → recovery reschedules → receiver sees the same `event_id` again.

Show `IN_FLIGHT` + `lease_expires_at` in DB, kill `-9` a worker (or `dispatcher` log
`[Crash Recovery] Reclaimed …`), and show the receiver's **Duplicate** badge.
State the guarantee honestly: **at-least-once**, receiver-side dedup required.

## 5. What to record

Record steps 2–4 with timestamps visible (delivery timeline + receiver table side by side).
Use the short demo retry policy (`USE_DEMO_RETRY_POLICY=True`, 2/5/10/20/40s) so the
video stays under 8 minutes.

Automated script (no manual clicking):

```powershell
python scripts/interactive_demo.py --mode fail-3-then-succeed
python scripts/interactive_demo.py --mode dead-then-replay
```

Publish the video link here when available:

- Demo video: `docs/demo-script.md` contains the shot list; record with OBS and upload to Loom/YouTube, then replace this line with the URL.
