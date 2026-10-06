import html
import os
import sqlite3
import time
from typing import Any

from fastapi import FastAPI, Form, Header, HTTPException, Request, Response
from fastapi.responses import HTMLResponse, RedirectResponse

from app.services.signing import verify_webhook_signature

app = FastAPI(title="Controllable Webhook Demo Receiver")

ADMIN_TOKEN = os.getenv("DEMO_RECEIVER_ADMIN_TOKEN", "")


def _require_admin(request: Request, token_field: str | None = None):
    """Protects behaviour-changing controls.

    - Only allow loopback callers without token if DEMO_RECEIVER_ADMIN_TOKEN is empty.
    - If DEMO_RECEIVER_ADMIN_TOKEN is set: require matching token via X-Admin-Token
      header, form field admin_token, or query param admin_token.
    """
    client_host = ""
    try:
        client_host = request.client.host if request.client else ""
    except Exception:
        client_host = ""
    is_loopback = client_host in ("127.0.0.1", "::1", "localhost", "testclient", "")

    if not ADMIN_TOKEN:
        if is_loopback:
            return
        raise HTTPException(
            status_code=403,
            detail="Admin token is not configured on demo receiver."
        )

    provided = (token_field or "").strip() or request.headers.get("x-admin-token", "").strip()
    if not provided:
        try:
            provided = (request.query_params.get("admin_token", "") or "").strip()
        except Exception:
            provided = ""

    # Allow local loopback callers if provided token matches or in local testing
    import hmac as _hmac
    if not provided or not _hmac.compare_digest(provided, ADMIN_TOKEN):
        raise HTTPException(
            status_code=403,
            detail="Invalid or missing admin token for demo-receiver controls."
        )

# Receiver state and configurations
config = {
    "mode": "success",          # "success", "fail_n", "rate_limit", "slow"
    "fail_count": 3,            # For "fail_n": fail this many times then succeed
    "failure_status_code": 500, # Status code to return when failing
    "current_failures": 0,      # Counter of consecutive failures
    "rate_limit_delay_sec": 3,  # Retry-After value for 429
    "slow_delay_sec": 5,        # Sleep duration for slow response
    "endpoint_secret": "",      # If provided, verifies signature
    "enforce_signatures": True, # When True, reject webhooks if no endpoint_secret is configured
}

received_events: list[dict[str, Any]] = []
seen_event_ids: set = set()

# Atomic SQLite-backed deduplication
_DEDUP_DB_FILE = os.getenv("DEMO_RECEIVER_DB_FILE", "/tmp/demo_receiver.db")

def _init_dedup_db() -> None:
    try:
        with sqlite3.connect(_DEDUP_DB_FILE) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS processed_events (
                    event_id TEXT PRIMARY KEY,
                    processed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            conn.commit()
            rows = conn.execute("SELECT event_id FROM processed_events").fetchall()
            for r in rows:
                seen_event_ids.add(r[0])
    except Exception:
        pass

def _record_processed_event(event_id: str) -> bool:
    """Atomically records event_id in SQLite transaction."""
    seen_event_ids.add(event_id)
    try:
        with sqlite3.connect(_DEDUP_DB_FILE) as conn:
            conn.execute("INSERT OR IGNORE INTO processed_events (event_id) VALUES (?)", (event_id,))
            conn.commit()
            return True
    except Exception:
        return False

def _clear_dedup_db() -> None:
    seen_event_ids.clear()
    try:
        with sqlite3.connect(_DEDUP_DB_FILE) as conn:
            conn.execute("DELETE FROM processed_events")
            conn.commit()
    except Exception:
        pass

_init_dedup_db()

@app.get("/", response_class=HTMLResponse)
def index():
    """Receiver Dashboard & Control Panel."""
    rows = ""
    for item in reversed(received_events[-20:]):
        sig_badge = (
            '<span style="background:#dcfce7;color:#166534;padding:2px 8px;border-radius:9999px;font-size:12px;">Valid</span>'
            if item["sig_valid"] is True
            else '<span style="background:#fee2e2;color:#991b1b;padding:2px 8px;border-radius:9999px;font-size:12px;">Invalid</span>'
            if item["sig_valid"] is False
            else '<span style="background:#f3f4f6;color:#374151;padding:2px 8px;border-radius:9999px;font-size:12px;">Unverified</span>'
        )
        dedup_badge = (
            '<span style="background:#fef3c7;color:#92400e;padding:2px 8px;border-radius:9999px;font-size:12px;">Duplicate</span>'
            if item["is_duplicate"]
            else '<span style="background:#e0e7ff;color:#3730a3;padding:2px 8px;border-radius:9999px;font-size:12px;">First seen</span>'
        )
        status_color = "#16a34a" if item["returned_status"] < 300 else "#dc2626"
        escaped_payload = html.escape(str(item.get("payload", "")))
        rows += f"""
        <tr style="border-bottom: 1px solid #e5e7eb;">
            <td style="padding:10px;font-family:monospace;font-size:12px;">{item["received_at"]}</td>
            <td style="padding:10px;font-family:monospace;font-size:12px;font-weight:600;">{item["event_id"]}</td>
            <td style="padding:10px;font-family:monospace;font-size:12px;">{item["delivery_id"]}</td>
            <td style="padding:10px;font-weight:bold;color:{status_color};">{item["returned_status"]}</td>
            <td style="padding:10px;">{sig_badge}</td>
            <td style="padding:10px;">{dedup_badge}</td>
            <td style="padding:10px;"><pre style="margin:0;font-size:11px;max-width:350px;overflow:hidden;text-overflow:ellipsis;">{escaped_payload}</pre></td>
        </tr>
        """

    if not rows:
        rows = '<tr><td colspan="7" style="padding:30px;text-align:center;color:#6b7280;">No webhooks received yet. Send an event from your platform to <code>http://127.0.0.1:8001/webhook</code></td></tr>'

    return f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Demo Webhook Receiver</title>
        <meta charset="utf-8">
        <style>
            body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #f9fafb; margin: 0; padding: 24px; color: #111827; }}
            .card {{ background: white; border-radius: 8px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); padding: 20px; margin-bottom: 24px; border: 1px solid #e5e7eb; }}
            .btn {{ background: #2563eb; color: white; border: none; padding: 8px 16px; border-radius: 6px; cursor: pointer; font-weight: 500; }}
            .btn-danger {{ background: #dc2626; }}
            input, select {{ padding: 8px 12px; border: 1px solid #d1d5db; border-radius: 6px; }}
            table {{ width: 100%; border-collapse: collapse; text-align: left; }}
            th {{ background: #f3f4f6; padding: 10px; font-size: 13px; text-transform: uppercase; color: #4b5563; }}
        </style>
    </head>
    <body>
        <div style="max-width: 1100px; margin: 0 auto;">
            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom: 20px;">
                <div>
                    <h1 style="margin:0; font-size: 24px;">Controllable Webhook Receiver</h1>
                    <p style="margin:4px 0 0 0; color: #6b7280;">Listening on <code>http://127.0.0.1:8001/webhook</code></p>
                </div>
                <form action="/clear" method="post" style="display:flex; gap:8px;">
                    <input type="password" name="admin_token" placeholder="Admin token (if configured)" style="padding:6px 10px; border-radius:6px; border:1px solid #d1d5db;">
                    <button class="btn btn-danger" type="submit">Clear Logs</button>
                </form>
            </div>

            <div class="card">
                <h3 style="margin-top:0;">Behavior Simulator</h3>
                <form action="/configure" method="post" style="display:grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 16px; align-items:end;">
                    <div>
                        <label style="display:block; font-size:13px; font-weight:500; margin-bottom:4px;">Receiver Mode</label>
                        <select name="mode" style="width:100%;">
                            <option value="success" {"selected" if config["mode"] == "success" else ""}>Always 200 OK</option>
                            <option value="fail_n" {"selected" if config["mode"] == "fail_n" else ""}>Fail First N Requests (then 200)</option>
                            <option value="rate_limit" {"selected" if config["mode"] == "rate_limit" else ""}>HTTP 429 Too Many Requests</option>
                            <option value="slow" {"selected" if config["mode"] == "slow" else ""}>Slow Response (Delay/Timeout)</option>
                        </select>
                    </div>

                    <div>
                        <label style="display:block; font-size:13px; font-weight:500; margin-bottom:4px;">Fail First N Times</label>
                        <input type="number" name="fail_count" value="{config['fail_count']}" min="1" max="10" style="width:90%;">
                    </div>

                    <div>
                        <label style="display:block; font-size:13px; font-weight:500; margin-bottom:4px;">Fail Status Code</label>
                        <select name="failure_status_code" style="width:100%;">
                            <option value="500" {"selected" if config["failure_status_code"] == 500 else ""}>500 Internal Server Error</option>
                            <option value="502" {"selected" if config["failure_status_code"] == 502 else ""}>502 Bad Gateway</option>
                            <option value="503" {"selected" if config["failure_status_code"] == 503 else ""}>503 Service Unavailable</option>
                            <option value="400" {"selected" if config["failure_status_code"] == 400 else ""}>400 Bad Request (Non-retryable)</option>
                        </select>
                    </div>

                    <div>
                        <label style="display:block; font-size:13px; font-weight:500; margin-bottom:4px;">Endpoint Signing Secret (Optional)</label>
                        <input type="text" name="endpoint_secret" value="{config['endpoint_secret']}" placeholder="whsec_..." style="width:90%;">
                    </div>

                    <div>
                        <label style="display:block; font-size:13px; font-weight:500; margin-bottom:4px;">Admin Token</label>
                        <input type="password" name="admin_token" value="" placeholder="Admin token (if configured)" style="width:90%;">
                    </div>

                    <div>
                        <button class="btn" type="submit" style="width:100%;">Update Behavior</button>
                    </div>
                </form>
                <div style="margin-top:12px; font-size:13px; color:#4b5563;">
                    Current Mode: <strong>{config['mode']}</strong> | Failures observed in current sequence: <strong>{config['current_failures']}/{config['fail_count']}</strong>
                </div>
            </div>

            <div class="card">
                <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:12px;">
                    <h3 style="margin:0;">Received Webhook Deliveries ({len(received_events)})</h3>
                    <a href="/" style="font-size:13px; color:#2563eb; text-decoration:none;">Refresh table</a>
                </div>
                <table>
                    <thead>
                        <tr>
                            <th>Time</th>
                            <th>Event ID</th>
                            <th>Delivery ID</th>
                            <th>Status</th>
                            <th>Signature</th>
                            <th>Deduplication</th>
                            <th>Payload</th>
                        </tr>
                    </thead>
                    <tbody>
                        {rows}
                    </tbody>
                </table>
            </div>
        </div>
    </body>
    </html>
    """

@app.get("/health")
def health():
    return {"status": "ok"}

@app.post("/config")
async def update_config_json(request: Request):
    data = await request.json()
    _require_admin(request, str(data.get("admin_token", "")) if isinstance(data, dict) else None)
    if "mode" in data:
        mode_val = data["mode"]
        if mode_val == "status_code":
            sc = int(data.get("status_code", 200))
            if sc < 300:
                config["mode"] = "success"
            else:
                config["mode"] = "fail_n"
                config["fail_count"] = 9999
                config["failure_status_code"] = sc
        else:
            config["mode"] = mode_val
    if "fail_count" in data:
        config["fail_count"] = int(data["fail_count"])
    if "failure_status_code" in data:
        config["failure_status_code"] = int(data["failure_status_code"])
    elif "status_code" in data and int(data["status_code"]) >= 300:
        config["failure_status_code"] = int(data["status_code"])
    if "endpoint_secret" in data:
        config["endpoint_secret"] = str(data["endpoint_secret"]).strip()
    if "enforce_signatures" in data:
        config["enforce_signatures"] = bool(data["enforce_signatures"])
    config["current_failures"] = 0
    return {"status": "updated", "config": config}

@app.post("/configure")
def configure(
    request: Request,
    mode: str = Form(...),
    fail_count: int = Form(...),
    failure_status_code: int = Form(...),
    endpoint_secret: str = Form(""),
    admin_token: str = Form(""),
):
    _require_admin(request, admin_token)
    config["mode"] = mode
    config["fail_count"] = max(1, fail_count)
    config["failure_status_code"] = failure_status_code
    config["endpoint_secret"] = endpoint_secret.strip()
    config["current_failures"] = 0  # reset sequence
    # enforce_signatures defaults True; disable only via JSON API /config
    return RedirectResponse(url="/", status_code=303)

@app.post("/clear")
def clear(request: Request, admin_token: str = Form("")):
    _require_admin(request, admin_token)
    received_events.clear()
    _clear_dedup_db()
    config["current_failures"] = 0
    return RedirectResponse(url="/", status_code=303)

@app.get("/webhook", response_class=HTMLResponse)
def webhook_info_get():
    """Friendly information page when accessing /webhook in a web browser."""
    return HTMLResponse(
        """<!DOCTYPE html><html><body style="font-family:sans-serif;padding:40px;max-width:600px;margin:auto;line-height:1.6;">
        <h2 style="color:#1e293b;">Demo Webhook Receiver</h2>
        <p>This endpoint receives <code>POST</code> webhook requests sent by the delivery platform.</p>
        <p><a href="/" style="display:inline-block;padding:10px 16px;background:#2563eb;color:white;text-decoration:none;border-radius:6px;font-weight:500;">
        Open Receiver Control Panel & Event Log &rarr;
        </a></p>
        </body></html>"""
    )


@app.post("/webhook")
async def receive_webhook(
    request: Request,
    webhook_event_id: str = Header(None, alias="Webhook-Event-Id"),
    webhook_delivery_id: str = Header(None, alias="Webhook-Delivery-Id"),
    webhook_timestamp: str = Header(None, alias="Webhook-Timestamp"),
    webhook_signature: str = Header(None, alias="Webhook-Signature"),
):
    raw_body_bytes = await request.body()
    raw_body_str = raw_body_bytes.decode("utf-8")

    # 1. Signature Verification (enforced by default; rejects if no secret configured)
    sig_valid = None
    if config["enforce_signatures"] and not config["endpoint_secret"]:
        received_events.append({
            "received_at": time.strftime("%H:%M:%S"),
            "event_id": webhook_event_id or "unknown",
            "delivery_id": webhook_delivery_id or "unknown",
            "returned_status": 500,
            "sig_valid": None,
            "is_duplicate": False,
            "payload": raw_body_str
        })
        return Response(
            content='{"error": "Signature verification required but no endpoint_secret configured. Set a secret via POST /configure."}',
            status_code=500,
            media_type="application/json"
        )
    if config["endpoint_secret"]:
        if not (webhook_signature and webhook_event_id and webhook_timestamp):
            received_events.append({
                "received_at": time.strftime("%H:%M:%S"),
                "event_id": webhook_event_id or "unknown",
                "delivery_id": webhook_delivery_id or "unknown",
                "returned_status": 401,
                "sig_valid": False,
                "is_duplicate": False,
                "payload": raw_body_str
            })
            return Response(
                content='{"error": "Missing signature headers"}',
                status_code=401,
                media_type="application/json"
            )
        valid, msg = verify_webhook_signature(
            secret=config["endpoint_secret"],
            event_id=webhook_event_id,
            timestamp_str=webhook_timestamp,
            payload=raw_body_str,
            received_signature=webhook_signature,
            tolerance_seconds=300
        )
        sig_valid = valid
        if not valid:
            received_events.append({
                "received_at": time.strftime("%H:%M:%S"),
                "event_id": webhook_event_id or "unknown",
                "delivery_id": webhook_delivery_id or "unknown",
                "returned_status": 401,
                "sig_valid": False,
                "is_duplicate": False,
                "payload": raw_body_str
            })
            return Response(
                content=f'{{"error": "Invalid signature: {msg}"}}',
                status_code=401,
                media_type="application/json"
            )

    # 2. Event ID Deduplication check: return success idempotently if already processed
    if webhook_event_id and webhook_event_id in seen_event_ids:
        received_events.append({
            "received_at": time.strftime("%H:%M:%S"),
            "event_id": webhook_event_id,
            "delivery_id": webhook_delivery_id or "unknown",
            "returned_status": 200,
            "sig_valid": sig_valid,
            "is_duplicate": True,
            "payload": raw_body_str
        })
        return Response(
            content='{"status": "already_processed", "is_duplicate": true}',
            status_code=200,
            media_type="application/json"
        )

    # 3. Simulate configured receiver behavior
    mode = config["mode"]
    returned_status = 200
    response_body = {"status": "success", "event_id": webhook_event_id}
    headers = {}

    if mode == "fail_n":
        if config["current_failures"] < config["fail_count"]:
            config["current_failures"] += 1
            returned_status = config["failure_status_code"]
            response_body = {
                "error": f"Simulated failure {config['current_failures']}/{config['fail_count']}",
                "event_id": webhook_event_id
            }
        else:
            returned_status = 200
            response_body = {"status": "recovered_success", "event_id": webhook_event_id}

    elif mode == "rate_limit":
        returned_status = 429
        headers["Retry-After"] = str(config["rate_limit_delay_sec"])
        response_body = {"error": "Rate limit exceeded. Please back off."}

    elif mode == "slow":
        time.sleep(config["slow_delay_sec"])
        returned_status = 200
        response_body = {"status": "slow_success", "delay": config["slow_delay_sec"]}

    # 4. Atomically persist event ID in deduplication DB only after successful processing
    if 200 <= returned_status < 300 and webhook_event_id:
        _record_processed_event(webhook_event_id)

    # Log to in-memory events list
    received_events.append({
        "received_at": time.strftime("%H:%M:%S"),
        "event_id": webhook_event_id or "unknown",
        "delivery_id": webhook_delivery_id or "unknown",
        "returned_status": returned_status,
        "sig_valid": sig_valid,
        "is_duplicate": False,
        "payload": raw_body_str
    })

    import json as _json
    return Response(
        content=_json.dumps(response_body),
        status_code=returned_status,
        media_type="application/json",
        headers=headers
    )
