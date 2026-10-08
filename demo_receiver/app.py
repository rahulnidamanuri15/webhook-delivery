import asyncio as _asyncio
import html
import json as _json
import os
import sqlite3
import time
from typing import Any

from fastapi import FastAPI, Form, Header, HTTPException, Request, Response
from fastapi.responses import HTMLResponse, RedirectResponse

from app.services.signing import verify_webhook_signature

app = FastAPI(title="Controllable Webhook Demo Receiver")

ADMIN_TOKEN = os.getenv("DEMO_RECEIVER_ADMIN_TOKEN", "")

# Default shared secret seeded by platform for demo receiver
DEFAULT_ENDPOINT_SECRET = os.getenv("DEMO_RECEIVER_ENDPOINT_SECRET", "whsec_demosecret1234567890abcdef")

# Ensure SQLite DB file lives in demo_receiver directory for persistence across reloads/restarts
_DEFAULT_DB_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "demo_receiver.db")
_DEDUP_DB_FILE = os.getenv("DEMO_RECEIVER_DB_FILE", _DEFAULT_DB_FILE)


def _is_loopback(request: Request) -> bool:
    """Checks if request originates from localhost/loopback."""
    client_host = ""
    try:
        client_host = request.client.host if request.client else ""
    except Exception:
        client_host = ""
    return client_host in ("127.0.0.1", "::1", "localhost", "testclient", "")


def _check_admin(request: Request, token_field: str | None = None) -> bool:
    """Returns True if caller is authorized as admin (via loopback or matching token)."""
    is_loopback = _is_loopback(request)
    if not ADMIN_TOKEN:
        return is_loopback

    provided = (
        (token_field or "").strip()
        or request.headers.get("x-admin-token", "").strip()
        or request.cookies.get("demo_admin_token", "").strip()
    )
    if not provided:
        try:
            provided = (request.query_params.get("admin_token", "") or "").strip()
        except Exception:
            provided = ""

    if provided:
        import hmac as _hmac
        if _hmac.compare_digest(provided, ADMIN_TOKEN):
            return True

    return False


def _require_admin(request: Request, token_field: str | None = None):
    """Protects behaviour-changing controls and sensitive dashboard views.

    - Only allow loopback callers without token if DEMO_RECEIVER_ADMIN_TOKEN is empty.
    - If DEMO_RECEIVER_ADMIN_TOKEN is set: require matching token via X-Admin-Token
      header, form field admin_token, cookie demo_admin_token, or query param admin_token.
    """
    if _check_admin(request, token_field):
        return

    if not ADMIN_TOKEN:
        raise HTTPException(
            status_code=403,
            detail="Admin token is not configured on demo receiver. Remote non-loopback access is forbidden."
        )

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
    "endpoint_secret": DEFAULT_ENDPOINT_SECRET,  # Pre-populated with default demo secret
    "enforce_signatures": False, # When True, reject webhooks if signature verification fails
}

received_events: list[dict[str, Any]] = []
seen_event_ids: set = set()


def _init_db() -> None:
    """Initializes SQLite tables and loads recent deliveries into memory."""
    try:
        os.makedirs(os.path.dirname(os.path.abspath(_DEDUP_DB_FILE)), exist_ok=True)
        with sqlite3.connect(_DEDUP_DB_FILE, timeout=10.0) as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("""
                CREATE TABLE IF NOT EXISTS processed_events (
                    event_id TEXT PRIMARY KEY,
                    processed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS received_webhooks (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    received_at TEXT NOT NULL,
                    event_id TEXT,
                    delivery_id TEXT,
                    returned_status INTEGER NOT NULL,
                    sig_valid INTEGER,
                    is_duplicate INTEGER DEFAULT 0,
                    payload TEXT
                )
            """)
            conn.commit()

            # Restore deduplicated event IDs
            seen_event_ids.clear()
            rows = conn.execute("SELECT event_id FROM processed_events").fetchall()
            for r in rows:
                seen_event_ids.add(r[0])

            # Restore recent received events (last 50)
            webhook_rows = conn.execute("""
                SELECT received_at, event_id, delivery_id, returned_status, sig_valid, is_duplicate, payload
                FROM received_webhooks
                ORDER BY id DESC LIMIT 50
            """).fetchall()
            received_events.clear()
            for r in reversed(webhook_rows):
                received_events.append({
                    "received_at": r[0],
                    "event_id": r[1],
                    "delivery_id": r[2],
                    "returned_status": r[3],
                    "sig_valid": True if r[4] == 1 else (False if r[4] == 0 else None),
                    "is_duplicate": bool(r[5]),
                    "payload": r[6],
                })
    except Exception as e:
        print(f"Warning: could not initialize demo receiver SQLite db: {e}")


def _record_processed_event(event_id: str) -> bool:
    """Atomically records event_id in SQLite transaction."""
    seen_event_ids.add(event_id)
    try:
        with sqlite3.connect(_DEDUP_DB_FILE, timeout=10.0) as conn:
            conn.execute("INSERT OR IGNORE INTO processed_events (event_id) VALUES (?)", (event_id,))
            conn.commit()
            return True
    except Exception:
        return False


def _persist_webhook_delivery(item: dict[str, Any]) -> None:
    """Persists a received webhook delivery to SQLite and memory."""
    received_events.append(item)
    try:
        with sqlite3.connect(_DEDUP_DB_FILE, timeout=10.0) as conn:
            sig_val = 1 if item["sig_valid"] is True else (0 if item["sig_valid"] is False else None)
            conn.execute("""
                INSERT INTO received_webhooks (received_at, event_id, delivery_id, returned_status, sig_valid, is_duplicate, payload)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                item["received_at"],
                item["event_id"],
                item["delivery_id"],
                item["returned_status"],
                sig_val,
                1 if item["is_duplicate"] else 0,
                item["payload"]
            ))
            conn.commit()
    except Exception as e:
        print(f"Warning: could not persist received webhook to SQLite: {e}")


def _clear_all_history() -> None:
    """Clears in-memory logs and SQLite database."""
    seen_event_ids.clear()
    received_events.clear()
    try:
        with sqlite3.connect(_DEDUP_DB_FILE, timeout=10.0) as conn:
            conn.execute("DELETE FROM processed_events")
            conn.execute("DELETE FROM received_webhooks")
            conn.commit()
    except Exception:
        pass


_init_db()


@app.get("/dashboard")
def dashboard_redirect():
    """Redirect /dashboard to the main receiver control panel."""
    return RedirectResponse(url="/", status_code=303)


@app.post("/auth")
def auth(admin_token: str = Form("")):
    import hmac as _hmac
    if ADMIN_TOKEN and _hmac.compare_digest(admin_token.strip(), ADMIN_TOKEN):
        response = RedirectResponse(url="/", status_code=303)
        response.set_cookie(key="demo_admin_token", value=admin_token.strip(), httponly=True, samesite="lax")
        return response
    raise HTTPException(status_code=403, detail="Invalid admin token.")


@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    """Receiver Dashboard & Control Panel."""
    # If admin_token passed in query param, authenticate and redirect to strip token from URL
    token_param = (request.query_params.get("admin_token") or "").strip()
    if token_param and ADMIN_TOKEN:
        import hmac as _hmac
        if _hmac.compare_digest(token_param, ADMIN_TOKEN):
            resp = RedirectResponse(url="/", status_code=303)
            resp.set_cookie(key="demo_admin_token", value=token_param, httponly=True, samesite="lax")
            return resp

    if not _check_admin(request):
        if not ADMIN_TOKEN:
            return HTMLResponse(
                """<!DOCTYPE html><html><body style="font-family:-apple-system,BlinkMacSystemFont,sans-serif;padding:40px;text-align:center;color:#1f2937;">
                <h2 style="color:#dc2626;">403 Forbidden</h2>
                <p>The demo receiver is running in loopback-only mode because <code>DEMO_RECEIVER_ADMIN_TOKEN</code> is not configured.</p>
                <p style="color:#6b7280;font-size:14px;">Remote access is blocked to prevent exposing webhook secrets and payloads.</p>
                </body></html>""",
                status_code=403
            )
        return HTMLResponse(
            """<!DOCTYPE html><html><head><title>Demo Receiver - Unlock</title></head>
            <body style="font-family:-apple-system,BlinkMacSystemFont,sans-serif;padding:60px 20px;background:#f9fafb;display:flex;justify-content:center;">
            <div style="background:white;padding:32px;border-radius:8px;border:1px solid #e5e7eb;max-width:400px;width:100%;box-shadow:0 1px 3px rgba(0,0,0,0.1);">
                <h2 style="margin-top:0;font-size:18px;">Demo Webhook Receiver</h2>
                <p style="color:#6b7280;font-size:13px;margin-bottom:20px;">This receiver is protected. Please enter the <code>DEMO_RECEIVER_ADMIN_TOKEN</code> to access the dashboard:</p>
                <form action="/auth" method="post">
                    <input type="password" name="admin_token" placeholder="Admin token" required style="width:100%;box-sizing:border-box;padding:8px 12px;border:1px solid #d1d5db;border-radius:6px;font-size:14px;margin-bottom:16px;">
                    <button type="submit" style="width:100%;padding:10px;background:#2563eb;color:white;border:none;border-radius:6px;font-weight:600;font-size:14px;cursor:pointer;">Unlock Dashboard</button>
                </form>
            </div>
            </body></html>""",
            status_code=403
        )

    # Reload from DB in case another process/thread recorded events
    try:
        with sqlite3.connect(_DEDUP_DB_FILE, timeout=2.0) as conn:
            webhook_rows = conn.execute("""
                SELECT received_at, event_id, delivery_id, returned_status, sig_valid, is_duplicate, payload
                FROM received_webhooks
                ORDER BY id DESC LIMIT 50
            """).fetchall()
            received_events.clear()
            for r in reversed(webhook_rows):
                received_events.append({
                    "received_at": r[0],
                    "event_id": r[1],
                    "delivery_id": r[2],
                    "returned_status": r[3],
                    "sig_valid": True if r[4] == 1 else (False if r[4] == 0 else None),
                    "is_duplicate": bool(r[5]),
                    "payload": r[6],
                })
    except Exception:
        pass

    rows = ""
    for item in reversed(received_events[-30:]):
        sig_badge = (
            '<span style="background:#dcfce7;color:#166534;padding:2px 8px;border-radius:9999px;font-size:12px;font-weight:600;">Valid</span>'
            if item["sig_valid"] is True
            else '<span style="background:#fee2e2;color:#991b1b;padding:2px 8px;border-radius:9999px;font-size:12px;font-weight:600;">Invalid</span>'
            if item["sig_valid"] is False
            else '<span style="background:#f3f4f6;color:#374151;padding:2px 8px;border-radius:9999px;font-size:12px;">Unverified</span>'
        )
        dedup_badge = (
            '<span style="background:#fef3c7;color:#92400e;padding:2px 8px;border-radius:9999px;font-size:12px;font-weight:600;">Duplicate</span>'
            if item["is_duplicate"]
            else '<span style="background:#e0e7ff;color:#3730a3;padding:2px 8px;border-radius:9999px;font-size:12px;font-weight:600;">First seen</span>'
        )
        status_color = "#16a34a" if int(item.get("returned_status") or 0) < 300 else "#dc2626"
        escaped_payload = html.escape(str(item.get("payload", ""))[:4000])
        esc_received_at = html.escape(str(item.get("received_at", "")))
        esc_event_id = html.escape(str(item.get("event_id", "")))
        esc_delivery_id = html.escape(str(item.get("delivery_id", "")))
        esc_status = html.escape(str(item.get("returned_status", "")))
        rows += f"""
        <tr style="border-bottom: 1px solid #e5e7eb;">
            <td style="padding:10px;font-family:monospace;font-size:12px;">{esc_received_at}</td>
            <td style="padding:10px;font-family:monospace;font-size:12px;font-weight:600;">{esc_event_id}</td>
            <td style="padding:10px;font-family:monospace;font-size:12px;color:#6b7280;">{esc_delivery_id}</td>
            <td style="padding:10px;font-weight:bold;color:{status_color};">{esc_status}</td>
            <td style="padding:10px;">{sig_badge}</td>
            <td style="padding:10px;">{dedup_badge}</td>
            <td style="padding:10px;"><pre style="margin:0;font-size:11px;max-width:350px;overflow:hidden;text-overflow:ellipsis;white-space:pre-wrap;word-break:break-all;">{escaped_payload}</pre></td>
        </tr>
        """

    if not rows:
        rows = '<tr><td colspan="7" style="padding:30px;text-align:center;color:#6b7280;">No webhooks received yet. Send an event from your platform to <code>http://127.0.0.1:8001/webhook</code></td></tr>'

    enforce_checked = "checked" if config["enforce_signatures"] else ""
    # Escape admin-controlled values to prevent self-XSS via f-string HTML
    _esc_mode = html.escape(str(config.get("mode", "")), quote=True)
    _esc_secret = html.escape(str(config.get("endpoint_secret") or "None"), quote=True)
    _esc_secret_attr = html.escape(str(config.get("endpoint_secret") or ""), quote=True)
    _esc_fail = int(config.get("fail_count", 0) or 0)
    _esc_cur_fail = int(config.get("current_failures", 0) or 0)

    return f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Demo Webhook Receiver</title>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <style>
            body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #f9fafb; margin: 0; padding: 24px; color: #111827; }}
            .card {{ background: white; border-radius: 8px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); padding: 20px; margin-bottom: 24px; border: 1px solid #e5e7eb; }}
            .btn {{ background: #2563eb; color: white; border: none; padding: 8px 16px; border-radius: 6px; cursor: pointer; font-weight: 500; font-size: 13px; }}
            .btn:hover {{ background: #1d4ed8; }}
            .btn-danger {{ background: #dc2626; }}
            .btn-danger:hover {{ background: #b91c1c; }}
            input, select {{ padding: 8px 12px; border: 1px solid #d1d5db; border-radius: 6px; font-size: 13px; }}
            table {{ width: 100%; border-collapse: collapse; text-align: left; }}
            th {{ background: #f3f4f6; padding: 10px; font-size: 12px; text-transform: uppercase; color: #4b5563; font-weight: 600; letter-spacing: 0.05em; }}
            .pulse-dot {{ width: 8px; height: 8px; background: #22c55e; border-radius: 50%; display: inline-block; animation: pulse 2s infinite; }}
            @keyframes pulse {{ 0% {{ opacity: 1; }} 50% {{ opacity: 0.3; }} 100% {{ opacity: 1; }} }}
        </style>
        <script>
            // Poll for fresh deliveries every 3 seconds without full page reload jumps
            let autoRefresh = true;
            setInterval(async () => {{
                if (!autoRefresh) return;
                try {{
                    const res = await fetch(window.location.href);
                    if (res.ok) {{
                        const html = await res.text();
                        const parser = new DOMParser();
                        const doc = parser.parseFromString(html, 'text/html');
                        const newTbody = doc.querySelector('tbody');
                        const currentTbody = document.querySelector('tbody');
                        if (newTbody && currentTbody && newTbody.innerHTML !== currentTbody.innerHTML) {{
                            currentTbody.innerHTML = newTbody.innerHTML;
                            const countEl = document.getElementById('delivery-count');
                            const newCountEl = doc.getElementById('delivery-count');
                            if (countEl && newCountEl) countEl.innerText = newCountEl.innerText;
                        }}
                    }}
                }} catch (e) {{}}
            }}, 3000);
        </script>
    </head>
    <body>
        <div style="max-width: 1100px; margin: 0 auto;">
            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom: 20px;">
                <div>
                    <h1 style="margin:0; font-size: 24px; display:flex; align-items:center; gap:8px;">
                        <span>Controllable Webhook Receiver</span>
                        <span class="pulse-dot" title="Listening for incoming webhooks"></span>
                    </h1>
                    <p style="margin:4px 0 0 0; color: #6b7280; font-size: 14px;">
                        Listening on <code>http://127.0.0.1:8001/webhook</code> | Platform: <a href="http://127.0.0.1:8080/dashboard" target="_blank" style="color:#2563eb; text-decoration:none;">WebhookHub Dashboard (8080) &rarr;</a>
                    </p>
                </div>
                <form action="/clear" method="post" style="display:flex; gap:8px;">
                    <input type="password" name="admin_token" placeholder="Admin token (if configured)" style="padding:6px 10px; border-radius:6px; border:1px solid #d1d5db;">
                    <button class="btn btn-danger" type="submit">Clear Logs</button>
                </form>
            </div>

            <div class="card">
                <h3 style="margin-top:0; font-size: 16px; margin-bottom: 14px;">Behavior Simulator & Signature Settings</h3>
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
                        <label style="display:block; font-size:13px; font-weight:500; margin-bottom:4px;">Endpoint Signing Secret</label>
                        <input type="text" name="endpoint_secret" value="{_esc_secret_attr}" placeholder="whsec_..." style="width:90%; font-family:monospace; font-size:12px;">
                    </div>

                    <div style="grid-column: 1 / -1; display:flex; flex-wrap:wrap; justify-content:space-between; align-items:center; gap:12px; margin-top:4px;">
                        <label style="display:flex; align-items:center; gap:8px; font-size:13px; cursor:pointer;">
                            <input type="checkbox" name="enforce_signatures" value="true" {enforce_checked}>
                            <span><strong>Enforce Signatures:</strong> Reject requests with HTTP 401 if HMAC signature is missing or invalid</span>
                        </label>
                        <button class="btn" type="submit" style="min-width:140px;">Update Behavior</button>
                    </div>
                </form>
                <div style="margin-top:12px; font-size:12px; color:#4b5563; border-top:1px solid #f3f4f6; padding-top:8px;">
                    Current Mode: <strong style="color:#111827;">{_esc_mode}</strong> | Failures in sequence: <strong style="color:#111827;">{_esc_cur_fail}/{_esc_fail}</strong> | Active Secret: <code style="background:#f3f4f6; padding:2px 6px; border-radius:4px;">{_esc_secret}</code> | Enforce Signatures: <strong style="color:{'#166534' if config['enforce_signatures'] else '#6b7280'}">{'ON' if config['enforce_signatures'] else 'OFF'}</strong>
                </div>
            </div>

            <div class="card">
                <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:12px;">
                    <h3 style="margin:0; font-size: 16px;">Received Webhook Deliveries (<span id="delivery-count">{len(received_events)}</span>)</h3>
                    <div style="display:flex; gap:12px; align-items:center;">
                        <span style="font-size:12px; color:#10b981;">&bull; Auto-refreshing every 3s</span>
                        <a href="/" style="font-size:13px; color:#2563eb; text-decoration:none; font-weight:500;">Refresh now</a>
                    </div>
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
    if not isinstance(data, dict):
        raise HTTPException(status_code=400, detail="Request body must be a JSON object.")
    _require_admin(request, str(data.get("admin_token", "")))
    if "mode" in data:
        mode_val = str(data["mode"]).strip()
        if mode_val not in ("success", "fail_n", "rate_limit", "slow", "status_code"):
            raise HTTPException(status_code=400, detail="Invalid mode.")
        if mode_val == "status_code":
            sc = int(data.get("status_code", 200))
            if not (100 <= sc <= 599):
                raise HTTPException(status_code=400, detail="Invalid status code.")
            if sc < 300:
                config["mode"] = "success"
            else:
                config["mode"] = "fail_n"
                config["fail_count"] = 9999
                config["failure_status_code"] = sc
        else:
            config["mode"] = mode_val
    if "fail_count" in data:
        config["fail_count"] = max(1, int(data["fail_count"]))
    if "failure_status_code" in data:
        fsc = int(data["failure_status_code"])
        if not (100 <= fsc <= 599):
            raise HTTPException(status_code=400, detail="Invalid failure_status_code.")
        config["failure_status_code"] = fsc
    elif "status_code" in data and int(data["status_code"]) >= 300:
        sc = int(data["status_code"])
        if not (100 <= sc <= 599):
            raise HTTPException(status_code=400, detail="Invalid status_code.")
        config["failure_status_code"] = sc
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
    enforce_signatures: bool = Form(False),
    admin_token: str = Form(""),
):
    _require_admin(request, admin_token)
    mode_clean = mode.strip()
    if mode_clean not in ("success", "fail_n", "rate_limit", "slow"):
        raise HTTPException(status_code=400, detail="Invalid mode.")
    if not (100 <= failure_status_code <= 599):
        raise HTTPException(status_code=400, detail="Invalid failure_status_code.")
    config["mode"] = mode_clean
    config["fail_count"] = max(1, fail_count)
    config["failure_status_code"] = failure_status_code
    config["endpoint_secret"] = endpoint_secret.strip()
    config["enforce_signatures"] = bool(enforce_signatures)
    config["current_failures"] = 0  # reset sequence
    return RedirectResponse(url="/", status_code=303)


@app.post("/clear")
def clear(request: Request, admin_token: str = Form("")):
    _require_admin(request, admin_token)
    _clear_all_history()
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
    raw_body_str = raw_body_bytes.decode("utf-8", errors="replace")
    now_str = time.strftime("%H:%M:%S")

    # 1. Signature Verification
    sig_valid = None
    if config["endpoint_secret"]:
        if not (webhook_signature and webhook_event_id and webhook_timestamp):
            sig_valid = False
            if config["enforce_signatures"]:
                _persist_webhook_delivery({
                    "received_at": now_str,
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
        else:
            valid, msg = verify_webhook_signature(
                secret=config["endpoint_secret"],
                event_id=webhook_event_id,
                timestamp_str=webhook_timestamp,
                payload=raw_body_str,
                received_signature=webhook_signature,
                tolerance_seconds=300
            )
            sig_valid = valid
            if not valid and config["enforce_signatures"]:
                _persist_webhook_delivery({
                    "received_at": now_str,
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
    elif config["enforce_signatures"]:
        # Enforce signatures requested, but no secret configured on receiver
        _persist_webhook_delivery({
            "received_at": now_str,
            "event_id": webhook_event_id or "unknown",
            "delivery_id": webhook_delivery_id or "unknown",
            "returned_status": 401,
            "sig_valid": None,
            "is_duplicate": False,
            "payload": raw_body_str
        })
        return Response(
            content='{"error": "Signature enforcement enabled but no endpoint_secret configured. Set a secret via POST /configure."}',
            status_code=401,
            media_type="application/json"
        )

    # 2. Event ID Deduplication check: return success idempotently if already processed
    if webhook_event_id and webhook_event_id in seen_event_ids:
        _persist_webhook_delivery({
            "received_at": now_str,
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
        # Non-blocking delay (was time.sleep which blocked the event loop)
        await _asyncio.sleep(min(float(config["slow_delay_sec"]), 15.0))
        returned_status = 200
        response_body = {"status": "slow_success", "delay": config["slow_delay_sec"]}

    # 4. Atomically persist event ID in deduplication DB only after successful processing
    if 200 <= returned_status < 300 and webhook_event_id:
        _record_processed_event(webhook_event_id)

    # 5. Persist delivery in SQLite and memory
    _persist_webhook_delivery({
        "received_at": now_str,
        "event_id": webhook_event_id or "unknown",
        "delivery_id": webhook_delivery_id or "unknown",
        "returned_status": returned_status,
        "sig_valid": sig_valid,
        "is_duplicate": False,
        "payload": raw_body_str
    })

    return Response(
        content=_json.dumps(response_body),
        status_code=returned_status,
        media_type="application/json",
        headers=headers
    )
