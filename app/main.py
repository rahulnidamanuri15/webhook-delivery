import logging
import threading
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, Request
from fastapi.staticfiles import StaticFiles

from app.api.v1 import api_router
from app.config import settings
from app.dashboard.views import router as dashboard_router
from app.db.session import Base, engine, get_db
from app.services import tracing as _tracing  # noqa: F401 - configures OTel provider
from app.services.logging_util import setup_structured_logging
from app.workers.runner import run_dispatcher_loop

setup_structured_logging()
logger = logging.getLogger("webhook.main")

dispatcher_thread = None

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Schema is managed exclusively by Alembic migrations (see compose.yaml).
    # Do NOT call Base.metadata.create_all here — it conflicts with Alembic
    # and can mask migration issues. Run: alembic upgrade head
    logger.info("Database schema managed by Alembic migrations.")

    # 2. In local dev mode, spawn background delivery thread only if explicitly enabled
    global dispatcher_thread
    if settings.ENABLE_INPROCESS_DISPATCHER:
        logger.info("Starting in-process delivery dispatcher thread...")
        dispatcher_thread = threading.Thread(
            target=run_dispatcher_loop,
            kwargs={"poll_interval": 1.0},
            daemon=True
        )
        dispatcher_thread.start()

    yield

    logger.info("Shutting down Webhook Delivery Platform...")

app = FastAPI(
    title=settings.PROJECT_NAME,
    version="0.1.0",
    lifespan=lifespan,
    docs_url="/api/docs",
    redoc_url="/api/redoc"
)


@app.middleware("http")
async def security_headers_middleware(request: Request, call_next):
    """Harden direct :8080 exposure (nginx also sets these when proxied)."""
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    # HTMX + inline dashboard JS need 'unsafe-inline'; no object/embed.
    # CDN scripts (htmx/chart.js) explicitly allowlisted.
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://unpkg.com https://cdn.jsdelivr.net; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "connect-src 'self'; "
        "frame-ancestors 'none'; "
        "object-src 'none'; base-uri 'self'"
    )
    if settings.ENV == "production" and not settings.DEBUG:
        # Only send HSTS when serving TLS via reverse_proxy
        response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains; preload"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    return response

# Mount Static Files
app.mount("/static", StaticFiles(directory="app/static"), name="static")

# Mount Routers
app.include_router(api_router)
app.include_router(dashboard_router)

@app.get("/health", tags=["Health"])
def healthcheck():
    return {
        "status": "ok",
        "env": settings.ENV,
        "version": "0.1.0"
    }

@app.get("/webhook")
def webhook_guide():
    from fastapi.responses import HTMLResponse
    return HTMLResponse(
        """<!DOCTYPE html><html><body style="font-family:sans-serif;padding:40px;max-width:600px;margin:auto;line-height:1.6;">
        <h2 style="color:#1e293b;">Looking for the Webhook Receiver?</h2>
        <p>This is port <strong>8080</strong> (the Webhook Delivery Platform / Sender).</p>
        <p>The <strong>Demo Receiver</strong> is running on port <strong>8001</strong>:</p>
        <p><a href="http://localhost:8001/" style="display:inline-block;padding:10px 16px;background:#2563eb;color:white;text-decoration:none;border-radius:6px;font-weight:500;">
        Open Demo Receiver on Port 8001 &rarr;
        </a></p>
        </body></html>"""
    )

@app.get("/metrics", tags=["Metrics"])
def metrics(request: "Request" = None, db = Depends(get_db)):
    """Prometheus metrics endpoint. Protected by METRICS_API_KEY (Bearer token)
    or a valid dashboard session cookie. Returns 401 if neither is provided."""
    from fastapi import Request as _Req
    from fastapi.responses import PlainTextResponse

    # Check Bearer token first
    auth_header = request.headers.get("authorization", "") if request else ""
    if settings.METRICS_API_KEY:
        if auth_header.startswith("Bearer "):
            token = auth_header[7:].strip()
            import hmac as _hmac
            if _hmac.compare_digest(token, settings.METRICS_API_KEY):
                from app.services.metrics import generate_prometheus_metrics
                metrics_text = generate_prometheus_metrics(db)
                return PlainTextResponse(metrics_text, media_type="text/plain; version=0.0.4; charset=utf-8")
        # Also allow session-authenticated dashboard users
        from app.services.security import verify_session_token
        session_token = request.cookies.get("wh_session") if request else None
        if session_token:
            data = verify_session_token(session_token)
            if data and "user_id" in data:
                from app.services.metrics import generate_prometheus_metrics
                metrics_text = generate_prometheus_metrics(db)
                return PlainTextResponse(metrics_text, media_type="text/plain; version=0.0.4; charset=utf-8")
        from fastapi.responses import JSONResponse
        return JSONResponse(
            status_code=401,
            content={"detail": "Valid METRICS_API_KEY Bearer token or dashboard session required."}
        )
    else:
        # No API key configured: require dashboard session auth
        from app.services.security import verify_session_token
        session_token = request.cookies.get("wh_session") if request else None
        if session_token:
            data = verify_session_token(session_token)
            if data and "user_id" in data:
                from app.services.metrics import generate_prometheus_metrics
                metrics_text = generate_prometheus_metrics(db)
                return PlainTextResponse(metrics_text, media_type="text/plain; version=0.0.4; charset=utf-8")
        from fastapi.responses import JSONResponse
        return JSONResponse(
            status_code=401,
            content={"detail": "Authentication required. Set METRICS_API_KEY or use a dashboard session."}
        )
