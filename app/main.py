
import logging
import threading
import uuid
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, Request, Response
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

_IS_PROD = str(settings.ENV or "").strip().lower() == "production"

app = FastAPI(
    title=settings.PROJECT_NAME,
    version="0.1.0",
    lifespan=lifespan,
    # Hide interactive docs in production (fingerprinting + attack surface).
    docs_url=None if _IS_PROD else "/api/docs",
    redoc_url=None if _IS_PROD else "/api/redoc",
)


@app.middleware("http")
async def request_id_middleware(request: Request, call_next):
    req_id = request.headers.get("x-request-id") or uuid.uuid4().hex
    request.state.request_id = req_id
    response = await call_next(request)
    response.headers["X-Request-ID"] = req_id
    return response


@app.middleware("http")
async def security_headers_middleware(request: Request, call_next):
    """Harden direct :8080 exposure (nginx also sets these when proxied)."""
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    # HTMX requires 'unsafe-eval' for dynamic trigger/swap expression evaluation.
    # CDN scripts (htmx/chart.js) explicitly allowlisted.
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://unpkg.com https://cdn.jsdelivr.net; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "connect-src 'self'; "
        "frame-ancestors 'none'; "
        "object-src 'none'; base-uri 'self'"
    )
    if _IS_PROD and not settings.DEBUG:
        # Only send HSTS when serving TLS via reverse_proxy
        response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains; preload"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    return response

@app.get("/favicon.ico", include_in_schema=False)
def favicon():
    return Response(status_code=204)

# Mount Static Files
app.mount("/static", StaticFiles(directory="app/static"), name="static")

# Mount Routers
app.include_router(api_router)
app.include_router(dashboard_router)

# Short-lived cache for /metrics (global text, same for all scrapers).
_metrics_cache: dict = {"text": None, "at": 0.0}
_metrics_lock = threading.Lock()
_METRICS_TTL_SECONDS = 30.0

@app.get("/health", tags=["Health"])
def healthcheck():
    # Liveness: process is up. Never leak ENV/isolation details.
    return {
        "status": "ok",
        "version": "0.1.0",
    }


@app.get("/ready", tags=["Health"])
def readiness():
    """Readiness: DB (+ Redis when Celery) must be reachable.

    Used by orchestrators to gate traffic; /health stays static for liveness.
    """
    from sqlalchemy import text as _text

    checks: dict = {}
    try:
        with engine.connect() as conn:
            conn.execute(_text("SELECT 1"))
        checks["database"] = "ok"
    except Exception as e:
        logger.warning("readiness database check failed: %s", e)
        from fastapi.responses import JSONResponse

        return JSONResponse(status_code=503, content={"status": "not_ready", "database": "error"})
    # Redis is required when Celery dispatch is enabled; best-effort otherwise.
    if settings.USE_CELERY:
        try:
            import redis as _redis

            _r = _redis.from_url(settings.REDIS_URL, socket_connect_timeout=2)
            _r.ping()
            checks["redis"] = "ok"
        except Exception as e:
            logger.warning("readiness redis check failed: %s", e)
            from fastapi.responses import JSONResponse

            return JSONResponse(
                status_code=503, content={"status": "not_ready", "database": "ok", "redis": "error"}
            )
    return {"status": "ready", "version": "0.1.0", **checks}

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
    or a valid dashboard session cookie. Returns 401 if neither is provided.
    Responses are cached for 30s to prevent full-table scrape DoS."""
    import time as _time
    from fastapi.responses import JSONResponse, PlainTextResponse

    def _authorized() -> bool:
        auth_header = request.headers.get("authorization", "") if request else ""
        if settings.METRICS_API_KEY:
            if auth_header.startswith("Bearer "):
                token = auth_header[7:].strip()
                import hmac as _hmac
                if _hmac.compare_digest(token, settings.METRICS_API_KEY):
                    return True
            # In production or when key is set, session must belong to an owner/admin
            from app.services.security import verify_session_token
            session_token = request.cookies.get("wh_session") if request else None
            if session_token:
                data = verify_session_token(session_token)
                if data and "user_id" in data:
                    from app.models import OrganizationMember
                    mem = db.query(OrganizationMember).filter(
                        OrganizationMember.user_id == data["user_id"],
                        OrganizationMember.role.in_(["owner", "admin"])
                    ).first()
                    if mem:
                        return True
            return False
        from app.services.security import verify_session_token as _v
        session_token = request.cookies.get("wh_session") if request else None
        if session_token:
            data = _v(session_token)
            if data and "user_id" in data:
                from app.models import OrganizationMember
                mem = db.query(OrganizationMember).filter(
                    OrganizationMember.user_id == data["user_id"],
                    OrganizationMember.role.in_(["owner", "admin"])
                ).first()
                if mem:
                    return True
        return False

    if not _authorized():
        if settings.METRICS_API_KEY:
            return JSONResponse(
                status_code=401,
                content={"detail": "Valid METRICS_API_KEY Bearer token or dashboard session required."}
            )
        return JSONResponse(
            status_code=401,
            content={"detail": "Authentication required. Set METRICS_API_KEY or use a dashboard session."}
        )

    # Cache global metrics text briefly (same for all authorized scrapers).
    # Lock prevents thundering-herd regeneration on concurrent scrapes.
    with _metrics_lock:
        now = _time.monotonic()
        cached = _metrics_cache.get("text")
        if cached is not None and (now - _metrics_cache.get("at", 0.0)) < _METRICS_TTL_SECONDS:
            return PlainTextResponse(cached, media_type="text/plain; version=0.0.4; charset=utf-8")
        from app.services.metrics import generate_prometheus_metrics
        metrics_text = generate_prometheus_metrics(db)
        _metrics_cache["text"] = metrics_text
        _metrics_cache["at"] = now
        return PlainTextResponse(metrics_text, media_type="text/plain; version=0.0.4; charset=utf-8")
