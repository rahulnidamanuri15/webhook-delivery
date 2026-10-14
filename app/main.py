import logging
import threading
import uuid
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, Request, Response
from fastapi.staticfiles import StaticFiles

from app.api.v1 import api_router
from app.config import settings
from app.dashboard.views import router as dashboard_router
from app.db.session import engine, get_db
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

    # 1. Startup self-test: verify PinnedIPTransport compatibility with httpcore internals
    from app.services.delivery_service import verify_dns_pinning_compatibility

    if not verify_dns_pinning_compatibility():
        err_msg = "CRITICAL: PinnedIPTransport self-test failed: httpcore internals incompatible with DNS pinning."
        logger.error(err_msg)
        if _IS_PROD:
            raise RuntimeError(err_msg)

    # 2. In local dev mode, spawn background delivery thread only if explicitly enabled
    global dispatcher_thread
    if settings.ENABLE_INPROCESS_DISPATCHER:
        logger.info("Starting in-process delivery dispatcher thread...")
        dispatcher_thread = threading.Thread(target=run_dispatcher_loop, kwargs={"poll_interval": 1.0}, daemon=True)
        dispatcher_thread.start()

    yield

    logger.info("Shutting down Webhook Delivery Platform...")


_IS_PROD = False
try:
    from app.config import is_production_env as _is_prod_env

    _IS_PROD = bool(_is_prod_env(settings.ENV))
except Exception:
    _IS_PROD = str(settings.ENV or "").strip().lower() == "production"

app = FastAPI(
    title=settings.PROJECT_NAME,
    version="1.0.0",
    lifespan=lifespan,
    # Hide interactive docs in production (fingerprinting + attack surface).
    docs_url=None if _IS_PROD else "/api/docs",
    redoc_url=None if _IS_PROD else "/api/redoc",
)


_ERROR_TITLES = {
    400: "Bad request",
    401: "Sign-in required",
    403: "Not allowed",
    404: "Not found",
    429: "Slow down",
    413: "Too large",
    500: "Something went wrong",
}


def _error_page(status_code: int, message: str):
    """Standalone branded error page (no dashboard context needed)."""
    from fastapi.responses import HTMLResponse
    from fastapi.templating import Jinja2Templates

    templates = Jinja2Templates(directory="app/templates")
    safe_message = (message or "Something went wrong.").strip()[:500] or "Something went wrong."
    html = templates.get_template("error.html").render(
        code=status_code, title=_ERROR_TITLES.get(status_code, "Error"), message=safe_message
    )
    return HTMLResponse(content=html, status_code=status_code)


from fastapi.exceptions import HTTPException as FastAPIHTTPException
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException


@app.exception_handler(StarletteHTTPException)
@app.exception_handler(FastAPIHTTPException)
@app.exception_handler(RequestValidationError)
async def _http_exception_handler(request: Request, exc: Exception):
    """Branded HTML error pages for human routes; JSON contract kept for APIs."""
    from fastapi.responses import JSONResponse
    from fastapi.responses import RedirectResponse

    # NOTE: registered for both HTTPException classes because Starlette looks
    # handlers up by exception MRO — a single registration can lose to the
    # built-in default. RequestValidationError rides along so dashboard form
    # posts never leak raw JSON/422 payloads.
    if isinstance(exc, RequestValidationError):
        if request.url.path.startswith("/api/"):
            from fastapi.encoders import jsonable_encoder

            return JSONResponse(status_code=422, content={"detail": jsonable_encoder(exc.errors())})
        return _error_page(400, "Something you submitted looks invalid. Please check and try again.")
    status_code = int(getattr(exc, "status_code", 500) or 500)
    detail = str(getattr(exc, "detail", "") or "")
    if request.url.path.startswith("/api/"):
        return JSONResponse(status_code=status_code, content={"detail": detail or "Error"})
    # Unauthenticated dashboard access goes to login instead of an error page.
    if status_code == 401:
        return RedirectResponse(url="/auth/login", status_code=302)
    return _error_page(status_code, detail)


@app.exception_handler(Exception)
async def _unhandled_exception_handler(request: Request, exc: Exception):
    """Last-resort 500s: logged, JSON for APIs, friendly page otherwise."""
    from fastapi.responses import JSONResponse

    logger.error(f"Unhandled error on {request.url.path}: {exc}", exc_info=True)
    if request.url.path.startswith("/api/"):
        return JSONResponse(status_code=500, content={"detail": "Internal server error"})
    return _error_page(500, "Something went wrong. Please try again.")


@app.middleware("http")
async def request_id_middleware(request: Request, call_next):
    raw_req_id = (request.headers.get("x-request-id") or "").strip()
    import re as _re

    if raw_req_id and len(raw_req_id) <= 64 and _re.match(r"^[A-Za-z0-9_-]+$", raw_req_id):
        req_id = raw_req_id
    else:
        req_id = uuid.uuid4().hex
    request.state.request_id = req_id
    try:
        from app.services.logging_util import set_request_context
        from app.services.security import get_client_ip as _get_ip

        try:
            _cip = _get_ip(request)
        except Exception:
            _cip = ""
        set_request_context(req_id, _cip or "")
    except Exception:
        pass
    response = await call_next(request)
    response.headers["X-Request-ID"] = req_id
    return response


@app.middleware("http")
async def request_size_limit_middleware(request: Request, call_next):
    """Enforces body size limit before JSON deserialization or memory exhaustion, including chunked streams."""
    content_length = request.headers.get("content-length")
    # MAX_PAYLOAD_SIZE_BYTES + 64KB margin for headers/JSON envelope
    max_bytes = settings.MAX_PAYLOAD_SIZE_BYTES + 65536
    if content_length:
        try:
            if int(content_length) > max_bytes:
                return Response(
                    content='{"detail":"Payload Too Large: request body exceeds maximum allowed size."}',
                    status_code=413,
                    media_type="application/json",
                )
        except ValueError:
            return Response(
                content='{"detail":"Invalid Content-Length header"}', status_code=400, media_type="application/json"
            )
    else:
        # Wrap receive channel to protect against chunked / streaming bodies exceeding max_bytes
        bytes_received = 0
        original_receive = request._receive

        async def limited_receive():
            nonlocal bytes_received
            msg = await original_receive()
            if msg.get("type") == "http.request":
                body = msg.get("body", b"")
                bytes_received += len(body)
                if bytes_received > max_bytes:
                    from fastapi import HTTPException

                    raise HTTPException(
                        status_code=413,
                        detail="Payload Too Large: request body exceeds maximum allowed size.",
                    )
            return msg

        request._receive = limited_receive

    try:
        return await call_next(request)
    except Exception as exc:
        from fastapi import HTTPException

        if isinstance(exc, HTTPException) and exc.status_code == 413:
            return Response(
                content='{"detail":"Payload Too Large: request body exceeds maximum allowed size."}',
                status_code=413,
                media_type="application/json",
            )
        raise


@app.middleware("http")
async def client_ip_middleware(request: Request, call_next):
    from app.services.security import get_client_ip

    request.state.client_ip = get_client_ip(request)
    return await call_next(request)


@app.middleware("http")
async def security_headers_middleware(request: Request, call_next):
    """Harden direct :8080 exposure (nginx also sets these when proxied)."""
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    # HTMX requires 'unsafe-eval' for dynamic trigger/swap expression evaluation.
    # Static assets and fonts loaded from local self or Google Fonts.
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' 'unsafe-eval'; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; "
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


@app.get("/live", tags=["Health"])
@app.get("/health", tags=["Health"])
def healthcheck():
    """Liveness probe: verifies process is alive."""
    return {
        "status": "ok",
        "version": "1.0.0",
    }


@app.get("/ready", tags=["Health"])
def readiness():
    """Readiness probe: DB (+ Redis when Celery) must be reachable and schema current."""
    from sqlalchemy import text as _text
    from fastapi.responses import JSONResponse

    checks: dict = {}
    try:
        with engine.connect() as conn:
            conn.execute(_text("SELECT 1"))
            # Verify migrations have run: alembic_version must exist. A partially
            # migrated schema passes SELECT 1 but fails at runtime (e.g. missing
            # uq_active_replay_per_delivery). Fail readiness until migrated.
            try:
                conn.execute(_text("SELECT version_num FROM alembic_version LIMIT 1"))
                checks["schema"] = "ok"
            except Exception as se:
                logger.warning("readiness schema version check failed: %s", se)
                return JSONResponse(
                    status_code=503, content={"status": "not_ready", "database": "ok", "schema": "migrating"}
                )
        checks["database"] = "ok"
    except Exception as e:
        logger.warning("readiness database check failed: %s", e)
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
            return JSONResponse(status_code=503, content={"status": "not_ready", "database": "ok", "redis": "error"})
    return {"status": "ready", "version": "1.0.0", **checks}


@app.get("/startup", tags=["Health"])
def startup_probe():
    """Startup probe: verifies database schema tables exist and migrations are current."""
    from sqlalchemy import text as _text
    from fastapi.responses import JSONResponse

    try:
        with engine.connect() as conn:
            conn.execute(_text("SELECT 1 FROM events LIMIT 1"))
            try:
                conn.execute(_text("SELECT version_num FROM alembic_version LIMIT 1"))
            except Exception as se:
                logger.warning("startup schema version check failed: %s", se)
                return JSONResponse(status_code=503, content={"status": "starting", "schema": "migrating"})
        return {"status": "started", "version": "1.0.0"}
    except Exception as e:
        logger.warning("startup check failed: %s", e)
        return JSONResponse(status_code=503, content={"status": "starting", "database": "not_ready"})


@app.get("/metrics", tags=["Metrics"])
def metrics(request: "Request" = None, db=Depends(get_db)):
    """Prometheus metrics endpoint. Protected by METRICS_API_KEY (Bearer token)
    or owner/admin session cookie in non-prod. In production, dedicated METRICS_API_KEY
    Bearer token is strictly required. Responses are cached for 30s to prevent DoS."""
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
            # In production, require dedicated METRICS_API_KEY token exclusively
            if _IS_PROD:
                return False
            # In non-production, allow owner/admin dashboard session as fallback
            from app.services.security import verify_session_token

            session_token = request.cookies.get("wh_session") if request else None
            if session_token:
                data = verify_session_token(session_token)
                if data and "user_id" in data:
                    from app.models import OrganizationMember

                    mem = (
                        db.query(OrganizationMember)
                        .filter(
                            OrganizationMember.user_id == data["user_id"],
                            OrganizationMember.role.in_(["owner", "admin"]),
                        )
                        .first()
                    )
                    if mem:
                        return True
            return False

        # NOTE: reachable only when METRICS_API_KEY is empty (dev/test).
        # Prod validator requires >=16 chars, so this branch never runs in prod.
        if _IS_PROD:
            return False

        from app.services.security import verify_session_token as _v

        session_token = request.cookies.get("wh_session") if request else None
        if session_token:
            data = _v(session_token)
            if data and "user_id" in data:
                from app.models import OrganizationMember

                mem = (
                    db.query(OrganizationMember)
                    .filter(
                        OrganizationMember.user_id == data["user_id"], OrganizationMember.role.in_(["owner", "admin"])
                    )
                    .first()
                )
                if mem:
                    return True
        return False

    if not _authorized():
        return JSONResponse(
            status_code=401,
            content={"detail": "Unauthorized: Valid METRICS_API_KEY Bearer token required for /metrics."},
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
