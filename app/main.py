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
