import threading
import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI, Depends
from fastapi.staticfiles import StaticFiles

from app.config import settings
from app.db.session import engine, Base, get_db
from app.api.v1 import api_router
from app.dashboard.views import router as dashboard_router
from app.workers.runner import run_dispatcher_loop, stop_requested
from app.services.logging_util import setup_structured_logging
from app.services import tracing as _tracing  # noqa: F401 - configures OTel provider

setup_structured_logging()
import logging
logger = logging.getLogger("webhook.main")

dispatcher_thread = None

@asynccontextmanager
async def lifespan(app: FastAPI):
    # 1. Initialize Database Schema
    logger.info("Initializing database tables...")
    Base.metadata.create_all(bind=engine)
    logger.info("Database initialized successfully.")

    # 2. In local dev mode, spawn background delivery thread if Celery is not explicitly managing tasks
    global dispatcher_thread
    if settings.DEBUG:
        logger.info("Starting in-process delivery dispatcher thread for development...")
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
        "debug": settings.DEBUG,
        "version": "0.1.0"
    }

@app.get("/metrics", tags=["Metrics"])
def metrics(db = Depends(get_db)):
    from fastapi.responses import PlainTextResponse
    from app.services.metrics import generate_prometheus_metrics
    metrics_text = generate_prometheus_metrics(db)
    return PlainTextResponse(metrics_text, media_type="text/plain; version=0.0.4; charset=utf-8")
