"""Structured JSON logging setup.

Usage:
    from app.services.logging_util import setup_structured_logging
    setup_structured_logging()  # call once at process startup

Emits single-line JSON records: timestamp, level, logger, message + extras.
Falls back to plain logging if JSON serialization fails.
"""

import json
import logging
import sys
from datetime import UTC, datetime


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "timestamp": datetime.now(UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        # Include structured extras passed via logger.info(..., extra={...})
        for key, value in getattr(record, "__dict__", {}).items():
            if key in (
                "args",
                "msg",
                "levelname",
                "levelno",
                "pathname",
                "filename",
                "module",
                "exc_info",
                "exc_text",
                "stack_info",
                "lineno",
                "funcName",
                "created",
                "msecs",
                "relativeCreated",
                "thread",
                "threadName",
                "processName",
                "process",
                "message",
            ):
                continue
            try:
                json.dumps(value)
                payload[key] = value
            except Exception:
                payload[key] = str(value)
        if record.exc_info:
            payload["exc_info"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=False)


_configured = False


def setup_structured_logging(level: int | str | None = None) -> None:
    global _configured
    if _configured:
        return
    # LOG_LEVEL env wins when no explicit level is passed (prod needs WARNING+).
    if level is None:
        try:
            from app.config import settings as _settings

            level = str(getattr(_settings, "LOG_LEVEL", "INFO") or "INFO").upper()
        except Exception:
            level = "INFO"
    if isinstance(level, str):
        level = getattr(logging, level.upper(), logging.INFO)
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter())
    root = logging.getLogger()
    root.handlers = [handler]
    root.setLevel(level)
    # Keep access logs (do not mute entirely); reduce verbosity only.
    # Operators need an access trail — uvicorn.access stays at INFO.
    _configured = True
