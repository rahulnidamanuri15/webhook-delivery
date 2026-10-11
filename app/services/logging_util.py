"""Structured JSON logging setup.

Usage:
    from app.services.logging_util import setup_structured_logging
    setup_structured_logging()  # call once at process startup

Emits single-line JSON records: timestamp, level, logger, message + extras.
Falls back to plain logging if JSON serialization fails.
"""

import json
import logging
import re
import sys
from contextvars import ContextVar
from datetime import UTC, datetime

# Request correlation (set by middleware per request; empty outside requests).
request_id_var: ContextVar[str] = ContextVar("request_id", default="")
client_ip_var: ContextVar[str] = ContextVar("client_ip", default="")


def set_request_context(request_id: str = "", client_ip: str = "") -> None:
    try:
        if request_id:
            request_id_var.set(request_id)
        if client_ip:
            client_ip_var.set(client_ip)
    except Exception:
        pass


# Keys whose values must never reach a log aggregator (case-insensitive
# substring match on the extra field name).
_SENSITIVE_KEY_PATTERN = re.compile(
    r"password|passwd|secret|token|api[-_ ]?key|authorization|cookie|set-cookie"
    r"|otp|one[-_ ]?time|session|csrf|private[-_ ]?key|signing",
    re.IGNORECASE,
)

# Token shapes that may be embedded in free-text messages/values.
_SENSITIVE_VALUE_PATTERNS = (
    re.compile(r"wh_live_[A-Za-z0-9]+"),
    re.compile(r"whsec_[A-Za-z0-9]+"),
    re.compile(r"Bearer\s+[A-Za-z0-9\-._~+/]+=*", re.IGNORECASE),
)

_REDACTED = "***REDACTED***"


def _scrub_text(text: str) -> str:
    """Replaces embedded credential shapes with a placeholder."""
    for _rx in _SENSITIVE_VALUE_PATTERNS:
        text = _rx.sub(_REDACTED, text)
    return text


def _redact_value(key: str, value):
    """Redacts a structured extra by field name, then scrubs string contents."""
    if _SENSITIVE_KEY_PATTERN.search(key or ""):
        return _REDACTED
    if isinstance(value, str):
        return _scrub_text(value)
    return value


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "timestamp": datetime.now(UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": _scrub_text(record.getMessage()),
        }
        # Request correlation (never fails the log line).
        try:
            _rid = request_id_var.get("")
            if _rid:
                payload["request_id"] = _rid
            _cip = client_ip_var.get("")
            if _cip:
                payload["client_ip"] = _cip
        except Exception:
            pass
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
                payload[key] = _redact_value(key, value)
            except Exception:
                payload[key] = _redact_value(key, str(value))
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
