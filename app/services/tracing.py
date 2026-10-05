from contextlib import contextmanager
from typing import Dict, Any, Optional
import logging

logger = logging.getLogger("webhook.tracing")

try:
    from opentelemetry import trace
    tracer = trace.get_tracer("webhook.platform", "0.1.0")
except Exception:
    tracer = None

@contextmanager
def start_trace_span(name: str, attributes: Optional[Dict[str, Any]] = None):
    """
    Context manager for distributed tracing across event ingestion, dispatch, and delivery.
    Gracefully no-ops if OpenTelemetry exporter is not configured.
    """
    if tracer:
        with tracer.start_as_current_span(name) as span:
            if attributes:
                for k, v in attributes.items():
                    span.set_attribute(k, str(v))
            yield span
    else:
        yield None
