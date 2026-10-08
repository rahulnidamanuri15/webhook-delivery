import logging
import os
from contextlib import contextmanager
from typing import Any

logger = logging.getLogger("webhook.tracing")

tracer = None
try:
    from opentelemetry import trace
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor

    # Install a real provider only once; export via OTLP when configured,
    # otherwise use console exporter in debug or no-op provider.
    if trace.get_tracer_provider() is None or type(trace.get_tracer_provider()).__name__ == "NoOpTracerProvider":
        otlp_endpoint = os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT", "")
        provider = TracerProvider()
        if otlp_endpoint:
            try:
                from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter

                provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter(endpoint=otlp_endpoint)))
                logger.info("otel_exporter_configured", extra={"endpoint": otlp_endpoint})
            except Exception as e:
                logger.warning(f"OTLP exporter unavailable, using no-export provider: {e}")
        trace.set_tracer_provider(provider)
    tracer = trace.get_tracer("webhook.platform", "0.1.0")
except Exception as e:
    logger.debug(f"OpenTelemetry unavailable, tracing will no-op: {e}")
    tracer = None


@contextmanager
def start_trace_span(name: str, attributes: dict[str, Any] | None = None):
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


def inject_trace_headers(headers: dict[str, str]) -> dict[str, str]:
    """Injects W3C trace-context (traceparent/tracestate) into outbound headers.

    Allows acceptance → dispatch → delivery spans to be correlated with any
    receiver-side tracing. No-op when OpenTelemetry is unavailable.
    """
    try:
        from opentelemetry import propagate

        # propagate.inject mutates the carrier dict in place.
        propagate.inject(headers)
    except Exception as e:
        logger.debug(f"trace propagation inject failed: {e}")
    return headers
