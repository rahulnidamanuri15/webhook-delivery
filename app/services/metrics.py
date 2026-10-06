import time
from typing import Dict
from sqlalchemy.orm import Session
from sqlalchemy import func
from app.models import Event, Delivery, DeliveryAttempt

def generate_prometheus_metrics(db: Session) -> str:
    """
    Generates standard Prometheus exposition format text metrics for monitoring.
    Exposes event ingestion rates, delivery states, attempt counts, and backlog.
    """
    lines = [
        "# HELP webhook_events_total Total number of webhook events ingested",
        "# TYPE webhook_events_total counter"
    ]

    # Events total
    total_events = db.query(func.count(Event.id)).scalar() or 0
    lines.append(f'webhook_events_total {total_events}')

    # Deliveries by status
    lines.extend([
        "# HELP webhook_deliveries_total Total deliveries by current status",
        "# TYPE webhook_deliveries_total gauge"
    ])
    status_counts = (
        db.query(Delivery.status, func.count(Delivery.id))
        .group_by(Delivery.status)
        .all()
    )
    all_statuses = {"PENDING": 0, "IN_FLIGHT": 0, "SUCCEEDED": 0, "RETRY_SCHEDULED": 0, "DEAD": 0}
    for st, count in status_counts:
        all_statuses[st] = count

    for st, count in all_statuses.items():
        lines.append(f'webhook_deliveries_total{{status="{st}"}} {count}')

    # Attempts by outcome
    lines.extend([
        "# HELP webhook_delivery_attempts_total Total delivery attempts by outcome",
        "# TYPE webhook_delivery_attempts_total counter"
    ])
    outcome_counts = (
        db.query(DeliveryAttempt.outcome, func.count(DeliveryAttempt.id))
        .group_by(DeliveryAttempt.outcome)
        .all()
    )
    for outcome, count in outcome_counts:
        lines.append(f'webhook_delivery_attempts_total{{outcome="{outcome}"}} {count}')

    # Latency summary
    lines.extend([
        "# HELP webhook_delivery_duration_ms Average delivery attempt turnaround time in milliseconds",
        "# TYPE webhook_delivery_duration_ms gauge"
    ])
    avg_latency = db.query(func.avg(DeliveryAttempt.duration_ms)).scalar() or 0.0
    lines.append(f'webhook_delivery_duration_ms {round(avg_latency, 2)}')

    # Latency histogram (fixed buckets) + per-endpoint delivery gauge.
    # Prometheus-native histograms need explicit buckets; we compute them in
    # Python to stay backend-agnostic (SQLite + PostgreSQL).
    try:
        durations = [r[0] for r in db.query(DeliveryAttempt.duration_ms).all()]
    except Exception:
        durations = []
    buckets = [50, 100, 250, 500, 1000, 5000]
    lines.extend([
        "# HELP webhook_delivery_duration_ms_bucket Delivery attempt latency histogram",
        "# TYPE webhook_delivery_duration_ms_bucket histogram",
    ])
    cumulative = 0
    sorted_d = sorted(durations)
    for bound in buckets:
        cumulative = sum(1 for d in sorted_d if d <= bound)
        lines.append(f'webhook_delivery_duration_ms_bucket{{le="{bound}"}} {cumulative}')
    lines.append(f'webhook_delivery_duration_ms_bucket{{le="+Inf"}} {len(sorted_d)}')
    lines.append(f'webhook_delivery_duration_ms_count {len(sorted_d)}')
    lines.append(f'webhook_delivery_duration_ms_sum {sum(sorted_d) if sorted_d else 0}')

    # Per-endpoint breakdown (bounded: endpoints per project are capped).
    try:
        lines.extend([
            "# HELP webhook_deliveries_by_endpoint Deliveries by endpoint and status",
            "# TYPE webhook_deliveries_by_endpoint gauge",
        ])
        per_ep = (
            db.query(Delivery.endpoint_id, Delivery.status, func.count(Delivery.id))
            .group_by(Delivery.endpoint_id, Delivery.status)
            .all()
        )
        for ep_id, st, count in per_ep:
            # Sanitize label value (IDs are whsec-safe alphanumerics).
            lines.append(f'webhook_deliveries_by_endpoint{{endpoint_id="{ep_id}",status="{st}"}} {count}')
    except Exception:
        pass

    # Queue backlog (due deliveries pending or retry_scheduled)
    lines.extend([
        "# HELP webhook_backlog_total Number of deliveries currently waiting for worker dispatch",
        "# TYPE webhook_backlog_total gauge"
    ])
    backlog = all_statuses["PENDING"] + all_statuses["RETRY_SCHEDULED"]
    lines.append(f'webhook_backlog_total {backlog}')

    return "\n".join(lines) + "\n"
