from sqlalchemy import func
from sqlalchemy.orm import Session

from app.models import Delivery, DeliveryAttempt, Event


def generate_prometheus_metrics(db: Session) -> str:
    """
    Generates standard Prometheus exposition format text metrics for monitoring.
    Exposes event ingestion rates, delivery states, attempt counts, and backlog.
    """
    lines = [
        "# HELP webhook_events_total Total number of webhook events ingested",
        "# TYPE webhook_events_total counter",
    ]

    # Events total
    total_events = db.query(func.count(Event.id)).scalar() or 0
    lines.append(f"webhook_events_total {total_events}")

    # Deliveries by status
    lines.extend(
        ["# HELP webhook_deliveries_total Total deliveries by current status", "# TYPE webhook_deliveries_total gauge"]
    )
    status_counts = db.query(Delivery.status, func.count(Delivery.id)).group_by(Delivery.status).all()
    all_statuses = {"PENDING": 0, "IN_FLIGHT": 0, "SUCCEEDED": 0, "RETRY_SCHEDULED": 0, "DEAD": 0}
    for st, count in status_counts:
        all_statuses[st] = count

    for st, count in all_statuses.items():
        lines.append(f'webhook_deliveries_total{{status="{st}"}} {count}')

    # Attempts by outcome
    lines.extend(
        [
            "# HELP webhook_delivery_attempts_total Total delivery attempts by outcome",
            "# TYPE webhook_delivery_attempts_total counter",
        ]
    )
    outcome_counts = (
        db.query(DeliveryAttempt.outcome, func.count(DeliveryAttempt.id)).group_by(DeliveryAttempt.outcome).all()
    )
    for outcome, count in outcome_counts:
        lines.append(f'webhook_delivery_attempts_total{{outcome="{outcome}"}} {count}')

    # Latency summary
    lines.extend(
        [
            "# HELP webhook_delivery_duration_ms Average delivery attempt turnaround time in milliseconds",
            "# TYPE webhook_delivery_duration_ms gauge",
        ]
    )
    avg_latency = db.query(func.avg(DeliveryAttempt.duration_ms)).scalar() or 0.0
    lines.append(f"webhook_delivery_duration_ms {round(avg_latency, 2)}")

    # Latency histogram (fixed buckets) — computed in SQL to avoid loading
    # all durations into Python (OOM with millions of attempts).
    from sqlalchemy import case as _case

    buckets = [50, 100, 250, 500, 1000, 5000]
    lines.extend(
        [
            "# HELP webhook_delivery_duration_ms_bucket Delivery attempt latency histogram",
            "# TYPE webhook_delivery_duration_ms_bucket histogram",
        ]
    )
    try:
        # Single-row SQL aggregation: count/sum + per-bucket cumulative counts
        agg = db.query(
            func.count(DeliveryAttempt.id).label("cnt"),
            func.coalesce(func.sum(DeliveryAttempt.duration_ms), 0).label("s"),
            *[func.sum(_case((DeliveryAttempt.duration_ms <= b, 1), else_=0)).label(f"le_{b}") for b in buckets],
        ).one()
        _counts = {b: int(getattr(agg, f"le_{b}") or 0) for b in buckets}
        _total = int(agg.cnt or 0)
        _sum = int(agg.s or 0)
    except Exception:
        _counts = {b: 0 for b in buckets}
        _total, _sum = 0, 0
    for bound in buckets:
        lines.append(f'webhook_delivery_duration_ms_bucket{{le="{bound}"}} {_counts[bound]}')
    lines.append(f'webhook_delivery_duration_ms_bucket{{le="+Inf"}} {_total}')
    lines.append(f"webhook_delivery_duration_ms_count {_total}")
    lines.append(f"webhook_delivery_duration_ms_sum {_sum}")

    # Per-endpoint breakdown — bounded to 200 series to avoid cardinality explosion.
    try:
        lines.extend(
            [
                "# HELP webhook_deliveries_by_endpoint Deliveries by endpoint and status",
                "# TYPE webhook_deliveries_by_endpoint gauge",
            ]
        )
        per_ep = (
            db.query(Delivery.endpoint_id, Delivery.status, func.count(Delivery.id))
            .group_by(Delivery.endpoint_id, Delivery.status)
            .limit(200)
            .all()
        )
        import re as _re

        for ep_id, st, count in per_ep:
            # Sanitize label values (IDs are alphanumerics + underscore).
            safe_ep = _re.sub(r"[^A-Za-z0-9_-]", "_", str(ep_id))[:64]
            safe_st = _re.sub(r"[^A-Za-z0-9_]", "_", str(st))[:32]
            lines.append(f'webhook_deliveries_by_endpoint{{endpoint_id="{safe_ep}",status="{safe_st}"}} {count}')
    except Exception:
        pass

    # Queue backlog (due deliveries pending or retry_scheduled)
    lines.extend(
        [
            "# HELP webhook_backlog_total Number of deliveries currently waiting for worker dispatch",
            "# TYPE webhook_backlog_total gauge",
        ]
    )
    backlog = all_statuses["PENDING"] + all_statuses["RETRY_SCHEDULED"]
    lines.append(f"webhook_backlog_total {backlog}")

    return "\n".join(lines) + "\n"
