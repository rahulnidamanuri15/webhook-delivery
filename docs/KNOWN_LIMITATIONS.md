# Known Limitations & Architecture Trade-offs

Engineering a reliable distributed system requires honest boundaries. This document outlines the intentional design decisions, edge-case trade-offs, and scalability roadmap for the Reliable Webhook Delivery Platform.

---

## 1. Core System Boundaries

### 1.1 At-Least-Once Delivery (Not Exactly-Once)
- **Constraint**: Network partitions and crash failures make exactly-once delivery physically impossible without two-phase commit across administrative boundaries.
- **Scenario**: If a receiving server processes an HTTP POST successfully (HTTP 200), but the TCP connection breaks or the delivery worker crashes before recording the success in the database, the recovery scanner will reschedule the delivery.
- **Requirement**: Receivers **must** implement idempotency by deduplicating against the header `Webhook-Event-Id` within a reasonable time window.

### 1.2 Event Ordering & Concurrency
- **Constraint**: The platform guarantees causal delivery per delivery row, but does **not** guarantee strict global FIFO ordering across multiple events sent in rapid succession.
- **Rationale**: If Event A fails and is scheduled for retry in 30 seconds, Event B to the same endpoint will not be held back by head-of-line blocking unless an explicit sequential queue per endpoint is enabled.

### 1.3 Database Concurrency: SQLite vs PostgreSQL
- **Development (SQLite)**: SQLite serializes all write transactions using file locks. Under high concurrent write benchmarks (>50 concurrent streams), SQLite will report busy lock contention.
- **Production (PostgreSQL)**: PostgreSQL provides row-level locking (`FOR UPDATE SKIP LOCKED`) and MVCC, enabling thousands of concurrent deliveries without table-level serialization bottlenecks.

---

## 2. Scalability Roadmap

### 2.1 Table Partitioning (Events & Deliveries)
As event volume grows into millions of records:
- **Strategy**: Partition the `events`, `deliveries`, and `delivery_attempts` tables by `created_at` (monthly or weekly range partitions).
- **Benefit**: Retains high query performance for recent deliveries while facilitating effortless archiving or dropping of old partitions according to retention policies.

### 2.2 Transactional Outbox & Message Broker
- Current periodic scanner queries due deliveries from the database.
- **Evolution**: Introduce a Transactional Outbox pattern or Change Data Capture (CDC via Debezium/Postgres WAL) streaming directly into Redis/RabbitMQ/Kafka to achieve sub-second dispatch latency under massive backlogs.

### 2.3 Multi-Region Delivery
- For global low latency, deploy worker pools in North America, Europe, and Asia-Pacific.
- Centralize metadata and event ingestion in primary region, routing outbound HTTP workers to regional egress nodes nearest to the merchant destination.
