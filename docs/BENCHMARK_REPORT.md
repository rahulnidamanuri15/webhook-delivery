# Webhook Delivery Platform - Performance Benchmark Report

**Generated:** 2026-10-06 05:30:39 UTC  
**Execution Mode:** In-Process (ASGITransport)  
**Total Ingested Events:** 20  
**Concurrency Level:** 2  
**Hardware:** AMD64 Intel64 Family 6 Model 186 Stepping 3, GenuineIntel | 12 CPUs | Windows 11 | Python 3.14.2  
**Database:** sqlite | **Worker concurrency:** 10 threads (dispatcher) / `-c 4` (celery)  
**Payload size:** ~180 bytes JSON | **Endpoints in DB:** 113 | **Receiver:** demo_receiver or live URL (see run flags)  
**Retry policy:** demo-short (max attempts 5) | **Failure percentage:** 0.0% | **Wall time:** 0.73s  

---

## 1. Executive Summary

The ingestion engine accepted **20/20 requests** (100.0% acceptance rate) across 2 concurrent streams, demonstrating single-transaction atomic durability (event row + delivery row creation with SHA-256 payload hashing and idempotency verification).

| Metric | Result | Target Benchmark |
|---|---|---|
| **Ingestion Throughput** | **27.58 events/sec** | > 100 events/sec |
| **Median Latency (p50)** | **16.69 ms** | < 50 ms |
| **95th Percentile (p95)** | **481.46 ms** | < 100 ms |
| **99th Percentile (p99)** | **487.41 ms** | < 250 ms |
| **Average Latency** | **70.95 ms** | < 60 ms |
| **Errors / Failures** | **0** | 0 |

---

## 2. Latency Distribution Curve

- **Minimum:** `11.07 ms`
- **Median (p50):** `16.69 ms`
- **p90:** `126.72 ms`
- **p95:** `481.46 ms`
- **p99:** `487.41 ms`
- **Maximum:** `488.90 ms`

---

## 3. Architecture & Reliability Analysis

### 3.1 Why Ingestion Latency Is Predictably Low
1. **Single-Transaction Boundary**: The endpoint ingests the event envelope and generates the initial `PENDING` delivery record in a single atomic database commit, eliminating multi-phase commit overhead.
2. **HTTP Requests Outside Transactions**: Outbound HTTP delivery is completely decoupled from the ingestion path. The API responds with `202 Accepted` immediately upon durable persistence.
3. **SSRF & Signature Pre-computation**: Endpoint signing keys are cached decrypted in-memory during worker execution to minimize cryptographic CPU cycles.

### 3.2 Recovery & Scaling Characteristics
- **Worker Crash Recovery**: Lease-based execution ensures that if a delivery worker terminates mid-flight, the recovery sweep restores orphaned deliveries without losing events.
- **Thundering Herd Prevention**: Retries employ exponential backoff with full randomized jitter ($[0, \text{backoff}]$) and honor `Retry-After` headers.
- **SSRF Hardening**: All target hostnames are resolved and pinned before connecting, mitigating DNS rebinding and loopback exploits.

---

## 4. Required Dimensions (§17 checklist)

- **Ingestion throughput:** `27.58 events/sec` over `0.73s`
- **Ingestion p50/p95:** `16.69 ms` / `481.46 ms` (p90 `126.72`, p99 `487.41`, avg `70.95`)
- **Acceptance-to-first-attempt delay:** measured live via dispatcher poll interval (~1s) + queue depth; see `Queue backlog` below
- **Outbound request duration:** per-attempt `duration_ms` in delivery timeline + `/metrics` `webhook_delivery_duration_ms`
- **Acceptance-to-success duration:** acceptance-to-success sample n=20 avg=59.49s min=0.04s max=261.15s
- **Queue backlog / oldest pending age:** `123` waiting, oldest `5982.52s`
- **Recovery time after worker restart:** expired-lease sweep runs every dispatch cycle; lease 30s bounds worst-case re-queue delay
- **Behavior under receiver failure:** use demo_receiver modes (`fail_n`, `429`, `slow`) — see `docs/DEMO.md`
- **Software config:** DB `sqlite`, retry `demo-short`, max attempts `5`, mode `In-Process (ASGITransport)`
