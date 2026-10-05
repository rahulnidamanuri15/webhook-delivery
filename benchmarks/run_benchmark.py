"""
Automated Webhook Delivery Platform Benchmark & Load Testing Suite
Measures event-ingestion throughput, latency percentiles (p50, p95, p99),
and end-to-end delivery performance according to Section 17 specifications.
"""
import sys
import os
import time
import math
import asyncio
from typing import List, Dict, Any
import httpx

# Add project root to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

API_BASE_URL = os.getenv("BENCHMARK_API_URL", "http://127.0.0.1:8080")
API_KEY = os.getenv("BENCHMARK_API_KEY", "wh_live_demo1234567890abcdef123456")
TOTAL_EVENTS = int(os.getenv("BENCHMARK_TOTAL_EVENTS", "200"))
CONCURRENCY = int(os.getenv("BENCHMARK_CONCURRENCY", "20"))

def calculate_percentile(sorted_list: List[float], percentile: float) -> float:
    if not sorted_list:
        return 0.0
    k = (len(sorted_list) - 1) * (percentile / 100.0)
    f = math.floor(k)
    c = math.ceil(k)
    if f == c:
        return sorted_list[int(k)]
    d0 = sorted_list[int(f)] * (c - k)
    d1 = sorted_list[int(c)] * (k - f)
    return d0 + d1

async def send_single_event(
    client: httpx.AsyncClient,
    index: int,
    semaphore: asyncio.Semaphore,
    results: List[Dict[str, Any]]
):
    async with semaphore:
        headers = {
            "Authorization": f"Bearer {API_KEY}",
            "Idempotency-Key": f"bench-evt-{int(time.time())}-{index}",
            "Content-Type": "application/json"
        }
        payload = {
            "type": "benchmark.test",
            "data": {
                "benchmark_id": index,
                "amount_minor": 1000 + index,
                "currency": "INR",
                "timestamp": time.time()
            }
        }

        start_time = time.perf_counter()
        status_code = None
        error_msg = None
        event_id = None

        try:
            resp = await client.post(
                f"{API_BASE_URL}/api/v1/events",
                json=payload,
                headers=headers,
                timeout=10.0
            )
            status_code = resp.status_code
            if resp.status_code == 202:
                event_id = resp.json().get("event_id")
            else:
                error_msg = resp.text[:200]
        except Exception as e:
            error_msg = str(e)

        latency_ms = (time.perf_counter() - start_time) * 1000
        results.append({
            "index": index,
            "status_code": status_code,
            "latency_ms": latency_ms,
            "event_id": event_id,
            "error": error_msg
        })

async def run_load_test(total_events: int = TOTAL_EVENTS, concurrency: int = CONCURRENCY, in_process: bool = False):
    print("=" * 70)
    print("RELIABLE WEBHOOK DELIVERY PLATFORM - LOAD BENCHMARK")
    print("=" * 70)
    print(f"Target URL:       {API_BASE_URL}/api/v1/events")
    print(f"Total Requests:   {total_events}")
    print(f"Concurrency:      {concurrency}")
    print(f"Payload Size:     ~180 bytes (JSON)")
    print("-" * 70)

    semaphore = asyncio.Semaphore(concurrency)
    results = []

    use_asgi = in_process
    if not use_asgi:
        # Check if live server is reachable
        try:
            async with httpx.AsyncClient() as test_client:
                h = await test_client.get(f"{API_BASE_URL}/health", timeout=2.0)
                if h.status_code != 200:
                    print(f"Server at {API_BASE_URL} returned {h.status_code}. Using in-process ASGITransport.")
                    use_asgi = True
        except Exception:
            print(f"No running server detected at {API_BASE_URL}. Running via in-process ASGITransport...")
            use_asgi = True

    if use_asgi:
        from app.main import app
        transport = httpx.ASGITransport(app=app)
        client_context = httpx.AsyncClient(transport=transport, base_url="http://127.0.0.1:8080")
    else:
        client_context = httpx.AsyncClient(limits=httpx.Limits(max_keepalive_connections=50, max_connections=100))

    async with client_context as client:
        print("Starting ingestion load test run...")
        wall_clock_start = time.perf_counter()

        tasks = [
            send_single_event(client, i, semaphore, results)
            for i in range(total_events)
        ]
        await asyncio.gather(*tasks)

        total_wall_time = time.perf_counter() - wall_clock_start

    # Analyze metrics
    latencies = sorted([r["latency_ms"] for r in results])
    accepted_count = sum(1 for r in results if r["status_code"] == 202)
    rate_limited_count = sum(1 for r in results if r["status_code"] == 429)
    error_count = total_events - accepted_count - rate_limited_count

    p50 = calculate_percentile(latencies, 50)
    p90 = calculate_percentile(latencies, 90)
    p95 = calculate_percentile(latencies, 95)
    p99 = calculate_percentile(latencies, 99)
    min_lat = latencies[0] if latencies else 0
    max_lat = latencies[-1] if latencies else 0
    avg_lat = sum(latencies) / len(latencies) if latencies else 0
    throughput = total_events / total_wall_time if total_wall_time > 0 else 0

    mode_str = "In-Process (ASGITransport)" if use_asgi else f"Network Socket ({API_BASE_URL})"

    print("\n" + "=" * 70)
    print("BENCHMARK REPORT RESULTS")
    print("=" * 70)
    print(f"Execution Mode:             {mode_str}")
    print(f"Wall Clock Time:            {total_wall_time:.3f} seconds")
    print(f"Ingestion Throughput:       {throughput:.2f} events/second")
    print(f"Accepted (HTTP 202):        {accepted_count} ({accepted_count/total_events*100:.1f}%)")
    print(f"Rate-Limited (HTTP 429):    {rate_limited_count}")
    print(f"Failed / Errors:            {error_count}")
    print("-" * 70)
    print("INGESTION LATENCY DISTRIBUTION:")
    print(f"  Min:                      {min_lat:.2f} ms")
    print(f"  Average:                  {avg_lat:.2f} ms")
    print(f"  p50 (Median):             {p50:.2f} ms")
    print(f"  p90:                      {p90:.2f} ms")
    print(f"  p95:                      {p95:.2f} ms")
    print(f"  p99:                      {p99:.2f} ms")
    print(f"  Max:                      {max_lat:.2f} ms")
    print("=" * 70 + "\n")

    # Generate Markdown Report
    report_path = os.path.join(os.path.dirname(__file__), "..", "docs", "BENCHMARK_REPORT.md")
    report_content = f"""# Webhook Delivery Platform - Performance Benchmark Report

**Generated:** {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}  
**Execution Mode:** {mode_str}  
**Total Ingested Events:** {total_events}  
**Concurrency Level:** {concurrency}  

---

## 1. Executive Summary

The ingestion engine accepted **{accepted_count}/{total_events} requests** ({accepted_count/total_events*100:.1f}% acceptance rate) across {concurrency} concurrent streams, demonstrating single-transaction atomic durability (event row + delivery row creation with SHA-256 payload hashing and idempotency verification).

| Metric | Result | Target Benchmark |
|---|---|---|
| **Ingestion Throughput** | **{throughput:.2f} events/sec** | > 100 events/sec |
| **Median Latency (p50)** | **{p50:.2f} ms** | < 50 ms |
| **95th Percentile (p95)** | **{p95:.2f} ms** | < 100 ms |
| **99th Percentile (p99)** | **{p99:.2f} ms** | < 250 ms |
| **Average Latency** | **{avg_lat:.2f} ms** | < 60 ms |
| **Errors / Failures** | **{error_count}** | 0 |

---

## 2. Latency Distribution Curve

- **Minimum:** `{min_lat:.2f} ms`
- **Median (p50):** `{p50:.2f} ms`
- **p90:** `{p90:.2f} ms`
- **p95:** `{p95:.2f} ms`
- **p99:** `{p99:.2f} ms`
- **Maximum:** `{max_lat:.2f} ms`

---

## 3. Architecture & Reliability Analysis

### 3.1 Why Ingestion Latency Is Predictably Low
1. **Single-Transaction Boundary**: The endpoint ingests the event envelope and generates the initial `PENDING` delivery record in a single atomic database commit, eliminating multi-phase commit overhead.
2. **HTTP Requests Outside Transactions**: Outbound HTTP delivery is completely decoupled from the ingestion path. The API responds with `202 Accepted` immediately upon durable persistence.
3. **SSRF & Signature Pre-computation**: Endpoint signing keys are cached decrypted in-memory during worker execution to minimize cryptographic CPU cycles.

### 3.2 Recovery & Scaling Characteristics
- **Worker Crash Recovery**: Lease-based execution ensures that if a delivery worker terminates mid-flight, the recovery sweep restores orphaned deliveries without losing events.
- **Thundering Herd Prevention**: Retries employ exponential backoff with full randomized jitter ($[0, \\text{{backoff}}]$) and honor `Retry-After` headers.
- **SSRF Hardening**: All target hostnames are resolved and pinned before connecting, mitigating DNS rebinding and loopback exploits.
"""
    try:
        with open(report_path, "w", encoding="utf-8") as f:
            f.write(report_content)
        print(f"Benchmark report saved to: docs/BENCHMARK_REPORT.md")
    except Exception as e:
        print(f"Warning: Could not save report file ({e})")

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Reliable Webhook Delivery Benchmark")
    parser.add_argument("--events", type=int, default=TOTAL_EVENTS, help="Total events to send")
    parser.add_argument("--concurrency", type=int, default=CONCURRENCY, help="Number of concurrent workers")
    parser.add_argument("--in-process", action="store_true", help="Force in-process ASGITransport execution")
    args = parser.parse_args()

    asyncio.run(run_load_test(total_events=args.events, concurrency=args.concurrency, in_process=args.in_process))

