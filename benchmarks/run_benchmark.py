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

async def run_load_test(total_events: int = TOTAL_EVENTS, concurrency: int = CONCURRENCY):
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

    async with httpx.AsyncClient(limits=httpx.Limits(max_keepalive_connections=50, max_connections=100)) as client:
        # Pre-check health
        try:
            h = await client.get(f"{API_BASE_URL}/health", timeout=3.0)
            if h.status_code != 200:
                print(f"ERROR: Platform health check failed with status {h.status_code}")
                return
        except Exception as e:
            print(f"ERROR: Cannot connect to {API_BASE_URL} ({e}). Ensure platform server is running.")
            return

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

    print("\n" + "=" * 70)
    print("BENCHMARK REPORT RESULTS")
    print("=" * 70)
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

if __name__ == "__main__":
    asyncio.run(run_load_test())
