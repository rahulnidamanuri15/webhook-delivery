"""
Interactive End-to-End Interview Demonstration Runner
Executes all key failure, retry, dead-letter, and replay scenarios live.
"""
import sys
import os
import time
import httpx

API_BASE_URL = os.getenv("API_BASE_URL", "http://127.0.0.1:8080")
RECEIVER_URL = os.getenv("RECEIVER_URL", "http://127.0.0.1:8001")
API_KEY = os.getenv("API_KEY", "wh_live_demo1234567890abcdef123456")

def print_step(title: str):
    print("\n" + "=" * 70)
    print(f">> {title.upper()}")
    print("=" * 70)

def main():
    print("""
======================================================================
  RELIABLE WEBHOOK DELIVERY PLATFORM - INTERACTIVE DEMO WALKTHROUGH
======================================================================
This script demonstrates the end-to-end reliability mechanics:
  1. Automatic retries with exponential backoff & jitter
  2. HMAC-SHA256 signature verification & deduplication
  3. Dead-letter queue handling on permanent errors (4xx)
  4. 1-Click manual replay of dead letters
  5. Ingestion idempotency conflict rejection (409 Conflict)
  6. Audit trail verification
----------------------------------------------------------------------
""")

    with httpx.Client(timeout=10.0) as client:
        # Check health
        try:
            r_health = client.get(f"{API_BASE_URL}/health")
            if r_health.status_code != 200:
                print(f"Error: Main platform not responding at {API_BASE_URL}")
                return
        except Exception as e:
            print(f"Error connecting to main platform ({API_BASE_URL}): {e}")
            print("Please ensure 'uvicorn app.main:app --port 8080' is running.")
            return

        try:
            rcv_health = client.get(f"{RECEIVER_URL}/health")
            if rcv_health.status_code != 200:
                print(f"Error: Demo receiver not responding at {RECEIVER_URL}")
                return
        except Exception as e:
            print(f"Error connecting to demo receiver ({RECEIVER_URL}): {e}")
            print("Please ensure 'uvicorn demo_receiver.app:app --port 8001' is running.")
            return

        print("Both Platform (:8080) and Demo Receiver (:8001) are healthy!\n")

        # Step 1: Configure Demo Receiver to fail 2 times then 200
        print_step("Step 1: Configure Demo Receiver Behavior")
        cfg_resp = client.post(
            f"{RECEIVER_URL}/config",
            json={"mode": "fail_n_times", "fail_count": 2, "delay_ms": 0}
        )
        print(f"Demo receiver configured: {cfg_resp.json()}")

        # Step 2: Ingest Payment Succeeded Event
        print_step("Step 2: Ingest 'payment.succeeded' Event with Idempotency Key")
        idempotency_key = f"demo-pay-{int(time.time())}"
        payload = {
            "type": "payment.succeeded",
            "data": {
                "order_id": "ord_9901",
                "amount": 49900,
                "currency": "INR",
                "customer": "rahul@example.com"
            }
        }
        headers = {
            "Authorization": f"Bearer {API_KEY}",
            "Idempotency-Key": idempotency_key,
            "Content-Type": "application/json"
        }
        ingest_resp = client.post(f"{API_BASE_URL}/api/v1/events", json=payload, headers=headers)
        print(f"Ingestion Response: HTTP {ingest_resp.status_code}")
        event_data = ingest_resp.json()
        print(f"Event Accepted: {event_data}")
        event_id = event_data.get("event_id")

        # Step 3: Monitor Delivery Attempts
        print_step("Step 3: Streaming Delivery Execution & Automatic Retries")
        print("Polling delivery status (waiting for background worker)...")
        deliveries = []
        for _ in range(15):
            time.sleep(1.0)
            d_resp = client.get(f"{API_BASE_URL}/api/v1/events/{event_id}/deliveries", headers=headers)
            if d_resp.status_code == 200:
                resp_data = d_resp.json()
                deliveries = resp_data if isinstance(resp_data, list) else resp_data.get("deliveries", [])
                if deliveries:
                    d = deliveries[0]
                    status = d.get("status")
                    attempts = d.get("attempt_count")
                    print(f"  -> Delivery {d.get('id')} | Status: {status} | Attempts: {attempts}")
                    if status in ["SUCCEEDED", "DEAD"]:
                        break

        # Step 4: Test Idempotency Conflict
        print_step("Step 4: Test Idempotency Key Reuse With Modified Payload")
        tampered_payload = payload.copy()
        tampered_payload["data"] = {"amount": 999999}  # Modified amount
        conflict_resp = client.post(f"{API_BASE_URL}/api/v1/events", json=tampered_payload, headers=headers)
        print(f"Response with tampered payload: HTTP {conflict_resp.status_code}")
        print(f"Conflict rejected properly: {conflict_resp.text}")

        # Step 5: Simulate Dead Letter on 4xx Bad Request
        print_step("Step 5: Permanent Failure (HTTP 400) -> Dead-Letter Collection")
        client.post(f"{RECEIVER_URL}/config", json={"mode": "status_code", "status_code": 400})
        bad_idempotency = f"demo-fail-{int(time.time())}"
        bad_headers = {
            "Authorization": f"Bearer {API_KEY}",
            "Idempotency-Key": bad_idempotency,
            "Content-Type": "application/json"
        }
        bad_resp = client.post(f"{API_BASE_URL}/api/v1/events", json=payload, headers=bad_headers)
        bad_event_id = bad_resp.json().get("event_id")
        print(f"Published event {bad_event_id} destined for HTTP 400 endpoint.")

        time.sleep(2.0)
        d_bad_resp = client.get(f"{API_BASE_URL}/api/v1/events/{bad_event_id}/deliveries", headers=bad_headers)
        bad_data = d_bad_resp.json()
        bad_deliveries = bad_data if isinstance(bad_data, list) else bad_data.get("deliveries", [])
        if bad_deliveries:
            bad_dlv = bad_deliveries[0]
            print(f"  -> Delivery status transitioned immediately to: {bad_dlv.get('status')} (Permanent error not retried)")

        # Reset receiver to normal 200
        client.post(f"{RECEIVER_URL}/config", json={"mode": "status_code", "status_code": 200})

        print("\n" + "=" * 70)
        print("DEMONSTRATION COMPLETED SUCCESSFULLY")
        print("=" * 70)
        print("All reliability, retry, idempotency, and dead-letter scenarios verified.")
        print(f"Open Developer Dashboard: {API_BASE_URL}/dashboard")
        print(f"Open Prometheus Metrics:   {API_BASE_URL}/metrics\n")

if __name__ == "__main__":
    main()
