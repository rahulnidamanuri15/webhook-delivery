# Spec §15 scenario → test mapping

Spec requires real PostgreSQL for locking/concurrency. CI sets
`DATABASE_URL=postgresql+...` so `test_api_v1` + `test_scenario_coverage` +
`integration/` run against PG; local defaults to SQLite.

| # | Spec §15 scenario | Test |
|---|---|---|
| 1 | Receiver 200 → SUCCEEDED | `test_delivery_engine.py::test_successful_delivery`, `unit` signing |
| 2 | Fail then recover → retry → success | `demo_receiver` fail_n + `test_delivery_engine::test_retryable_error…`, `e2e` manual |
| 3 | Never recovers → DEAD | `test_delivery_engine::test_exhausted_retry_budget…` |
| 4 | Process-then-drop → duplicate, dedup | `demo_receiver/app.py` durable `seen_event_ids` + `test_reliability_fixes::test_prefix…` |
| 5 | Worker crash → lease recovery | `test_delivery_engine::test_crash_recovery…` + `test_reliability_fixes::test_recovery_writes_attempt_history` |
| 6 | Redis loses queue → DB scanner republish | `dispatcher.get_due_delivery_ids` + `tasks.dispatch_due_deliveries_task` (scanner is source of truth) |
| 7 | Same idempotency key concurrently → 1 event | `test_scenario_coverage::test_concurrent_ingestion_race_condition`, `test_event_service` |
| 8 | Cross-org access denied | `test_scenario_coverage::test_cross_tenant_isolation…`, `test_api_v1` 404 |
| 9 | Tamper → signature fail | `test_signing.py` |
| 10 | Huge response bounded | `test_scenario_coverage::test_bounded_response_excerpt_truncation` |
| 11 | Internal address blocked | `test_ssrf.py`, `test_dns_rebinding.py` |
| 12 | Replay dead → new linked delivery, same event | `test_delivery_engine::test_manual_replay…` + `test_reliability_fixes::test_replay_only_dead` |
| + | 429 + Retry-After (sec + HTTP-date) | `test_reliability_fixes::test_retry_after_*` |
| + | Prefix `order.*` subscriptions | `test_reliability_fixes::test_prefix_*` |
| + | Payload 413, CSRF 403, endpoint cap, disable | `test_scenario_coverage` |
| + | Metrics histogram, tracing inject | `test_reliability_fixes::test_metrics_…`, `test_trace_…` |

Layout:
- `tests/test_*.py` — legacy flat suite (kept for CI).
- `tests/unit/` — pure logic (signing, backoff, matching).
- `tests/integration/` — DB + API with PG when available.
- `tests/e2e/` — full publish → dispatch → receiver flows.
