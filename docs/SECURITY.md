# Security Policy & Threat Model

This document outlines the security architecture, threat model, and defense mechanisms implemented within the Reliable Webhook Delivery Platform.

---

## 1. Threat Model & Mitigations

### 1.1 Server-Side Request Forgery (SSRF)
- **Threat**: Malicious actors register webhook destinations pointing to internal cloud metadata (`http://169.254.169.254`), container interfaces, or private VPC services (`10.0.0.0/8`, `192.168.0.0/16`) to exfiltrate IAM credentials or probe internal systems.
- **Defense**:
  1. Strict destination IP range inspection (`app/services/ssrf.py`).
  2. Blocking of all loopback, RFC1918 private, link-local, multicast, and cloud metadata addresses.
  3. Automatic resolution and IP pinning (`resolve_and_pin_destination`) preventing DNS rebinding (Time-of-Check to Time-of-Use attacks).
  4. Disabling HTTP redirect following (`follow_redirects=False`) in outbound delivery workers.
  5. Optional receiver domain allowlist (`ALLOWED_RECEIVER_DOMAINS`): when set, only listed
     domains (and subdomains) are accepted. Recommended for any public demo.
     Example: `ALLOWED_RECEIVER_DOMAINS=merchant.example.com`. Empty disables.

### 1.2 Webhook Forgery & Replay Attacks
- **Threat**: An adversary intercepts or forges webhook HTTP requests to trigger unauthorized business logic on the receiver.
- **Defense**:
  1. Outbound requests are signed using **HMAC-SHA256** with endpoint-specific symmetric secrets.
  2. Canonical signing payload binds `event_id`, UNIX `timestamp`, and the exact `raw_wire_payload`.
  3. Receivers verify timestamp freshness ($\pm 300\text{ seconds}$) and compare signatures with `hmac.compare_digest` to prevent timing attacks.

### 1.3 Credential Theft & Key Compromise
- **Threat**: Database compromise exposes developer API keys or webhook signing secrets.
- **Defense**:
  1. **API Keys**: High-entropy keys prefixed with `wh_live_` are displayed to the user **only once**. Only the SHA-256 hash is persisted in the database.
  2. **Signing Secrets**: Encrypted at rest using **Fernet (AES-128-CBC + HMAC-SHA256)** via `SIGNING_SECRET_ENCRYPTION_KEY`. Plaintext secrets never appear in database storage or audit logs.
  3. **User Passwords**: Hashed using **Argon2id**, the winner of the Password Hashing Competition.

### 1.4 Denial of Service & Resource Exhaustion (DoS)
- **Threat**:
  - Receiver returns gigabytes of data to exhaust worker memory.
  - Floods of ingestion events overwhelm the system.
  - Slow receiver ties up worker threads.
- **Defense**:
  1. **Bounded streaming reads**: workers stream at most 64 KiB from the wire
     (`MAX_RESPONSE_READ_BYTES`) and store at most 1,024 chars
     (`RESPONSE_EXCERPT_MAX_BYTES`). Bodies are never loaded unbounded.
  2. **Token Bucket Rate Limiting**: Per-project ingestion rate limits and per-endpoint delivery rate limits (Redis Lua atomic; see Redis fallback below).
  3. **Strict Timeouts**: separate connect timeout (`HTTP_CONNECT_TIMEOUT_SECONDS=3s`)
     and total timeout (`HTTP_TIMEOUT_SECONDS=10s`), both well below the 30-second worker lease.
  4. **Bounded concurrency**: dispatcher uses a capped thread pool (`DISPATCH_MAX_WORKERS=10`)
     so one slow endpoint cannot block all other endpoints.

#### Redis-unavailability behavior (documented)
- If Redis is unreachable at startup or per-request, rate limiting falls back to a
  **per-process in-memory token bucket**. Single-instance deployments stay safe;
  multi-replica deployments lose cross-instance coordination until Redis recovers.
- Session logout denylist also prefers Redis (`session_denylist:*`, 7-day TTL) with
  in-memory fallback. Monitor logs for `Redis unavailable` warnings; Redis is required
  for production multi-replica rate limiting.

### 1.5 Cross-Site Request Forgery (CSRF) & Session Hijacking
- **Threat**: Malicious cross-origin scripts manipulate dashboard settings (e.g., replaying dead letters or rotating keys).
- **Defense**:
  1. Signed session cookies with `HttpOnly`, `SameSite=Lax`, and `Secure` attributes.
  2. Cryptographic CSRF tokens validated on all state-changing HTML forms (`POST`).
  3. New signed session on login; logout adds the token hash to a server-side denylist
     (Redis `session_denylist:*` with 7-day TTL, in-memory fallback) so stolen cookies
     cannot be reused after logout.

---

## 2. Audit Logging System

All security-sensitive operations generate immutable audit records stored in the `audit_logs` table:
- API key generation and revocation
- Webhook endpoint creation, disabling, and deletion
- Endpoint signing secret rotation
- Dead letter manual replays
- Team member invitations and role adjustments

Each audit entry records `actor_user_id`, `actor_email`, `action`, `resource_type`, `resource_id`, and `ip_address`.

---

## 3. Production Deployment Checklist

When deploying to a production environment:

- [ ] Set `ALLOW_LOCAL_RECEIVERS=False` to strictly disallow loopback/RFC1918 destinations.
- [ ] Set `ALLOWED_RECEIVER_DOMAINS` to your controlled receiver domains for public demos.
- [ ] Serve via `reverse_proxy` (nginx, `deploy/nginx.conf`): enable the 443 block with real certs.
- [ ] Enforce HTTPS-only receiver URLs (production defaults to `https` when `DEBUG=False` and `ALLOW_LOCAL_RECEIVERS=False`).
- [ ] Store `SECRET_KEY` and `SIGNING_SECRET_ENCRYPTION_KEY` in a secure secrets manager (e.g., AWS Secrets Manager, HashiCorp Vault).
- [ ] Set `DATA_RETENTION_DAYS` (default 90) and verify the hourly purge / `tasks.purge_expired_data` schedule.
- [ ] Set `DEMO_RECEIVER_ADMIN_TOKEN` and do not expose the demo receiver publicly without it.
- [ ] Configure outbound egress proxies or firewalls to restrict worker network interfaces.
- [ ] Set `OTEL_EXPORTER_OTLP_ENDPOINT` to collect traces; logs are JSON-structured to stdout.
- [ ] Serve ONLY behind the nginx `reverse_proxy`: `get_client_ip()` trusts
      `X-Forwarded-For`/`X-Real-IP`, so direct `:8080` exposure lets clients spoof
      IPs (rate-limit bypass, audit-log poisoning). Never publish port 8080.
- [ ] Set `REDIS_URL` with a password: session logout revocation and rate limits
      are per-process memory without Redis (multi-replica logout gap).
- [ ] Set `USE_CELERY=True` in production so deliveries survive web restarts.
- [ ] Schedule backups per `docs/BACKUP_AND_RESTORE.md` (DB dumps + offsite copies).

---

## 4. Data-Retention Policy

`DATA_RETENTION_DAYS` (default `90`, `0` disables) controls automatic purging:

- Only **terminal** deliveries (`SUCCEEDED`/`DEAD`) older than the window are removed,
  with their attempts deleted first.
- Events are removed once they have no remaining deliveries and are older than the window.
- Audit logs older than the window are trimmed.
- In-flight / pending / retry-scheduled records are **never** purged.
- Purge runs hourly in the dispatcher loop and via Celery `tasks.purge_expired_data`.

If the encryption key (`SIGNING_SECRET_ENCRYPTION_KEY`) is lost, restored signing
secrets cannot be decrypted — back it up separately (see `BACKUP_AND_RESTORE.md`).
