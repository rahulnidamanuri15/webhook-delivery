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
  1. **Bounded Reads**: Workers read and truncate HTTP response excerpts to a maximum of 1,024 characters.
  2. **Token Bucket Rate Limiting**: Per-project ingestion rate limits and per-endpoint delivery rate limits.
  3. **Strict Timeouts**: HTTP requests have an aggressive 10-second timeout, well below the 30-second worker lease.

### 1.5 Cross-Site Request Forgery (CSRF) & Session Hijacking
- **Threat**: Malicious cross-origin scripts manipulate dashboard settings (e.g., replaying dead letters or rotating keys).
- **Defense**:
  1. Signed session cookies with `HttpOnly`, `SameSite=Lax`, and `Secure` attributes.
  2. Cryptographic CSRF tokens validated on all state-changing HTML forms (`POST`).
  3. Automatic session regeneration upon login.

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
- [ ] Enforce HTTPS (`REQUIRE_HTTPS=True`) for all webhook endpoints.
- [ ] Store `SECRET_KEY` and `SIGNING_SECRET_ENCRYPTION_KEY` in a secure secrets manager (e.g., AWS Secrets Manager, HashiCorp Vault).
- [ ] Configure outbound egress proxies or firewalls to restrict worker network interfaces.
