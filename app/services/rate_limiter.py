import threading
import time

import redis

from app.config import settings


class MemoryTokenBucket:
    """Thread-safe in-memory token bucket implementation for rate limiting."""
    def __init__(self):
        self._buckets = {}
        self._lock = threading.Lock()

    def acquire(self, key: str, rate_per_second: float, capacity: float | None = None) -> tuple[bool, float]:
        """
        Attempts to acquire 1 token from the bucket.
        Returns:
            (allowed: bool, wait_seconds: float)
        """
        if capacity is None:
            capacity = float(rate_per_second)

        now = time.monotonic()
        with self._lock:
            if key not in self._buckets:
                self._buckets[key] = {
                    "tokens": float(capacity),
                    "last_updated": now
                }

            bucket = self._buckets[key]
            elapsed = now - bucket["last_updated"]
            bucket["last_updated"] = now

            # Replenish tokens based on elapsed time
            bucket["tokens"] = min(float(capacity), bucket["tokens"] + elapsed * rate_per_second)

            if bucket["tokens"] >= 1.0:
                bucket["tokens"] -= 1.0
                return True, 0.0
            else:
                missing_tokens = 1.0 - bucket["tokens"]
                wait_time = missing_tokens / rate_per_second
                return False, wait_time

class RedisTokenBucket:
    """Redis-backed token bucket using an atomic Lua script."""
    LUA_SCRIPT = """
    local key = KEYS[1]
    local rate = tonumber(ARGV[1])
    local capacity = tonumber(ARGV[2])
    local now = tonumber(ARGV[3])

    local data = redis.call("HMGET", key, "tokens", "last_updated")
    local tokens = tonumber(data[1])
    local last_updated = tonumber(data[2])

    if tokens == nil then
        tokens = capacity
        last_updated = now
    else
        local elapsed = math.max(0, now - last_updated)
        tokens = math.min(capacity, tokens + elapsed * rate)
        last_updated = now
    end

    if tokens >= 1.0 then
        tokens = tokens - 1.0
        redis.call("HMSET", key, "tokens", tokens, "last_updated", last_updated)
        redis.call("EXPIRE", key, math.ceil(capacity / rate * 2 + 10))
        return {1, 0}
    else
        local wait_time = (1.0 - tokens) / rate
        redis.call("HMSET", key, "tokens", tokens, "last_updated", last_updated)
        redis.call("EXPIRE", key, math.ceil(capacity / rate * 2 + 10))
        return {0, tostring(wait_time)}
    end
    """

    def __init__(self, redis_client: redis.Redis):
        self.redis = redis_client
        self._script = self.redis.register_script(self.LUA_SCRIPT)

    def acquire(self, key: str, rate_per_second: float, capacity: float | None = None) -> tuple[bool, float]:
        """Atomic Redis token-bucket. On Redis failure raises so callers can
        fall back to the in-memory bucket (documented fail-local behavior)."""
        if capacity is None:
            capacity = float(rate_per_second)
        now = time.time()
        result = self._script(
            keys=[f"ratelimit:{key}"],
            args=[rate_per_second, capacity, now]
        )
        allowed = bool(result[0] == 1)
        wait_time = float(result[1]) if not allowed else 0.0
        return allowed, wait_time

# Initialize Rate Limiter with graceful fallback.
# Documented behavior when Redis is unavailable (see docs/SECURITY.md):
# rate limiting falls back to a per-process in-memory token bucket. This keeps
# a single instance safe but does NOT coordinate across replicas. For
# multi-replica production, Redis is required; monitor `redis_bucket is None`.
memory_bucket = MemoryTokenBucket()
redis_bucket: RedisTokenBucket | None = None
redis_unavailable_logged = False

try:
    r = redis.from_url(settings.REDIS_URL, socket_connect_timeout=0.2)
    r.ping()
    redis_bucket = RedisTokenBucket(r)
except Exception as _e:
    import logging as _logging
    _logging.getLogger("webhook.rate_limiter").warning(
        "Redis unavailable at startup, using in-memory rate limiter (per-process only): %s",
        _e,
    )
    redis_bucket = None

def check_endpoint_rate_limit(endpoint_id: str, rate_per_second: int) -> tuple[bool, float]:
    """
    Checks per-endpoint delivery rate limit.
    Returns (allowed, wait_seconds).
    """
    rate = max(1.0, float(rate_per_second))
    if redis_bucket:
        try:
            return redis_bucket.acquire(f"endpoint:{endpoint_id}", rate)
        except Exception:
            pass
    return memory_bucket.acquire(f"endpoint:{endpoint_id}", rate)

def check_ingestion_rate_limit(project_id: str, max_per_second: float = 30.0) -> tuple[bool, float]:
    """
    Checks project event ingestion rate limit.
    Returns (allowed, wait_seconds).
    """
    if redis_bucket:
        try:
            return redis_bucket.acquire(f"ingest:{project_id}", max_per_second)
        except Exception:
            pass
    return memory_bucket.acquire(f"ingest:{project_id}", max_per_second)

def _acquire_both(key: str, rate_per_sec: float, capacity: float) -> tuple[bool, float]:
    """Try Redis first, fall back to in-memory. Single bucket helper."""
    if redis_bucket:
        try:
            return redis_bucket.acquire(key, rate_per_sec, capacity)
        except Exception:
            pass
    return memory_bucket.acquire(key, rate_per_sec, capacity)


def check_login_rate_limit(client_ip: str, email: str = "") -> tuple[bool, float]:
    """
    Dual-bucket login throttle (fixes email-rotation bypass):
    - per-IP bucket: 20 attempts / 60s (burst 20) — stops distributed guessing
    - per-IP+email bucket: 5 attempts / 60s (burst 5) — stops targeted guessing
    Both must allow; returns longest wait on denial.
    """
    ip = (client_ip or "unknown").strip() or "unknown"
    em = (email or "").strip().lower()
    ip_allowed, ip_wait = _acquire_both(f"login:ip:{ip}", 20.0 / 60.0, 20.0)
    if not ip_allowed:
        return False, ip_wait
    if em:
        em_allowed, em_wait = _acquire_both(f"login:ip-email:{ip}:{em}", 5.0 / 60.0, 5.0)
        if not em_allowed:
            return False, em_wait
    else:
        # No email supplied: apply stricter per-IP email-less bucket
        em_allowed, em_wait = _acquire_both(f"login:ip:{ip}:noemail", 5.0 / 60.0, 5.0)
        if not em_allowed:
            return False, em_wait
    return True, 0.0


def check_registration_rate_limit(client_ip: str) -> tuple[bool, float]:
    """Registration throttle: 10 accounts / hour per IP (burst 10)."""
    ip = (client_ip or "unknown").strip() or "unknown"
    return _acquire_both(f"register:ip:{ip}", 10.0 / 3600.0, 10.0)


def check_invite_rate_limit(org_id: str) -> tuple[bool, float]:
    """Team-invite throttle: 20 invites / hour per org (burst 20)."""
    return _acquire_both(f"invite:org:{org_id}", 20.0 / 3600.0, 20.0)

