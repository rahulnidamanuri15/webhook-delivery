import time
import threading
from typing import Tuple, Optional
import redis
from app.config import settings

class MemoryTokenBucket:
    """Thread-safe in-memory token bucket implementation for rate limiting."""
    def __init__(self):
        self._buckets = {}
        self._lock = threading.Lock()

    def acquire(self, key: str, rate_per_second: float, capacity: Optional[float] = None) -> Tuple[bool, float]:
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

    def acquire(self, key: str, rate_per_second: float, capacity: Optional[float] = None) -> Tuple[bool, float]:
        if capacity is None:
            capacity = float(rate_per_second)
        now = time.time()
        try:
            result = self._script(
                keys=[f"ratelimit:{key}"],
                args=[rate_per_second, capacity, now]
            )
            allowed = bool(result[0] == 1)
            wait_time = float(result[1]) if not allowed else 0.0
            return allowed, wait_time
        except Exception:
            # Fallback to local memory if Redis fails
            return True, 0.0

# Initialize Rate Limiter with graceful fallback
memory_bucket = MemoryTokenBucket()
redis_bucket: Optional[RedisTokenBucket] = None

try:
    r = redis.from_url(settings.REDIS_URL, socket_connect_timeout=0.2)
    r.ping()
    redis_bucket = RedisTokenBucket(r)
except Exception:
    redis_bucket = None

def check_endpoint_rate_limit(endpoint_id: str, rate_per_second: int) -> Tuple[bool, float]:
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

def check_ingestion_rate_limit(project_id: str, max_per_second: float = 30.0) -> Tuple[bool, float]:
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
