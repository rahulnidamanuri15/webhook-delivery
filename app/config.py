from cryptography.fernet import Fernet
from pydantic import Field
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    PROJECT_NAME: str = "Reliable Webhook Delivery Platform"
    ENV: str = "development"
    DEBUG: bool = False
    PORT: int = 8080

    # Database
    DATABASE_URL: str = Field(
        default="postgresql+psycopg://postgres:postgrespassword@localhost:5432/webhook_platform",
        description="PostgreSQL or SQLite connection string",
    )

    # Security
    SECRET_KEY: str = Field(
        default="wh_dev_insecure_secret_key_change_in_production_1234567890",
        description="Session & cookie signing secret",
    )
    SIGNING_SECRET_ENCRYPTION_KEY: str = Field(
        default="yFz8s0v81v3G-xG3hV48V7s9uY5pL0tM2wN4bQ6rE8A=",
        description="Fernet key for encrypting endpoint HMAC secrets at rest (first key if comma-separated)",
    )
    SIGNING_SECRET_ENCRYPTION_KEYS_FALLBACK: str = Field(
        default="",
        description="Comma-separated fallback Fernet keys for zero-downtime key rotation",
    )

    # Delivery Engine & Workers
    REDIS_URL: str = "redis://localhost:6379/0"
    USE_CELERY: bool = Field(default=False, description="Enqueue outbound webhook deliveries through Celery and Redis")
    ENABLE_INPROCESS_DISPATCHER: bool = Field(
        default=False, description="Run background delivery dispatcher thread inside web process"
    )
    # Secure-by-default: loopback receivers are denied unless explicitly
    # enabled for local dev (ALLOW_LOCAL_RECEIVERS=True in .env).
    ALLOW_LOCAL_RECEIVERS: bool = False
    # Public-demo safety: comma-separated allowlist of receiver domains.
    # Empty = no allowlist enforcement (dev). Set in production/demo, e.g.
    # "merchant.example.com,receiver.example.org". Localhost is still gated
    # by ALLOW_LOCAL_RECEIVERS.
    ALLOWED_RECEIVER_DOMAINS: str = Field(
        default="", description="Comma-separated allowlist of webhook receiver domains (empty disables)"
    )
    # Observability
    LOG_LEVEL: str = Field(default="INFO", description="Root log level (DEBUG, INFO, WARNING, ERROR)")
    # Cookie security
    COOKIE_SECURE: bool | None = Field(
        default=None, description="Force secure cookie flag (None = auto based on ENV and DEBUG)"
    )
    # Outbound HTTP timeouts (total must stay < lease duration with margin)
    HTTP_CONNECT_TIMEOUT_SECONDS: float = 3.0
    # Data retention (0/None disables automatic purging)
    DATA_RETENTION_DAYS: int = Field(
        default=90, description="Purge terminal events/deliveries older than N days (0 disables)"
    )
    # Audit logs are compliance-sensitive: retain longer than operational data.
    AUDIT_RETENTION_DAYS: int = Field(default=365, description="Purge audit logs older than N days (0 disables)")
    # Server-side pepper for API-key hashes (HMAC). Empty = legacy plain
    # SHA-256 (back-compat); set a strong random value in production.
    API_KEY_PEPPER: str = Field(default="", description="Pepper for API key hashing (HMAC-SHA256)")
    # DNS resolution timeout for SSRF checks (prevents slow-DNS DoS in request path)
    DNS_RESOLVE_TIMEOUT_SECONDS: float = Field(
        default=3.0, description="Timeout for DNS resolution during URL validation"
    )
    # Recovery scanner batch bound (prevents OOM when many leases expire)
    RECOVERY_BATCH_SIZE: int = Field(default=500, description="Max abandoned leases reclaimed per cycle")

    # Retry & Delivery policies
    MAX_DELIVERY_ATTEMPTS: int = 5
    HTTP_TIMEOUT_SECONDS: float = 10.0
    LEASE_DURATION_SECONDS: int = 30
    # Product retry policy (spec §7): 10s, 30s, 2m, 10m, 30m, 2h with +/-15% jitter.
    # With MAX_DELIVERY_ATTEMPTS=5 the first five intervals are used; the sixth
    # applies if an operator raises the budget. Shorter DEMO policy is enabled
    # by default for recorded demos (USE_DEMO_RETRY_POLICY=True).
    DEFAULT_RETRY_INTERVALS: list[int] = [10, 30, 120, 600, 1800, 7200]
    DEMO_RETRY_INTERVALS: list[int] = [2, 5, 10, 20, 40]
    USE_DEMO_RETRY_POLICY: bool = True

    # Payload & Rate limits
    MAX_PAYLOAD_SIZE_BYTES: int = 1_048_576  # 1 MB
    RESPONSE_EXCERPT_MAX_BYTES: int = 1024  # Max stored response excerpt
    MAX_ENDPOINTS_PER_PROJECT: int = 20
    INGESTION_RATE_LIMIT_PER_SECOND: float = 30.0

    # Metrics endpoint protection
    METRICS_API_KEY: str = Field(
        default="", description="Bearer token required for /metrics. Empty = require session auth instead."
    )

    def __init__(self, **values):
        super().__init__(**values)
        import os as _os

        # Docker Secrets and Kubernetes Secrets support via *_FILE environment variables
        for _secret_field in (
            "SECRET_KEY",
            "SIGNING_SECRET_ENCRYPTION_KEY",
            "SIGNING_SECRET_ENCRYPTION_KEYS_FALLBACK",
            "API_KEY_PEPPER",
            "METRICS_API_KEY",
            "DATABASE_URL",
            "REDIS_URL",
        ):
            _file_path = _os.getenv(f"{_secret_field}_FILE")
            if _file_path and _os.path.isfile(_file_path):
                try:
                    with open(_file_path, "r", encoding="utf-8") as _f:
                        _val = _f.read().strip()
                        if _val:
                            setattr(self, _secret_field, _val)
                except Exception:
                    pass

    class Config:
        env_file = ".env"
        extra = "ignore"


settings = Settings()

# Fail fast in production when insecure placeholder secrets are still configured.
# Development (ENV != production) keeps convenient defaults for local compose/tests.
_INSECURE_SECRET_DEFAULTS = {
    "wh_dev_insecure_secret_key_change_in_production_1234567890",
    "ci_secret_key_testing_only_1234567890_super_safe",
    "secret",
    "changeme",
}
_INSECURE_FERNET_DEFAULTS = {
    "yFz8s0v81v3G-xG3hV48V7s9uY5pL0tM2wN4bQ6rE8A=",
    "d2hfc2VjcmV0X2Zlcm5ldF9rZXlfMTIzNDU2Nzg5MDEyMzQ=",
}
_INSECURE_DB_SUBSTRINGS = ("postgrespassword", "postgres:postgres@")


def validate_production_settings(s: Settings) -> None:
    # Normalized prod check (ENV is case-insensitive; "Production" must not bypass).
    is_prod = str(s.ENV or "").strip().lower() == "production"
    if not is_prod:
        return
    if s.SECRET_KEY in _INSECURE_SECRET_DEFAULTS or len(s.SECRET_KEY) < 32:
        raise RuntimeError(
            "SECRET_KEY must be set to a strong random value (>=32 chars) in production. "
            'Generate one with: python -c "import secrets; print(secrets.token_urlsafe(48))"'
        )
    primary_fernet_key = (s.SIGNING_SECRET_ENCRYPTION_KEY or "").split(",")[0].strip()
    if primary_fernet_key in _INSECURE_FERNET_DEFAULTS:
        raise RuntimeError(
            "SIGNING_SECRET_ENCRYPTION_KEY uses the public dev default or a committed repository key. "
            'Generate one with: python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"'
        )
    if not s.API_KEY_PEPPER or len(s.API_KEY_PEPPER) < 16:
        raise RuntimeError(
            "API_KEY_PEPPER must be set to a strong random value (>=16 chars) in production. "
            'Generate one with: python -c "import secrets; print(secrets.token_urlsafe(32))"'
        )
    if any(substr in s.DATABASE_URL for substr in _INSECURE_DB_SUBSTRINGS):
        raise RuntimeError("DATABASE_URL uses dev default credentials in production. Set a strong POSTGRES_PASSWORD.")
    # SQLite and other non-PostgreSQL backends are never valid in production
    # (no concurrency, no SKIP LOCKED, data loss on ephemeral disk).
    _db_url_lower = str(s.DATABASE_URL or "").strip().lower()
    if _db_url_lower.startswith("sqlite"):
        raise RuntimeError("DATABASE_URL must be PostgreSQL in production (SQLite is dev/test only).")
    if not _db_url_lower.startswith("postgresql"):
        raise RuntimeError("DATABASE_URL must be a postgresql+psycopg URL in production.")
    # DEBUG must never be enabled in production (enables http receivers,
    # suppresses HSTS, weakens cookie flags).
    if s.DEBUG:
        raise RuntimeError("DEBUG must be False in production. Unset DEBUG or set DEBUG=False.")
    if not s.METRICS_API_KEY or len(s.METRICS_API_KEY) < 16:
        raise RuntimeError("METRICS_API_KEY must be set (>=16 chars) in production to protect /metrics.")
    if s.ALLOW_LOCAL_RECEIVERS:
        import os as _os

        if _os.getenv("I_UNDERSTAND_ALLOW_LOCAL_RISK", "").lower() not in ("1", "true", "yes"):
            raise RuntimeError(
                "ALLOW_LOCAL_RECEIVERS=True is forbidden in production (SSRF risk). "
                "Set ALLOW_LOCAL_RECEIVERS=False and configure ALLOWED_RECEIVER_DOMAINS, "
                "or set I_UNDERSTAND_ALLOW_LOCAL_RISK=1 for a closed demo."
            )
    if s.USE_DEMO_RETRY_POLICY:
        raise RuntimeError(
            "USE_DEMO_RETRY_POLICY must be False in production. "
            "Set USE_DEMO_RETRY_POLICY=False to enable exponential backoff intervals [10, 30, 120, 600, 1800, 7200]."
        )
    if s.HTTP_TIMEOUT_SECONDS + 5 > s.LEASE_DURATION_SECONDS:
        raise RuntimeError(
            f"LEASE_DURATION_SECONDS ({s.LEASE_DURATION_SECONDS}) must exceed "
            f"HTTP_TIMEOUT_SECONDS ({s.HTTP_TIMEOUT_SECONDS}) by at least 5 seconds safety margin."
        )
    if not s.ALLOWED_RECEIVER_DOMAINS or not s.ALLOWED_RECEIVER_DOMAINS.strip():
        raise RuntimeError(
            "ALLOWED_RECEIVER_DOMAINS must be configured in production (e.g. 'api.partner.com,webhooks.acme.com'). "
            "An explicit allowlist is required to prevent arbitrary outbound SSRF connections."
        )


_IS_PRODUCTION = str(settings.ENV or "").strip().lower() == "production"
validate_production_settings(settings)


def get_configured_fernet_keys(s: Settings) -> list[str]:
    keys: list[str] = []
    if s.SIGNING_SECRET_ENCRYPTION_KEY:
        for k in s.SIGNING_SECRET_ENCRYPTION_KEY.split(","):
            clean = k.strip()
            if clean and clean not in keys:
                keys.append(clean)
    fallback = getattr(s, "SIGNING_SECRET_ENCRYPTION_KEYS_FALLBACK", "")
    if fallback:
        for k in fallback.split(","):
            clean = k.strip()
            if clean and clean not in keys:
                keys.append(clean)
    return keys


# Ensure all configured signing secret keys are valid Fernet keys — fail fast, never silently rotate
_configured_fernet_keys = get_configured_fernet_keys(settings)
if not _configured_fernet_keys:
    raise RuntimeError("At least one Fernet key must be configured in SIGNING_SECRET_ENCRYPTION_KEY.")

for _k in _configured_fernet_keys:
    try:
        Fernet(_k.encode("utf-8"))
    except Exception as e:
        raise RuntimeError(
            f"Configured Fernet key '{_k[:8]}...' is not a valid Fernet key: {e}. "
            'Generate one with: python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"'
        )
