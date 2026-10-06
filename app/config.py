import os
from pydantic_settings import BaseSettings
from pydantic import Field
from cryptography.fernet import Fernet

class Settings(BaseSettings):
    PROJECT_NAME: str = "Reliable Webhook Delivery Platform"
    ENV: str = "development"
    DEBUG: bool = True
    PORT: int = 8080
    
    # Database
    DATABASE_URL: str = Field(
        default="sqlite:///./webhooks.db",
        description="PostgreSQL or SQLite connection string"
    )
    
    # Security
    SECRET_KEY: str = Field(
        default="wh_dev_insecure_secret_key_change_in_production_1234567890",
        description="Session & cookie signing secret"
    )
    SIGNING_SECRET_ENCRYPTION_KEY: str = Field(
        default="yFz8s0v81v3G-xG3hV48V7s9uY5pL0tM2wN4bQ6rE8A=",
        description="Fernet key for encrypting endpoint HMAC secrets at rest"
    )
    
    # Delivery Engine & Workers
    REDIS_URL: str = "redis://localhost:6379/0"
    ALLOW_LOCAL_RECEIVERS: bool = True  # Enable for dev & controllable demo receiver
    # Public-demo safety: comma-separated allowlist of receiver domains.
    # Empty = no allowlist enforcement (dev). Set in production/demo, e.g.
    # "merchant.example.com,receiver.example.org". Localhost is still gated
    # by ALLOW_LOCAL_RECEIVERS.
    ALLOWED_RECEIVER_DOMAINS: str = Field(
        default="",
        description="Comma-separated allowlist of webhook receiver domains (empty disables)"
    )
    # Outbound HTTP timeouts (total must stay < lease duration with margin)
    HTTP_CONNECT_TIMEOUT_SECONDS: float = 3.0
    # Data retention (0/None disables automatic purging)
    DATA_RETENTION_DAYS: int = Field(default=90, description="Purge terminal events/deliveries older than N days (0 disables)")
    
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

    class Config:
        env_file = ".env"
        extra = "ignore"

settings = Settings()

# Fail fast in production when insecure placeholder secrets are still configured.
# Development (ENV != production) keeps convenient defaults for local compose/tests.
_INSECURE_SECRET_DEFAULTS = {
    "wh_dev_insecure_secret_key_change_in_production_1234567890",
}
if settings.ENV == "production":
    if settings.SECRET_KEY in _INSECURE_SECRET_DEFAULTS or len(settings.SECRET_KEY) < 32:
        raise RuntimeError(
            "SECRET_KEY must be set to a strong random value (>=32 chars) in production. "
            "Generate one with: python -c \"import secrets; print(secrets.token_urlsafe(48))\""
        )
    if settings.ALLOW_LOCAL_RECEIVERS:
        # Local receivers (loopback) must never be reachable in a public deployment
        # unless explicitly intended; fail closed and require operator opt-in.
        import os as _os
        if _os.getenv("I_UNDERSTAND_ALLOW_LOCAL_RISK", "").lower() not in ("1", "true", "yes"):
            raise RuntimeError(
                "ALLOW_LOCAL_RECEIVERS=True is forbidden in production (SSRF risk). "
                "Set ALLOW_LOCAL_RECEIVERS=False and configure ALLOWED_RECEIVER_DOMAINS, "
                "or set I_UNDERSTAND_ALLOW_LOCAL_RISK=1 for a closed demo."
            )

# Ensure signing secret key is valid Fernet key
try:
    Fernet(settings.SIGNING_SECRET_ENCRYPTION_KEY.encode())
except Exception:
    # Generate fallback valid Fernet key in dev
    settings.SIGNING_SECRET_ENCRYPTION_KEY = Fernet.generate_key().decode()
