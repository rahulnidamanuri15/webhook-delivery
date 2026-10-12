from cryptography.fernet import Fernet
from pydantic import Field
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    PROJECT_NAME: str = "Hookflow"
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

    ALLOW_OPEN_REGISTRATION: bool = Field(
        default=False, description="Allow anyone to register. MUST be False in production."
    )
    # Registration approval queue: when True, /auth/register accepts signups
    # even while ALLOW_OPEN_REGISTRATION is False, but creates PENDING users
    # (no org, no session) for superadmin approve/reject. Safe for production:
    # pending users get zero access until approved.
    ALLOW_PENDING_REGISTRATION: bool = Field(
        default=False, description="Accept registrations into pending approval queue (no instant access)"
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

    # SMTP / Email (forgot-password OTP delivery)
    SMTP_HOST: str = Field(default="", description="SMTP server hostname (empty disables email sending)")
    SMTP_PORT: int = Field(default=587, description="SMTP server port (587 TLS / 465 SSL / 25 plain)")
    SMTP_USERNAME: str = Field(default="", description="SMTP auth username (empty = no auth)")
    SMTP_PASSWORD: str = Field(default="", description="SMTP auth password")
    SMTP_FROM_EMAIL: str = Field(
        default="noreply@hookflow.local", description="From address used for transactional emails"
    )
    SMTP_FROM_NAME: str = Field(default="Hookflow", description="From display name for transactional emails")
    SMTP_USE_TLS: bool = Field(
        default=True, description="Use STARTTLS on SMTP_PORT (False for SSL-on-connect on 465 or plain local relay)"
    )
    SMTP_USE_SSL: bool = Field(default=False, description="Use implicit SSL (SMTPS, typically port 465)")
    SMTP_TIMEOUT_SECONDS: float = Field(default=10.0, description="SMTP connection/socket timeout")

    # Forgot-password OTP policy
    PASSWORD_RESET_OTP_LENGTH: int = Field(default=6, description="Digits in the forgot-password OTP")
    PASSWORD_RESET_OTP_EXPIRE_MINUTES: int = Field(default=10, description="OTP validity window in minutes")
    PASSWORD_RESET_OTP_MAX_ATTEMPTS: int = Field(
        default=5, description="Max OTP verification attempts before OTP is invalidated"
    )
    PASSWORD_RESET_TOKEN_EXPIRE_MINUTES: int = Field(
        default=15, description="Short-lived reset-token validity after successful OTP verification"
    )
    # Test-only sink for the plaintext OTP when SMTP is not configured.
    # Never enable outside automated tests: it keeps live OTPs in process memory.
    PASSWORD_RESET_OTP_CAPTURE: bool = Field(
        default=False,
        description="Test-only: capture plaintext OTPs in-process instead of sending or logging them",
    )

    # Trusted proxies for X-Forwarded-For evaluation (comma-separated IPs/CIDRs).
    # Secure-by-default narrow ranges (prefixlen >= 16): broad /8 defaults let
    # any VPC/bridge peer forge XFF (rate-limit bypass, audit poisoning).
    # Override with your actual proxy/bridge CIDR.
    TRUSTED_PROXIES: str = Field(
        default="127.0.0.1,::1,172.18.0.0/24,10.0.0.0/24",
        description="Comma-separated trusted reverse-proxy IPs/CIDRs allowed to set the client IP",
    )
    # Public origin used in invitation emails. Empty = derive from the request.
    PUBLIC_BASE_URL: str = Field(
        default="",
        description="Public https origin for links in email (e.g. https://hooks.example.com). No trailing slash.",
    )
    # Compliance hold: comma-separated project IDs excluded from retention purge.
    LEGAL_HOLD_PROJECT_IDS: str = Field(
        default="",
        description="Comma-separated project IDs excluded from retention purge (legal hold).",
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
            "SMTP_PASSWORD",
        ):
            _file_path = _os.getenv(f"{_secret_field}_FILE")
            if _file_path:
                if not _os.path.isfile(_file_path):
                    raise RuntimeError(
                        f"{_secret_field}_FILE is set to '{_file_path}', but the file does not exist or is not a regular file."
                    )
                try:
                    with open(_file_path, "r", encoding="utf-8") as _f:
                        _val = _f.read().strip()
                        if not _val:
                            raise RuntimeError(f"{_secret_field}_FILE at '{_file_path}' is empty.")
                        setattr(self, _secret_field, _val)
                except Exception as _e:
                    if isinstance(_e, RuntimeError):
                        raise
                    raise RuntimeError(
                        f"Failed to read secret from {_secret_field}_FILE at '{_file_path}': {_e}"
                    ) from _e

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
# Any value copied from .env.example without generation must fail closed,
# even when it happens to satisfy length checks.
_PLACEHOLDER_SUBSTRINGS = ("change_me", "changeme", "replace_me", "example.com")


def _contains_placeholder(value: str | None) -> bool:
    if not value:
        return False
    lowered = str(value).strip().lower()
    return any(marker in lowered for marker in _PLACEHOLDER_SUBSTRINGS)


def is_production_env(env_value: str | None) -> bool:
    """True for production AND common aliases (prod/live) so ENV=prod cannot
    bypass fail-fasts. Staging is treated as prod-like (strict) too."""
    return str(env_value or "").strip().lower() in ("production", "prod", "live", "staging")


def validate_production_settings(s: Settings) -> None:
    # Normalized prod check (ENV is case-insensitive; "Production"/"prod" must not bypass).
    is_prod = is_production_env(s.ENV)
    if not is_prod:
        return
    _redis = str(s.REDIS_URL or "").strip()
    if _redis.startswith(("redis://", "rediss://")) and "@" not in _redis:
        raise RuntimeError(
            "REDIS_URL must include authentication credentials (e.g., redis://:password@host:port/db) in production."
        )
    if not (s.SMTP_HOST or "").strip() or not (s.SMTP_FROM_EMAIL or "").strip() or not (s.SMTP_PASSWORD or "").strip():
        raise RuntimeError(
            "SMTP_HOST, SMTP_FROM_EMAIL, and SMTP_PASSWORD are required in production "
            "so password-reset codes and team invitations are actually delivered."
        )
    if (s.TRUSTED_PROXIES or "").strip() in ("", "*"):
        raise RuntimeError("TRUSTED_PROXIES must list explicit proxy IPs or CIDRs in production. '*' is not allowed.")
    if s.SECRET_KEY in _INSECURE_SECRET_DEFAULTS or len(s.SECRET_KEY) < 32 or _contains_placeholder(s.SECRET_KEY):
        raise RuntimeError(
            "SECRET_KEY must be set to a strong random value (>=32 chars) in production. "
            'Generate one with: python -c "import secrets; print(secrets.token_urlsafe(48))"'
        )
    primary_fernet_key = (s.SIGNING_SECRET_ENCRYPTION_KEY or "").split(",")[0].strip()
    if primary_fernet_key in _INSECURE_FERNET_DEFAULTS or _contains_placeholder(s.SIGNING_SECRET_ENCRYPTION_KEY):
        raise RuntimeError(
            "SIGNING_SECRET_ENCRYPTION_KEY uses the public dev default, a committed repository key, "
            "or an un-generated CHANGE_ME placeholder. "
            'Generate one with: python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"'
        )
    if not s.API_KEY_PEPPER or len(s.API_KEY_PEPPER) < 16 or _contains_placeholder(s.API_KEY_PEPPER):
        raise RuntimeError(
            "API_KEY_PEPPER must be set to a strong random value (>=16 chars) in production. "
            'Generate one with: python -c "import secrets; print(secrets.token_urlsafe(32))"'
        )
    if (
        any(substr in s.DATABASE_URL for substr in _INSECURE_DB_SUBSTRINGS)
        or _contains_placeholder(s.DATABASE_URL)
        or _contains_placeholder((s.DATABASE_URL.split("@")[0] if "@" in s.DATABASE_URL else s.DATABASE_URL))
    ):
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
    if not s.METRICS_API_KEY or len(s.METRICS_API_KEY) < 16 or _contains_placeholder(s.METRICS_API_KEY):
        raise RuntimeError("METRICS_API_KEY must be set (>=16 chars) in production to protect /metrics.")
    if _contains_placeholder(s.SMTP_PASSWORD) or _contains_placeholder(_redis):
        raise RuntimeError(
            "Production secrets still contain CHANGE_ME/example placeholders. "
            "Generate real values (see .env.example) and re-deploy."
        )
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
    # Email transport sanity: both TLS and SSL on is a common 465 mistake that
    # silently takes the SSL branch; both off sends creds in plaintext.
    if s.SMTP_USE_TLS and s.SMTP_USE_SSL:
        raise RuntimeError(
            "SMTP_USE_TLS and SMTP_USE_SSL cannot both be True (port 465 = SSL True/TLS False; "
            "port 587 = TLS True/SSL False)."
        )
    if (s.SMTP_PASSWORD or "").strip() and not (s.SMTP_USERNAME or "").strip():
        raise RuntimeError(
            "SMTP_USERNAME is required when SMTP_PASSWORD is set (password would otherwise be silently ignored)."
        )
    # Invitation links are built from PUBLIC_BASE_URL; empty falls back to Host:
    # header (poisonable). Require explicit https origin in production.
    _base = (s.PUBLIC_BASE_URL or "").strip()
    if not _base:
        raise RuntimeError(
            "PUBLIC_BASE_URL must be set in production (e.g. https://hooks.example.com) "
            "so invitation emails cannot be Host-header poisoned."
        )
    if not _base.lower().startswith("https://"):
        raise RuntimeError("PUBLIC_BASE_URL must be an https:// origin in production.")
    # Test-only OTP sink must never hold live codes in prod memory.
    if s.PASSWORD_RESET_OTP_CAPTURE:
        raise RuntimeError("PASSWORD_RESET_OTP_CAPTURE must be False in production (holds live OTPs in memory).")
    # LEGAL_HOLD_PROJECT_IDS is parsed as CSV; validate shape early.
    _hold_raw = getattr(s, "LEGAL_HOLD_PROJECT_IDS", "") or ""
    if isinstance(_hold_raw, str) and len(_hold_raw) > 4096:
        raise RuntimeError("LEGAL_HOLD_PROJECT_IDS is too long (max 4096 chars).")
    # Registration must stay closed in production. The prod overlay hardcodes
    # False; this validator is defense-in-depth if env is injected directly.
    if bool(getattr(s, "ALLOW_OPEN_REGISTRATION", False)):
        raise RuntimeError(
            "ALLOW_OPEN_REGISTRATION must be False in production. "
            "Create the first owner with scripts/bootstrap_admin.py instead."
        )
    # Redis dual-password drift: compose uses REDIS_PASSWORD for the server and
    # REDIS_URL for the app. Mismatch = boot loop. Validate when both are set.
    try:
        import os as _os_red
        import urllib.parse as _up

        _env_redis_pw = (_os_red.getenv("REDIS_PASSWORD", "") or "").strip()
        if _env_redis_pw:
            _parsed = _up.urlparse(_redis)
            _url_pw = (_parsed.password or "").strip() if hasattr(_parsed, "password") else ""
            # URL-encoded passwords must match after decoding.
            try:
                _url_pw = _up.unquote(_url_pw)
            except Exception:
                pass
            if _url_pw and _url_pw != _env_redis_pw:
                raise RuntimeError(
                    "REDIS_URL password does not match REDIS_PASSWORD. "
                    "Set REDIS_URL=redis://:<REDIS_PASSWORD>@redis:6379/0 consistently."
                )
    except RuntimeError:
        raise
    except Exception:
        pass
    # Trusted proxies must be explicit and narrow. Broad /8 + /12 defaults let
    # any VPC/bridge peer forge X-Forwarded-For (rate-limit bypass, audit poisoning).
    # Require prefixlen >= 16 and reject the legacy broad default combo.
    try:
        import ipaddress as _ip

        _tp_raw = (s.TRUSTED_PROXIES or "").strip()
        _tp_parts = [p.strip() for p in _tp_raw.split(",") if p.strip()]
        if "10.0.0.0/8" in _tp_parts:
            raise RuntimeError(
                "TRUSTED_PROXIES contains 10.0.0.0/8 which is too broad (any 10/8 peer can spoof XFF). "
                "Set narrow CIDRs, e.g. TRUSTED_PROXIES=127.0.0.1,::1,172.18.0.0/24 "
                "(docker bridge / nginx IP)."
            )
        for _part in _tp_parts:
            if _part == "*" or _part in ("127.0.0.1", "::1", "localhost"):
                continue
            try:
                if "/" in _part:
                    _net = _ip.ip_network(_part, strict=False)
                    if _net.prefixlen < 16:
                        raise RuntimeError(
                            f"TRUSTED_PROXIES entry '{_part}' is too broad (prefixlen < 16). "
                            "Use /16 or narrower (e.g. /24 or /32 for the proxy IP)."
                        )
            except ValueError:
                # Non-CIDR single IPs are fine (exact match).
                pass
    except RuntimeError:
        raise
    except Exception:
        pass


_IS_PRODUCTION = is_production_env(settings.ENV)
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
