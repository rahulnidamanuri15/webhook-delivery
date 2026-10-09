import hashlib
import secrets

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from cryptography.fernet import Fernet, InvalidToken, MultiFernet
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer

from app.config import get_configured_fernet_keys, settings

ph = PasswordHasher()
serializer = URLSafeTimedSerializer(settings.SECRET_KEY, salt="wh_session_salt")
csrf_serializer = URLSafeTimedSerializer(settings.SECRET_KEY, salt="wh_csrf_salt")


class SecretDecryptionError(RuntimeError):
    """Raised when an encrypted secret cannot be decrypted by any configured Fernet key."""

    pass


_cached_fernet_keys: tuple[str, ...] | None = None
_cached_multi_fernet: MultiFernet | None = None


def get_multi_fernet() -> MultiFernet:
    """Returns a MultiFernet instance initialized with the primary key and all fallback keys."""
    global _cached_fernet_keys, _cached_multi_fernet
    keys = tuple(get_configured_fernet_keys(settings))
    if not keys:
        raise RuntimeError("No Fernet encryption keys configured.")
    if _cached_multi_fernet is None or _cached_fernet_keys != keys:
        _cached_multi_fernet = MultiFernet([Fernet(k.encode("utf-8")) for k in keys])
        _cached_fernet_keys = keys
    return _cached_multi_fernet


# Backward-compatibility alias
def get_fernet() -> MultiFernet:
    return get_multi_fernet()


# --- Password Management (Argon2id) ---
def hash_password(password: str) -> str:
    return ph.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    try:
        return ph.verify(hashed_password, plain_password)
    except (VerifyMismatchError, Exception):
        return False


# --- Endpoint Secret Encryption (Fernet / AES-128-CBC) ---
def generate_signing_secret() -> str:
    """Generate a high-entropy secret for an endpoint (e.g. whsec_...)."""
    return f"whsec_{secrets.token_hex(24)}"


def encrypt_secret(plain_secret: str) -> str:
    """Always encrypts using the primary Fernet key."""
    return get_multi_fernet().encrypt(plain_secret.encode("utf-8")).decode("utf-8")


def decrypt_secret(encrypted_secret: str) -> str:
    """Decrypts ciphertext using the primary key, falling back to secondary keys in order.

    Raises SecretDecryptionError if no configured key can decrypt the ciphertext.
    """
    if not encrypted_secret:
        raise SecretDecryptionError("Empty encrypted secret provided.")
    try:
        return get_multi_fernet().decrypt(encrypted_secret.encode("utf-8")).decode("utf-8")
    except (InvalidToken, Exception) as e:
        raise SecretDecryptionError(
            f"Failed to decrypt signing secret: {type(e).__name__} (key mismatch or corrupted ciphertext). "
            "Verify SIGNING_SECRET_ENCRYPTION_KEY or configure SIGNING_SECRET_ENCRYPTION_KEYS_FALLBACK."
        ) from e


def rotate_secret_ciphertext(encrypted_secret: str) -> tuple[str, bool]:
    """Re-encrypts ciphertext with the primary key IF it was encrypted with a fallback key.

    Returns:
        (new_ciphertext, was_rotated)
        If already encrypted with primary key or invalid, returns (encrypted_secret, False).
    """
    if not encrypted_secret:
        return encrypted_secret, False
    try:
        mf = get_multi_fernet()
        primary_fernet = mf._fernets[0]
        # Fast-path: if primary key can decrypt, it's already using primary key
        try:
            primary_fernet.decrypt(encrypted_secret.encode("utf-8"))
            return encrypted_secret, False
        except (InvalidToken, Exception):
            pass

        # Decrypted with fallback key: rotate to primary key
        rotated = mf.rotate(encrypted_secret.encode("utf-8")).decode("utf-8")
        return rotated, True
    except Exception:
        return encrypted_secret, False


# --- Project-Scoped API Keys ---
def generate_api_key() -> tuple[str, str, str]:
    """
    Returns:
        (full_key, key_prefix, key_hash)
        full_key: e.g. wh_live_a1b2c3d4e5f6... (shown only once to user)
        key_prefix: e.g. wh_live_a1b2c3d4 (for identifying the key in dashboard)
        key_hash: SHA-256 hex digest stored in database
    """
    random_part = secrets.token_hex(24)
    full_key = f"wh_live_{random_part}"
    key_prefix = full_key[:16]
    key_hash = hash_api_key(full_key)
    return full_key, key_prefix, key_hash


def _pepper() -> str:
    try:
        from app.config import settings as _s

        return (_s.API_KEY_PEPPER or "").strip()
    except Exception:
        return ""


def hash_api_key(key: str) -> str:
    """HMAC-SHA256 with server pepper when configured, else legacy plain SHA-256.

    New deployments should set API_KEY_PEPPER. Lookup tries peppered first,
    then legacy, so existing keys keep working after enabling a pepper.
    """
    raw = key.strip().encode("utf-8")
    pepper = _pepper()
    if pepper:
        import hmac as _hmac

        return _hmac.new(pepper.encode("utf-8"), raw, hashlib.sha256).hexdigest()
    return hashlib.sha256(raw).hexdigest()


def hash_api_key_candidates(key: str) -> list[str]:
    """All hashes to try on lookup (peppered + legacy) for zero-downtime rotation."""
    raw = key.strip().encode("utf-8")
    pepper = _pepper()
    out: list[str] = []
    if pepper:
        import hmac as _hmac

        out.append(_hmac.new(pepper.encode("utf-8"), raw, hashlib.sha256).hexdigest())
    out.append(hashlib.sha256(raw).hexdigest())
    # Deduplicate while preserving order
    seen: set[str] = set()
    uniq: list[str] = []
    for h in out:
        if h not in seen:
            seen.add(h)
            uniq.append(h)
    return uniq


def hash_invitation_token(raw_token: str) -> str:
    """Returns SHA-256 hex digest of the raw invitation token for secure at-rest storage."""
    return hashlib.sha256(raw_token.strip().encode("utf-8")).hexdigest()


def hash_invitation_token_candidates(raw_token: str) -> list[str]:
    """Returns candidate token representations (hashed first, legacy raw fallback)."""
    clean = raw_token.strip()
    return [hash_invitation_token(clean), clean]


# --- Sessions & CSRF ---
# Server-side logout invalidation via token denylist.
# Stateless signed cookies cannot be revoked without server state, so logout
# adds the token hash to a denylist (Redis when available, else in-memory)
# until its natural 7-day expiry.
import time as _time

_denied_session_hashes: dict[str, float] = {}
_redis_denylist = None


def _get_redis_client():
    global _redis_denylist
    if _redis_denylist is not None:
        return _redis_denylist
    try:
        import redis as _redis_mod

        from app.config import settings as _settings

        _r = _redis_mod.from_url(_settings.REDIS_URL, socket_connect_timeout=0.3, socket_timeout=0.3)
        _r.ping()
        _redis_denylist = _r
        return _redis_denylist
    except Exception:
        return None


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


_denied_user_session_timestamps: dict[str, float] = {}


def invalidate_session_token(token: str) -> None:
    """Adds a session token to the logout denylist until its max_age elapses."""
    if not token:
        return
    h = _hash_token(token)
    expiry = int(_time.time()) + 86400 * 7
    r = _get_redis_client()
    if r is not None:
        try:
            r.setex(f"session_denylist:{h}", 86400 * 7, "1")
            return
        except Exception:
            pass
    _denied_session_hashes[h] = float(expiry)


def invalidate_all_user_sessions(user_id: str) -> None:
    """Invalidates all sessions issued for user_id prior to this moment (e.g. on password reset)."""
    if not user_id:
        return
    now_ts = _time.time()
    r = _get_redis_client()
    if r is not None:
        try:
            r.setex(f"user_session_revoked_at:{user_id}", 86400 * 7, str(now_ts))
        except Exception:
            pass
    _denied_user_session_timestamps[user_id] = float(now_ts)


def is_user_session_revoked(user_id: str, token_timestamp: float) -> bool:
    if not user_id:
        return False
    r = _get_redis_client()
    if r is not None:
        try:
            val = r.get(f"user_session_revoked_at:{user_id}")
            if val is not None:
                revoked_at = float(val)
                if token_timestamp < revoked_at:
                    return True
        except Exception:
            pass
    revoked_at = _denied_user_session_timestamps.get(user_id)
    if revoked_at is not None:
        if _time.time() > revoked_at + (86400 * 7):
            _denied_user_session_timestamps.pop(user_id, None)
        elif token_timestamp < revoked_at:
            return True
    return False


def is_session_token_denied(token: str) -> bool:
    if not token:
        return False
    h = _hash_token(token)
    r = _get_redis_client()
    if r is not None:
        try:
            if r.exists(f"session_denylist:{h}"):
                return True
        except Exception:
            pass
    exp = _denied_session_hashes.get(h)
    if exp is None:
        return False
    if _time.time() > exp:
        _denied_session_hashes.pop(h, None)
        return False
    return True


def create_session_token(user_id: str, org_id: str | None = None, project_id: str | None = None) -> str:
    data = {"user_id": user_id, "org_id": org_id, "project_id": project_id}
    return serializer.dumps(data)


def verify_session_token(token: str, max_age: int = 86400 * 7) -> dict | None:
    if not token or is_session_token_denied(token):
        return None
    try:
        data, ts = serializer.loads(token, max_age=max_age, return_timestamp=True)
        if not isinstance(data, dict):
            return None
        token_ts = ts.timestamp() if hasattr(ts, "timestamp") else float(ts)
        user_id = data.get("user_id")
        if user_id and is_user_session_revoked(user_id, token_ts):
            return None
        return data
    except (BadSignature, SignatureExpired, Exception):
        return None


def generate_csrf_token(session_id: str) -> str:
    return csrf_serializer.dumps({"session_id": session_id})


def verify_csrf_token(csrf_token: str, session_id: str, max_age: int = 3600) -> bool:
    try:
        data = csrf_serializer.loads(csrf_token, max_age=max_age)
        return data.get("session_id") == session_id
    except (BadSignature, SignatureExpired, Exception):
        return False


def get_csrf_token_for_request(request, response=None) -> tuple[str, str | None]:
    """
    Returns (csrf_token, new_cookie_id_to_set).
    Binds the CSRF token to wh_session if present, or to an anonymous wh_csrf_id cookie.
    """
    session_token = request.cookies.get("wh_session")
    if session_token:
        return generate_csrf_token(session_token), None

    csrf_id = request.cookies.get("wh_csrf_id")
    new_cookie = None
    if not csrf_id:
        csrf_id = secrets.token_hex(16)
        new_cookie = csrf_id
    return generate_csrf_token(csrf_id), new_cookie


def validate_request_csrf(request, form_csrf_token: str | None = None) -> bool:
    """Validates the CSRF token against the request's session or anonymous cookie."""
    if not form_csrf_token:
        # Check header as fallback
        form_csrf_token = request.headers.get("x-csrf-token")
    if not form_csrf_token:
        return False

    session_token = request.cookies.get("wh_session")
    session_id = session_token if session_token else request.cookies.get("wh_csrf_id")
    if not session_id:
        return False
    return verify_csrf_token(form_csrf_token, session_id)


def _is_trusted_proxy(ip_str: str) -> bool:
    if not ip_str:
        return False
    # Local loopback and testclient are trusted by default
    if ip_str in ("127.0.0.1", "::1", "localhost", "testclient"):
        return True
    import ipaddress

    trusted_raw = getattr(settings, "TRUSTED_PROXIES", "127.0.0.1,::1") or "127.0.0.1,::1"
    trusted_list = [p.strip() for p in trusted_raw.split(",") if p.strip()]
    for pattern in trusted_list:
        if pattern == "*" or pattern == ip_str:
            return True
        try:
            if "/" in pattern:
                if ipaddress.ip_address(ip_str) in ipaddress.ip_network(pattern, strict=False):
                    return True
            else:
                if ipaddress.ip_address(ip_str) == ipaddress.ip_address(pattern):
                    return True
        except ValueError:
            pass
    return False


def get_client_ip(request) -> str:
    """Safely extracts client IP.
    Only trusts X-Forwarded-For and X-Real-IP if the direct connecting peer is a trusted proxy.
    On direct exposure, returns request.client.host directly to prevent IP header spoofing.
    """
    if not request:
        return "127.0.0.1"

    direct_ip = "127.0.0.1"
    client_obj = getattr(request, "client", None)
    if client_obj is not None:
        host = getattr(client_obj, "host", None)
        if isinstance(host, str) and host:
            direct_ip = host

    # Only inspect forwarded headers if incoming connection comes from trusted reverse proxy
    if _is_trusted_proxy(direct_ip):
        headers = getattr(request, "headers", {})
        xff = headers.get("x-forwarded-for") if hasattr(headers, "get") else None
        if xff:
            parts = [p.strip() for p in xff.split(",") if p.strip()]
            if parts:
                return parts[0]
        x_real = headers.get("x-real-ip") if hasattr(headers, "get") else None
        if x_real and x_real.strip():
            return x_real.strip()

    return direct_ip
