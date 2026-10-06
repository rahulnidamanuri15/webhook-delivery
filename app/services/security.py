import hashlib
import secrets
from typing import Tuple, Optional
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from cryptography.fernet import Fernet
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from app.config import settings

ph = PasswordHasher()
fernet = Fernet(settings.SIGNING_SECRET_ENCRYPTION_KEY.encode())
serializer = URLSafeTimedSerializer(settings.SECRET_KEY, salt="wh_session_salt")
csrf_serializer = URLSafeTimedSerializer(settings.SECRET_KEY, salt="wh_csrf_salt")

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
    return fernet.encrypt(plain_secret.encode("utf-8")).decode("utf-8")

def decrypt_secret(encrypted_secret: str) -> str:
    return fernet.decrypt(encrypted_secret.encode("utf-8")).decode("utf-8")

# --- Project-Scoped API Keys ---
def generate_api_key() -> Tuple[str, str, str]:
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

def hash_api_key(key: str) -> str:
    return hashlib.sha256(key.strip().encode("utf-8")).hexdigest()

# --- Sessions & CSRF ---
# Server-side logout invalidation via token denylist.
# Stateless signed cookies cannot be revoked without server state, so logout
# adds the token hash to a denylist (Redis when available, else in-memory)
# until its natural 7-day expiry.
import time as _time

_denied_session_hashes: dict[str, float] = {}
_redis_denylist = None
try:
    import redis as _redis_mod
    from app.config import settings as _settings
    _r = _redis_mod.from_url(_settings.REDIS_URL, socket_connect_timeout=0.2)
    _r.ping()
    _redis_denylist = _r
except Exception:
    _redis_denylist = None


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def invalidate_session_token(token: str) -> None:
    """Adds a session token to the logout denylist until its max_age elapses."""
    if not token:
        return
    h = _hash_token(token)
    expiry = int(_time.time()) + 86400 * 7
    if _redis_denylist is not None:
        try:
            _redis_denylist.setex(f"session_denylist:{h}", 86400 * 7, "1")
            return
        except Exception:
            pass
    _denied_session_hashes[h] = float(expiry)


def is_session_token_denied(token: str) -> bool:
    if not token:
        return False
    h = _hash_token(token)
    if _redis_denylist is not None:
        try:
            if _redis_denylist.exists(f"session_denylist:{h}"):
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

def create_session_token(user_id: str, org_id: Optional[str] = None, project_id: Optional[str] = None) -> str:
    data = {
        "user_id": user_id,
        "org_id": org_id,
        "project_id": project_id
    }
    return serializer.dumps(data)

def verify_session_token(token: str, max_age: int = 86400 * 7) -> Optional[dict]:
    if not token or is_session_token_denied(token):
        return None
    try:
        return serializer.loads(token, max_age=max_age)
    except (BadSignature, SignatureExpired):
        return None

def generate_csrf_token(session_id: str) -> str:
    return csrf_serializer.dumps({"session_id": session_id})

def verify_csrf_token(csrf_token: str, session_id: str, max_age: int = 3600) -> bool:
    try:
        data = csrf_serializer.loads(csrf_token, max_age=max_age)
        return data.get("session_id") == session_id
    except (BadSignature, SignatureExpired, Exception):
        return False

def get_csrf_token_for_request(request, response = None) -> Tuple[str, Optional[str]]:
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

def validate_request_csrf(request, form_csrf_token: Optional[str] = None) -> bool:
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

