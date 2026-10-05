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
def create_session_token(user_id: str, org_id: Optional[str] = None, project_id: Optional[str] = None) -> str:
    data = {
        "user_id": user_id,
        "org_id": org_id,
        "project_id": project_id
    }
    return serializer.dumps(data)

def verify_session_token(token: str, max_age: int = 86400 * 7) -> Optional[dict]:
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
