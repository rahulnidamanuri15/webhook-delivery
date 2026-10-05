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
    
    # Retry & Delivery policies
    MAX_DELIVERY_ATTEMPTS: int = 5
    HTTP_TIMEOUT_SECONDS: float = 10.0
    LEASE_DURATION_SECONDS: int = 30
    DEFAULT_RETRY_INTERVALS: list[int] = [5, 15, 60, 300, 900]
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

# Ensure signing secret key is valid Fernet key
try:
    Fernet(settings.SIGNING_SECRET_ENCRYPTION_KEY.encode())
except Exception:
    # Generate fallback valid Fernet key in dev
    settings.SIGNING_SECRET_ENCRYPTION_KEY = Fernet.generate_key().decode()
