import re as _re
from datetime import datetime

from pydantic import BaseModel, EmailStr, Field, field_validator


class UserRegister(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8, max_length=128, description="8..128 chars, 3 of: upper/lower/digit/symbol")

    @field_validator("password")
    @classmethod
    def _enforce_complexity(cls, v: str) -> str:
        # Mirrors the dashboard registration rule (views.py): 3 of 4 classes.
        classes = sum(
            [
                bool(_re.search(r"[A-Z]", v)),
                bool(_re.search(r"[a-z]", v)),
                bool(_re.search(r"[0-9]", v)),
                bool(_re.search(r"[^A-Za-z0-9]", v)),
            ]
        )
        if classes < 3:
            raise ValueError("Password must include 3 of: uppercase, lowercase, digit, symbol.")
        return v


class UserLogin(BaseModel):
    email: EmailStr
    password: str


class UserResponse(BaseModel):
    id: str
    email: str
    created_at: datetime

    class Config:
        from_attributes = True


class ProjectCreate(BaseModel):
    name: str = Field(min_length=1, max_length=100)


class ProjectResponse(BaseModel):
    id: str
    organization_id: str
    name: str
    created_at: datetime

    class Config:
        from_attributes = True


class ApiKeyCreate(BaseModel):
    name: str = Field(min_length=1, max_length=100)


class ApiKeyResponse(BaseModel):
    id: str
    project_id: str
    name: str
    key_prefix: str
    created_at: datetime
    revoked_at: datetime | None = None
    is_active: bool

    class Config:
        from_attributes = True


class ApiKeyCreatedResponse(ApiKeyResponse):
    full_key: str  # Only returned upon initial creation!
