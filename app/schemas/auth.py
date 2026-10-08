from datetime import datetime

from pydantic import BaseModel, EmailStr, Field


class UserRegister(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8, description="Minimum 8 characters")


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
