from sqlmodel import Field, SQLModel
from pydantic import EmailStr

# ==========================================
# SQLModel (Database Entity + Base Pydantic)
# ==========================================
class User(SQLModel, table=True):
    __tablename__ = "users"

    id: int | None = Field(default=None, primary_key=True)
    username: str = Field(unique=True, index=True, nullable=False)
    hashed_password: str | None = Field(default=None, nullable=True) # Nullable until activation
    full_name: str | None = Field(default=None, nullable=True)
    email: str | None = Field(default=None, unique=True, index=True, nullable=True)
    is_active: bool = Field(default=False)
    is_admin: bool = Field(default=False)
    otp_hash: str | None = Field(default=None, nullable=True)
    public_key: str | None = Field(default=None, nullable=True)
    encrypted_private_key: str | None = Field(default=None, nullable=True)

# ==========================================
# Pydantic Models (DTOs)
# ==========================================

# Properties to receive via API on creation (Admin)
class UserCreate(SQLModel):
    username: str
    otp: str
    email: EmailStr | None = None
    full_name: str | None = None

# Properties to receive via API on activation (User)
class UserActivate(SQLModel):
    username: str
    otp: str
    password: str
    public_key: str
    encrypted_private_key: str

# Properties to receive via API on login
class LoginRequest(SQLModel):
    username: str
    password: str

# Properties to return via API
class UserResponse(SQLModel):
    id: int
    username: str
    email: str | None = None
    full_name: str | None = None
    is_active: bool
    is_admin: bool

# Vault Content
class VaultContent(SQLModel):
    encrypted_private_key: str

class VaultUpdate(SQLModel):
    encrypted_private_key: str

class UserUpdate(SQLModel):
    full_name: str | None = None
    email: EmailStr | None = None
    password: str | None = None

from .JWTRBACToken import JWTRBACToken
from .JWTMLSToken import JWTMLSToken

class UserClearanceResponse(SQLModel):
    mls_tokens: list[JWTMLSToken]
    rbac_tokens: list[JWTRBACToken]
