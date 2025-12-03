from sqlmodel import SQLModel, Field
from datetime import datetime

class Token(SQLModel):
    access_token: str # JWT Token
    token_type: str # Token type

class TokenPayload(SQLModel):
    sub: str | None = None # User ID
    exp: int | None = None # Expiration time
    iat: int | None = None # Issued at time

class JWTAuthToken(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    access_token: str = Field(index=True)
    user_id: int = Field(index=True)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    expires_at: datetime
    is_active: bool = Field(default=True)
