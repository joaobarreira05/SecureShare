from sqlmodel import SQLModel, Field

class RBACToken(SQLModel):
    access_token: str
    token_type: str

class RBACPayload(SQLModel):
    iss: str | None = None
    sub: str | None = None
    exp: int | None = None
    app_role: str | None = None
    iat: int | None = None

class JWTRBACToken(SQLModel, table=True):
    id: str = Field(primary_key=True, description="JTI: Unique Token Identifier")
    iss: str = Field(description="Issuer: The User ID of the Administrator or Security Officer who signed this role assignment.")
    sub: str = Field(description="Subject: The User ID of the person this role applies to.")
    exp: int = Field(description="Expiration Time: Roles are typically long-lived but may be time-limited.")
    app_role: str = Field(description="The Role being assigned (e.g., Administrator, Security Officer, Trusted Officer, Auditor).")
    signed_jwt: str = Field(description="Raw signed JWT string.")
