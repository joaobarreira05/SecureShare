from sqlmodel import Field, SQLModel
from datetime import datetime

class JWTMLSToken(SQLModel, table=True):
    token_id: str = Field(primary_key=True) # JTI
    user_id: int = Field(index=True) # Subject (sub)
    issuer_id: int = Field(index=True) # Issuer (iss)
    signed_jwt: str # Raw token string
    expires_at: datetime
