from sqlmodel import SQLModel, Field
from datetime import datetime

class JWTRevocationToken(SQLModel, table=True):
    token_id: str = Field(primary_key=True, description="A unique identifier (JTI claim) of the original token being revoked.")
    revoker_id: int = Field(description="The User ID of the Security Officer who performed the revocation.")
    timestamp: datetime = Field(description="Time of revocation.")
    signature: str = Field(description="Signature by the Security Officer's private key to ensure revocation integrity.")
