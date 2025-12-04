from enum import Enum
from datetime import datetime
from typing import List, Optional
from uuid import UUID, uuid4
from sqlmodel import SQLModel, Field, Relationship
from sqlalchemy import Column, String

class SecurityLevel(str, Enum):
    TOP_SECRET = "TOP_SECRET"
    SECRET = "SECRET"
    CONFIDENTIAL = "CONFIDENTIAL"
    UNCLASSIFIED = "UNCLASSIFIED"

class Transfer(SQLModel, table=True):
    __tablename__ = "transfers"

    id: UUID = Field(default_factory=uuid4, primary_key=True, index=True)
    uploader_id: int = Field(foreign_key="users.id")
    blob_path: str
    filename: str
    classification_level: SecurityLevel
    departments: str  # Stored as JSON string
    is_public: bool = Field(default=False)
    expires_at: Optional[datetime] = None

    keys: List["TransferKey"] = Relationship(back_populates="transfer")

class TransferKey(SQLModel, table=True):
    __tablename__ = "transfer_keys"

    id: Optional[int] = Field(default=None, primary_key=True)
    transfer_id: UUID = Field(foreign_key="transfers.id")
    recipient_id: int = Field(foreign_key="users.id")
    encrypted_key: str  # Base64 encoded encrypted key

    transfer: Transfer = Relationship(back_populates="keys")