from datetime import datetime, timezone
from typing import Optional
from sqlmodel import Field, SQLModel
import hashlib
import json

class AuditLog(SQLModel, table=True):
    __tablename__ = "audit_logs"

    id: Optional[int] = Field(default=None, primary_key=True)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc).replace(microsecond=0))
    actor_id: int = Field(index=True)
    action: str
    details: str  # JSON dump
    previous_hash: str
    current_hash: str

    def calculate_hash(self) -> str:
        """
        Concatenates previous_hash + timestamp (isoformat) + str(actor_id) + action + details
        and returns the SHA-256 hexdigest.
        """
        # Ensure deterministic behavior by using a consistent timestamp format
        # We assume timestamp is already set.
        # Normalize to naive UTC string to handle DB roundtrip (SQLite stores as string, loses tz)
        ts_str = self.timestamp.replace(tzinfo=None).isoformat()
        
        data = (
            self.previous_hash +
            ts_str +
            str(self.actor_id) +
            self.action +
            self.details
        )
        return hashlib.sha256(data.encode("utf-8")).hexdigest()

class AuditCheckpoint(SQLModel, table=True):
    __tablename__ = "audit_checkpoints"

    id: Optional[int] = Field(default=None, primary_key=True)
    auditor_id: int = Field(foreign_key="users.id")
    log_id: int = Field(foreign_key="audit_logs.id")
    logged_hash: str
    signature: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
