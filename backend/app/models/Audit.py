from datetime import datetime, timezone
from typing import Optional
from sqlmodel import Field, SQLModel
import hashlib
import json

class AuditLog(SQLModel, table=True):
    __tablename__ = "audit_logs"

    id: Optional[int] = Field(default=None, primary_key=True)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc).replace(microsecond=0))
    actor_username: str = Field(index=True)
    action: str
    details: str  # JSON dump
    signature: Optional[str] = Field(default=None)
    previous_hash: str
    current_hash: str

    def calculate_hash(self) -> str:
        
        
        ts_str = self.timestamp.replace(tzinfo=None).isoformat()
        
        data = (
            self.previous_hash +
            ts_str +
            self.actor_username +
            self.action +
            self.details
        )
        return hashlib.sha256(data.encode("utf-8")).hexdigest()

class AuditValidationRequest(BaseModel):
    log_id: int
    signature: str