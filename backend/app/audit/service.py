from sqlmodel import Session, select
from app.models.Audit import AuditLog, AuditCheckpoint
from datetime import datetime, timezone
from typing import Optional

def log_event(db: Session, actor_username: str, action: str, details: str) -> AuditLog:
    """
    Logs a new event to the AuditLog chain.
    """
    last_entry = db.query(AuditLog).order_by(AuditLog.id.desc()).first()

    # 2. Determine previous_hash
    if last_entry:
        previous_hash = last_entry.current_hash
    else:
        previous_hash = "00000000000000000000000000000000"

    # 3. Create the new object
    new_log = AuditLog(
        actor_username=actor_username,
        action=action,
        details=details,
        previous_hash=previous_hash,
        current_hash="", # Placeholder, will be calculated
        timestamp=datetime.now(timezone.utc).replace(microsecond=0)
    )

    # 4. Calculate current_hash
    new_log.current_hash = new_log.calculate_hash()

    # 5. Save and commit
    db.add(new_log)
    db.commit()
    db.refresh(new_log)
    
    return new_log

def add_log_signature(db: Session, log_id: int, signature: str) -> Optional[AuditLog]:
    log_entry = db.get(AuditLog, log_id)
    if not log_entry:
        return None
    
    log_entry.signature = signature
    db.add(log_entry)
    db.commit()
    db.refresh(log_entry)
    return log_entry