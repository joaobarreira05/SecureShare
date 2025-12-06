from sqlmodel import Session
from ..models.Audit import AuditLog
from datetime import datetime, timezone
from typing import Optional

def log_event(db: Session, actor_id: int, action: str, details: Optional[str] = None) -> AuditLog:
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
        actor_id=actor_id,
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

def create_validation_entry(db: Session, auditor_id: int, log_id: int, signature: str) -> AuditLog:
    """
    Creates a new audit log entry to record the validation of a previous entry.
    """
    # Verify the log entry exists
    log_entry = db.get(AuditLog, log_id)
    if not log_entry:
        return None

    # Create a new log entry for the validation event
    # We store the signature of the validated entry in the details
    details = f"Validated Log ID: {log_id}. Signature: {signature}"
    
    return log_event(db, auditor_id, "LOG_VALIDATION", details)