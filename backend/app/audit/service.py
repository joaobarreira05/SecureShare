from sqlmodel import Session, select
from app.models.Audit import AuditLog, AuditCheckpoint
from datetime import datetime, timezone

def log_event(db: Session, actor_id: int, action: str, details: str) -> AuditLog:
    """
    Logs a new event to the AuditLog chain.
    """
    # 1. Query the last entry in AuditLog
    statement = select(AuditLog).order_by(AuditLog.id.desc()).limit(1)
    last_entry = db.exec(statement).first()

    # 2. Determine previous_hash
    if last_entry:
        previous_hash = last_entry.current_hash
    else:
        # Genesis block: use 64 zeros
        previous_hash = "0" * 64

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

def verify_signature(public_key: str, data_hash: str, signature: str) -> bool:
    """
    Mock signature verification.
    In a real system, this would verify the digital signature.
    """
    # TODO: Implement actual signature verification
    return True

def validate_chain(db: Session):
    """
    Validates the integrity of the AuditLog chain.
    Returns (True, None) if valid.
    Returns (False, broken_log_id) if invalid.
    """
    # 1. Fetch the latest AuditCheckpoint
    checkpoint_stmt = select(AuditCheckpoint).order_by(AuditCheckpoint.id.desc()).limit(1)
    checkpoint = db.exec(checkpoint_stmt).first()

    start_index = 0
    expected_prev_hash = "0" * 64

    if checkpoint:
        # Verify signature (Mock)
        # We don't have the auditor's public key handy here easily without querying User, 
        # but for now we mock the verification function anyway.
        if not verify_signature("mock_key", checkpoint.logged_hash, checkpoint.signature):
             # Checkpoint signature invalid - this is a different kind of error, 
             # but strictly speaking the chain from this point is untrusted.
             # We could return a special error or just fail.
             # For simplicity, let's treat it as a validation failure at the checkpoint's log_id.
             return False, checkpoint.log_id

        # Verify the checkpoint's logged_hash matches the actual current_hash of the referenced AuditLog ID
        referenced_log = db.get(AuditLog, checkpoint.log_id)
        if not referenced_log or referenced_log.current_hash != checkpoint.logged_hash:
            return False, checkpoint.log_id

        start_index = checkpoint.log_id
        expected_prev_hash = checkpoint.logged_hash

    # 2. Iterate through all AuditLog entries starting after the start_index
    # We need to fetch them in order of ID
    query = select(AuditLog).where(AuditLog.id > start_index).order_by(AuditLog.id.asc())
    logs = db.exec(query).all()

    for entry in logs:
        # Verify entry.previous_hash == expected_prev_hash
        if entry.previous_hash != expected_prev_hash:
            return False, entry.id

        # Recalculate the hash
        calculated_hash = entry.calculate_hash()
        if calculated_hash != entry.current_hash:
            return False, entry.id

        # Update expected_prev_hash for the next iteration
        expected_prev_hash = entry.current_hash

    return True, None
