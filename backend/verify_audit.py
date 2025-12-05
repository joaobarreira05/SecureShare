import sys
import os
from sqlmodel import Session, select, create_engine, SQLModel, delete
from datetime import datetime

# Add backend to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from app.models.Audit import AuditLog, AuditCheckpoint
from app.models.User import User
from app.audit.service import log_event, validate_chain
from app.core.database import engine

def test_audit_system():
    print("Initializing DB...")
    SQLModel.metadata.create_all(engine)
    
    with Session(engine) as db:
        # Clear existing data
        print("Clearing old audit data...")
        db.exec(delete(AuditCheckpoint))
        db.exec(delete(AuditLog))
        db.commit()

        # 1. Log some events
        print("Logging events...")
        log1 = log_event(db, actor_id=1, action="LOGIN", details='{"ip": "127.0.0.1"}')
        log2 = log_event(db, actor_id=1, action="FILE_UPLOAD", details='{"file": "secret.txt"}')
        print(f"Logged events: {log1.id}, {log2.id}")
        
        # 2. Validate chain (should be valid)
        print("Validating chain...")
        is_valid, broken_id = validate_chain(db)
        if is_valid:
            print("Chain is VALID (Expected)")
        else:
            print(f"Chain is INVALID at {broken_id} (Unexpected)")
            return

        # 3. Tamper with log
        print("Tampering with log...")
        log1.action = "TAMPERED_ACTION"
        db.add(log1)
        db.commit()
        db.refresh(log1)
        
        # 4. Validate chain (should be invalid)
        print("Validating chain after tampering...")
        is_valid, broken_id = validate_chain(db)
        if not is_valid:
            print(f"Chain is INVALID at {broken_id} (Expected)")
        else:
            print("Chain is VALID (Unexpected - Tampering not detected)")
            return

        # 5. Restore log to fix chain
        print("Restoring log...")
        log1.action = "LOGIN"
        db.add(log1)
        db.commit()
        db.refresh(log1)
        
        # 6. Create Checkpoint
        print("Creating checkpoint...")
        checkpoint = AuditCheckpoint(
            auditor_id=99,
            log_id=log2.id,
            logged_hash=log2.current_hash,
            signature="mock_signature"
        )
        db.add(checkpoint)
        db.commit()
        
        # 7. Validate chain with checkpoint (should be valid)
        print("Validating chain with checkpoint...")
        is_valid, broken_id = validate_chain(db)
        if is_valid:
            print("Chain is VALID with checkpoint (Expected)")
        else:
            print(f"Chain is INVALID at {broken_id} (Unexpected)")
            return

        print("ALL TESTS PASSED")

if __name__ == "__main__":
    test_audit_system()
