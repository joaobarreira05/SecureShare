from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlmodel import Session, select
from typing import List
from ..core.database import get_session
from ..auth.service import check_if_auditor
from ..models.User import User
from ..models.Audit import AuditLog, AuditValidationRequest
from .service import create_validation_entry

router = APIRouter(
    prefix="/audit",
    tags=["audit"],
    responses={404: {"description": "Not found"}},
)

@router.get("/log", response_model=List[AuditLog])
def get_audit_logs(
    session: Session = Depends(get_session),
    current_auditor: User = Depends(check_if_auditor)
):
    return session.query(AuditLog).order_by(AuditLog.id.asc()).all()

@router.put("/validate")
def validate_audit_log_entry(
    request: AuditValidationRequest,
    current_auditor: User = Depends(check_if_auditor),
    db: Session = Depends(get_session)
):
    # We pass the current_auditor.id as the actor_id for the new log entry
    validation_log = create_validation_entry(db, current_auditor.id, request.log_id, request.signature)
    
    if not validation_log:
        raise HTTPException(status_code=404, detail="Log entry not found")
        
    return validation_log