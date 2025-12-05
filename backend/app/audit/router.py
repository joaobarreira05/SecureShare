from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlmodel import Session, select
from typing import List
from app.core.database import get_session
from app.auth.service import get_current_user
from app.models.User import User
from app.models.Audit import AuditLog
from app.audit.service import validate_chain, add_log_signature

router = APIRouter(
    prefix="/audit",
    tags=["audit"],
    responses={404: {"description": "Not found"}},
)

@router.get("/log", response_model=List[AuditLog])
def get_audit_logs(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_session)
):
    return db.query(AuditLog).order_by(AuditLog.id.asc()).all()

@router.put("/validate")
def validate_audit_log_entry(
    request: AuditValidationRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_session)
):
    updated_log = add_log_signature(db, request.log_id, request.signature)
    if not updated_log:
        raise HTTPException(status_code=404, detail="Log entry not found")
    return updated_log