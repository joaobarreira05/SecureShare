from uuid import UUID
from typing import Optional

from fastapi import APIRouter, Depends, UploadFile, File, Form, status, Header
from fastapi.responses import StreamingResponse
from sqlmodel import Session

from ..models.Transfer import SecurityLevel
from ..models.User import User
from ..core.database import get_session
from ..auth.service import get_current_user, get_current_clearance, check_if_trusted_officer_or_none
from . import service

router = APIRouter(prefix="/transfers", tags=["transfers"])

@router.post("", status_code=status.HTTP_201_CREATED)
async def create_transfer(
    file: UploadFile = File(...),
    classification: SecurityLevel = Form(...),
    departments: str = Form(...), # JSON string
    recipient_keys: str = Form(...), # JSON string
    expires_in_days: int = Form(7),
    current_user: User = Depends(get_current_user),
    mls_payload: Optional[dict] = Depends(get_current_clearance),
    x_justification: Optional[str] = Header(None, alias="X-Justification"),
    is_trusted_officer: bool = Depends(check_if_trusted_officer_or_none),
    db: Session = Depends(get_session)
):
    transfer_id = service.create_transfer_service(
        db=db,
        user=current_user,
        file=file,
        classification=classification,
        departments=departments,
        recipient_keys=recipient_keys,
        expires_in_days=expires_in_days,
        mls_payload=mls_payload,
        justification=x_justification,
        is_trusted_officer=is_trusted_officer
    )
    return {"transfer_id": transfer_id}

@router.get("/{transfer_id}")
async def get_transfer_metadata(
    transfer_id: UUID,
    current_user: User = Depends(get_current_user),
    mls_payload: Optional[dict] = Depends(get_current_clearance),
    x_justification: Optional[str] = Header(None, alias="X-Justification"),
    is_trusted_officer: bool = Depends(check_if_trusted_officer_or_none),
    db: Session = Depends(get_session)
):
    return service.get_transfer_metadata_service(
        db, 
        current_user, 
        transfer_id,
        mls_payload,
        x_justification,
        is_trusted_officer
    )

@router.get("/download/{transfer_id}")
async def download_encrypted_blob(
    transfer_id: UUID,
    current_user: User = Depends(get_current_user),
    mls_payload: Optional[dict] = Depends(get_current_clearance),
    x_justification: Optional[str] = Header(None, alias="X-Justification"),
    is_trusted_officer: bool = Depends(check_if_trusted_officer_or_none),
    db: Session = Depends(get_session)
):
    iterfile = service.get_transfer_file_stream_service(
        db, 
        current_user, 
        transfer_id,
        mls_payload,
        x_justification,
        is_trusted_officer
    )
    return StreamingResponse(iterfile, media_type="application/octet-stream")

@router.get("")
async def list_user_transfers(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_session)
):
    return service.list_user_transfers_service(db, current_user)

@router.delete("/{transfer_id}")
async def delete_transfer(
    transfer_id: UUID,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_session)
):
    service.delete_transfer_service(db, current_user, transfer_id)
    return {"detail": "Transfer deleted"}
