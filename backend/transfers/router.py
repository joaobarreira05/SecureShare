from uuid import UUID

from fastapi import APIRouter, Depends, UploadFile, File, Form, status
from fastapi.responses import StreamingResponse
from sqlmodel import Session

from app.models.Transfer import SecurityLevel
from app.core.database import get_session
from transfers.dependencies import get_current_user
from transfers import service

router = APIRouter(prefix="/transfers", tags=["transfers"])

@router.post("", status_code=status.HTTP_201_CREATED)
async def create_transfer(
    file: UploadFile = File(...),
    classification: SecurityLevel = Form(...),
    departments: str = Form(...), # JSON string
    recipient_keys: str = Form(...), # JSON string
    expires_in_days: int = Form(7),
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_session)
):
    transfer_id = service.create_transfer_service(
        db=db,
        user=current_user,
        file=file,
        classification=classification,
        departments=departments,
        recipient_keys=recipient_keys,
        expires_in_days=expires_in_days
    )
    return {"transfer_id": transfer_id}

@router.get("/{transfer_id}")
async def get_transfer_metadata(
    transfer_id: UUID,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_session)
):
    return service.get_transfer_metadata_service(db, current_user, transfer_id)

@router.get("/download/{transfer_id}")
async def download_encrypted_blob(
    transfer_id: UUID,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_session)
):
    iterfile = service.get_transfer_file_stream_service(db, current_user, transfer_id)
    return StreamingResponse(iterfile, media_type="application/octet-stream")

@router.get("")
async def list_user_transfers(
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_session)
):
    return service.list_user_transfers_service(db, current_user)

@router.delete("/{transfer_id}")
async def delete_transfer(
    transfer_id: UUID,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_session)
):
    service.delete_transfer_service(db, current_user, transfer_id)
    return {"detail": "Transfer deleted"}
