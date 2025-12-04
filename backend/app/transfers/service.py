import json
import os
import shutil
from datetime import datetime, timedelta
from typing import List, Optional, Generator
from uuid import UUID

from fastapi import HTTPException, UploadFile, status
from sqlmodel import Session, select

from ..models.Transfer import Transfer, TransferKey, SecurityLevel
from ..models.User import User
from .dependencies import check_mls_write, check_mls_read

STORAGE_DIR = "storage"
os.makedirs(STORAGE_DIR, exist_ok=True)

def create_transfer_service(
    db: Session,
    user: User,
    file: UploadFile,
    classification: SecurityLevel,
    departments: str,
    recipient_keys: str,
    expires_in_days: int,
    mls_payload: Optional[dict] = None,
    justification: Optional[str] = None,
    is_trusted_officer: bool = False
) -> UUID:
    # Parse departments
    try:
        dept_list = json.loads(departments)
        if not isinstance(dept_list, list):
            raise ValueError
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid departments format. Must be a JSON list of strings.")

    # 1. MLS Write Check
    check_mls_write(
        user=user, 
        classification=classification, 
        departments=dept_list,
        mls_payload=mls_payload,
        justification=justification,
        is_trusted_officer=is_trusted_officer
    )

    # 2. Create Transfer Object
    new_transfer = Transfer(
        uploader_id=user.id,
        blob_path="", # Update later
        filename=file.filename,
        classification_level=classification,
        departments=departments,
        is_public=False,
        expires_at=datetime.utcnow() + timedelta(days=expires_in_days)
    )
    
    db.add(new_transfer)
    db.commit()
    db.refresh(new_transfer)

    file_location = os.path.join(STORAGE_DIR, str(new_transfer.id))
    new_transfer.blob_path = file_location

    with open(file_location, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)

    db.add(new_transfer)
    db.commit()
    db.refresh(new_transfer)

    # 3. Save encrypted keys
    try:
        keys_data = json.loads(recipient_keys)
        if not isinstance(keys_data, list):
            raise ValueError
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid recipient_keys format.")

    for key_entry in keys_data:
        new_key = TransferKey(
            transfer_id=new_transfer.id,
            recipient_id=key_entry["recipient_id"],
            encrypted_key=key_entry["encrypted_key"]
        )
        db.add(new_key)
    
    db.commit()

    return new_transfer.id

def get_transfer_metadata_service(
    db: Session,
    user: User,
    transfer_id: UUID,
    mls_payload: Optional[dict] = None,
    justification: Optional[str] = None,
    is_trusted_officer: bool = False
) -> dict:
    transfer = db.get(Transfer, transfer_id)
    if not transfer:
        raise HTTPException(status_code=404, detail="Transfer not found")

    # 1. MLS Read Check
    dept_list = json.loads(transfer.departments)
    check_mls_read(
        user=user, 
        classification=transfer.classification_level, 
        departments=dept_list,
        mls_payload=mls_payload,
        justification=justification,
        is_trusted_officer=is_trusted_officer
    )

    # 2. Check Expiration
    if transfer.expires_at and transfer.expires_at < datetime.utcnow():
        raise HTTPException(status_code=410, detail="Transfer expired")

    # 3. Check permissions
    user_key = db.exec(
        select(TransferKey)
        .where(TransferKey.transfer_id == transfer_id)
        .where(TransferKey.recipient_id == user.id)
    ).first()

    if not user_key and transfer.uploader_id != user.id:
         raise HTTPException(status_code=403, detail="Access denied. No key available for this user.")

    return {
        "id": transfer.id,
        "filename": transfer.filename,
        "classification": transfer.classification_level,
        "departments": dept_list,
        "is_public": transfer.is_public,
        "expires_at": transfer.expires_at,
        "encrypted_key": user_key.encrypted_key if user_key else None
    }

def get_transfer_file_stream_service(
    db: Session,
    user: User,
    transfer_id: UUID,
    mls_payload: Optional[dict] = None,
    justification: Optional[str] = None,
    is_trusted_officer: bool = False
) -> Generator[bytes, None, None]:
    transfer = db.get(Transfer, transfer_id)
    if not transfer:
        raise HTTPException(status_code=404, detail="Transfer not found")

    # 1. MLS Read Check
    dept_list = json.loads(transfer.departments)
    check_mls_read(
        user=user, 
        classification=transfer.classification_level, 
        departments=dept_list,
        mls_payload=mls_payload,
        justification=justification,
        is_trusted_officer=is_trusted_officer
    )

    # 2. Check permissions
    user_key = db.exec(
        select(TransferKey)
        .where(TransferKey.transfer_id == transfer_id)
        .where(TransferKey.recipient_id == user.id)
    ).first()

    if not transfer.is_public and not user_key and transfer.uploader_id != user.id:
        raise HTTPException(status_code=403, detail="Access denied.")

    # 3. Stream file
    if not os.path.exists(transfer.blob_path):
         raise HTTPException(status_code=404, detail="File not found on disk")

    def iterfile():
        with open(transfer.blob_path, mode="rb") as file_like:
            yield from file_like
            
    return iterfile()

def list_user_transfers_service(
    db: Session,
    user: User
) -> List[Transfer]:
    transfers = db.exec(
        select(Transfer).where(Transfer.uploader_id == user.id)
    ).all()
    return transfers

def delete_transfer_service(
    db: Session,
    user: User,
    transfer_id: UUID
):
    transfer = db.get(Transfer, transfer_id)
    if not transfer:
        raise HTTPException(status_code=404, detail="Transfer not found")

    if transfer.uploader_id != user.id:
        raise HTTPException(status_code=403, detail="Only the uploader can delete this transfer")

    # Delete keys
    keys = db.exec(select(TransferKey).where(TransferKey.transfer_id == transfer_id)).all()
    for key in keys:
        db.delete(key)
    
    db.delete(transfer)
    db.commit()

    # Securely remove file
    if os.path.exists(transfer.blob_path):
        try:
            file_size = os.path.getsize(transfer.blob_path)
            with open(transfer.blob_path, "wb") as f:
                f.write(b"\0" * file_size)
            os.remove(transfer.blob_path)
        except Exception as e:
            print(f"Error deleting file: {e}")
