from fastapi import APIRouter, Depends, HTTPException, status
from sqlmodel import Session
from ..core.database import get_session
from ..models.User import VaultContent, VaultUpdate, UserCreate
from .service import create_user
from ..auth.service import get_current_active_admin
from ..models.User import User

router = APIRouter(prefix="/users", tags=["users"])

@router.post("", status_code=status.HTTP_201_CREATED)
async def create_new_user(
    user: UserCreate, 
    session: Session = Depends(get_session),
    current_admin: User = Depends(get_current_active_admin)
):
    """
    Create a new user (Admin only).
    """
    await create_user(session, user)
    return {"message": "Created new user Successfully"}

@router.get("/me/vault", response_model=VaultContent)
async def get_user_vault(token: str = Depends(lambda: "dummy_token")):
    """
    Retrieve the current user's encrypted private key blob.
    """
    pass

@router.put("/me/vault", status_code=status.HTTP_204_NO_CONTENT)
async def update_user_vault(vault: VaultUpdate, token: str = Depends(lambda: "dummy_token")):
    """
    Upload or update the current user's encrypted private key blob.
    """
    pass
