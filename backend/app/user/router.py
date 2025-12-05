from fastapi import APIRouter, Depends, status
from sqlmodel import Session
from ..core.database import get_session
from ..models.User import User, UserResponse, UserUpdate
from ..auth.service import get_current_user
from .service import update_user_info

router = APIRouter(prefix="/user", tags=["user"])

@router.get("/me/info", response_model=UserResponse)
async def get_my_info(current_user: User = Depends(get_current_user)):
    """
    Get current user information.
    """
    return current_user

@router.post("/me/info", response_model=UserResponse)
async def update_my_info(
    update_data: UserUpdate,
    session: Session = Depends(get_session),
    current_user: User = Depends(get_current_user)
):
    """
    Updates existing information, such as the password.
    """
    return await update_user_info(session, current_user, update_data)
