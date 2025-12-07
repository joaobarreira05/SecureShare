from fastapi import APIRouter, Depends, status, HTTPException
import http
from sqlmodel import Session
from ..core.database import get_session
from ..audit.service import log_event
from ..models.User import User, UserResponse, UserUpdate
from ..auth.service import get_current_user
from .service import update_user_info

router = APIRouter(prefix="/user", tags=["user"])

@router.get("/me/info", response_model=UserResponse)
async def get_my_info(
    session: Session = Depends(get_session),
    current_user: User = Depends(get_current_user)
):
    """
    Get current user information.
    """
    action = f"GET /user/me/info {status.HTTP_200_OK} {http.HTTPStatus(status.HTTP_200_OK).phrase}"
    log_event(session, current_user.id, action)
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
    if current_user.is_admin and update_data.password:
        action = f"POST /user/me/info {status.HTTP_403_FORBIDDEN} - Admin cannot change password"
        log_event(session, current_user.id, action)
        raise HTTPException(status_code=403, detail="Administrators cannot change their password")

    action = f"POST /user/me/info {status.HTTP_200_OK} {http.HTTPStatus(status.HTTP_200_OK).phrase}"
    log_event(session, current_user.id, action, "User info updated successfully")
    return await update_user_info(session, current_user, update_data)
