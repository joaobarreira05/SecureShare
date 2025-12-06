from datetime import timedelta
import http
from typing import Annotated
from fastapi import APIRouter, Depends, HTTPException, status
from sqlmodel import Session
from ..core.database import get_session
from ..core.settings import settings
from ..models.User import UserResponse, LoginRequest, UserActivate, User
from ..models.JWTAuthToken import Token
from .service import authenticate_user, create_access_token, get_current_user, activate_user_account
from ..audit.service import log_event

router = APIRouter(prefix="/auth", tags=["auth"])

@router.post("/activate", status_code=status.HTTP_200_OK)
async def activate_account(activation_data: UserActivate, session: Session = Depends(get_session)):
    """
    Activate a new user account using OTP and set password/keys.
    """
    user = await activate_user_account(session, activation_data)

    action = f"POST /activate {status.HTTP_200_OK} {http.HTTPStatus(status.HTTP_200_OK).phrase}"
    log_event(session, user.id, action, "Account activated successfully")
    return {"message": "Account activated successfully"}

@router.post("/login", response_model=Token)
async def login(login_data: LoginRequest, session: Session = Depends(get_session)):
    """
    Login with username and password to get an access token.
    """
    user = await authenticate_user(session, login_data.username, login_data.password)

    if not user:
        action = f"POST /login {status.HTTP_401_UNAUTHORIZED} - {http.HTTPStatus(status.HTTP_401_UNAUTHORIZED).phrase}"
        log_event(session, 0, action, "Incorrect username or password")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        session=session,
        user_id=user.id,
        data={"sub": user.username, "scopes": ["admin"] if user.is_admin else []},
        expires_delta=access_token_expires
    )
    action = f"POST /login {status.HTTP_200_OK} {http.HTTPStatus(status.HTTP_200_OK).phrase}"
    log_event(session, user.id, action, "Login successful")
    return Token(access_token=access_token, token_type="bearer")


@router.post("/logout")
async def logout(
    current_user: Annotated[User, Depends(get_current_user)],
    session: Session = Depends(get_session)
):
    """
    Logout the current user.
    """
    action = f"POST /logout {status.HTTP_200_OK} {http.HTTPStatus(status.HTTP_200_OK).phrase}"
    log_event(session, current_user.id, action, "Logged out successfully")
    return {"message": "Logged out successfully"}
