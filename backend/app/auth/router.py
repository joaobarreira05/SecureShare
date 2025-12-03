from datetime import timedelta
from typing import Annotated
from fastapi import APIRouter, Depends, HTTPException, status
from sqlmodel import Session
from ..core.database import get_session
from ..core.settings import settings
from ..models.User import UserResponse, LoginRequest, UserActivate, User
from ..models.JWTAuthToken import Token
from .service import authenticate_user, create_access_token, get_current_user, activate_user_account

router = APIRouter(prefix="/auth", tags=["auth"])

@router.post("/activate", status_code=status.HTTP_200_OK)
async def activate_account(activation_data: UserActivate, session: Session = Depends(get_session)):
    """
    Activate a new user account using OTP and set password/keys.
    """
    await activate_user_account(session, activation_data)
    return {"message": "Account activated successfully"}

@router.post("/login", response_model=Token)
async def login(login_data: LoginRequest, session: Session = Depends(get_session)):
    """
    Login with username and password to get an access token.
    """
    user = await authenticate_user(session, login_data.username, login_data.password)
    if not user:
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
    return Token(access_token=access_token, token_type="bearer")


@router.post("/logout")
async def logout(current_user: Annotated[User, Depends(get_current_user)]):
    """
    Logout the current user.
    """
    return {"message": "Logged out successfully"}
