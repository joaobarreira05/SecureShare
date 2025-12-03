from datetime import datetime, timedelta, timezone
from typing import Annotated
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlmodel import Session, select
from ..core.database import get_session
from ..core.settings import settings
from ..models.User import User, UserActivate
from ..models.JWTAuthToken import TokenPayload

# Password hashing
pwd_context = CryptContext(schemes=["argon2"], deprecated="auto")

# OAuth2 scheme (for extracting token from header)
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/login")

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

from ..models.JWTAuthToken import JWTAuthToken

def create_access_token(session: Session, user_id: int, data: dict, expires_delta: timedelta | None = None):
    # Check for existing valid token
    statement = select(JWTAuthToken).where(
        JWTAuthToken.user_id == user_id,
        JWTAuthToken.is_active == True,
        JWTAuthToken.expires_at > datetime.utcnow()
    )
    existing_token = session.exec(statement).first()
    
    if existing_token:
        return existing_token.access_token

    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    
    # Store new token
    new_token = JWTAuthToken(
        access_token=encoded_jwt,
        user_id=user_id,
        expires_at=expire,
        is_active=True
    )
    session.add(new_token)
    session.commit()
    
    return encoded_jwt

async def get_current_user(token: Annotated[str, Depends(oauth2_scheme)], session: Session = Depends(get_session)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenPayload(sub=username)
    except JWTError:
        raise credentials_exception
    
    statement = select(User).where(User.username == token_data.sub)
    user = session.exec(statement).first()
    if user is None:
        raise credentials_exception
    return user

async def get_current_active_admin(current_user: Annotated[User, Depends(get_current_user)]):
    if not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Not enough privileges"
        )
    return current_user

async def authenticate_user(session: Session, username: str, password: str):
    statement = select(User).where(User.username == username)
    user = session.exec(statement).first()
    if not user:
        return False
    if not user.is_active:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user

async def activate_user_account(session: Session, activation_data: UserActivate):
    statement = select(User).where(User.username == activation_data.username)
    user = session.exec(statement).first()
    
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    if user.is_active:
        raise HTTPException(status_code=400, detail="User already active")

    if not verify_password(activation_data.otp, user.otp_hash):
         raise HTTPException(status_code=400, detail="Invalid OTP")

    user.hashed_password = get_password_hash(activation_data.password)
    user.public_key = activation_data.public_key
    user.encrypted_private_key = activation_data.encrypted_private_key
    user.is_active = True
    user.otp_hash = None # Clear OTP after use
    
    session.add(user)
    session.commit()
    session.refresh(user)
    return user
