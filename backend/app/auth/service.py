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
pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")

# OAuth2 scheme (for extracting token from header)
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/login")

import hashlib
import binascii

# ... existing imports ...

def get_custom_hash(password: str, salt: str, alg: str = "sha256", iters: int = 10000) -> str:
    """
    Generates a custom hash in the format: $$hash$alg$salt$iters
    """
    dk = hashlib.pbkdf2_hmac(alg, password.encode(), salt.encode(), iters)
    hex_hash = binascii.hexlify(dk).decode()
    return f"$${hex_hash}${alg}${salt}${iters}"

def verify_custom_hash(plain_password: str, stored_hash: str) -> bool:
    """
    Verifies a password against the custom hash format: $$hash$alg$salt$iters
    """
    try:
        # Remove leading $$ and split
        parts = stored_hash[2:].split('$')
        if len(parts) != 4:
            return False
        
        hex_hash, alg, salt, iters = parts
        iters = int(iters)
        
        # Recalculate hash
        dk = hashlib.pbkdf2_hmac(alg, plain_password.encode(), salt.encode(), iters)
        recalculated_hash = binascii.hexlify(dk).decode()
        
        return recalculated_hash == hex_hash
    except Exception:
        return False

def verify_password(plain_password, hashed_password):
    if hashed_password.startswith("$$"):
        return verify_custom_hash(plain_password, hashed_password)
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

    # Verify OTP (In a real app, verify hash. Here assuming simple check or hash comparison)
    # For this implementation, let's assume otp_hash stores the actual OTP or a hash of it.
    # If it's a hash: verify_password(activation_data.otp, user.otp_hash)
    # Let's assume otp_hash IS the hash of the OTP.
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
