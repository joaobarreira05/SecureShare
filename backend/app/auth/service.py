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
    encoded_jwt = jwt.encode(to_encode, settings.SERVER_PRIVATE_KEY, algorithm=settings.ALGORITHM)
    
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
        payload = jwt.decode(token, settings.SERVER_PUBLIC_KEY, algorithms=[settings.ALGORITHM])
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

from ..models.JWTRBACToken import JWTRBACToken
from ..models.Role import Role
from cryptography.hazmat.backends import default_backend

from fastapi import Header
import json
from ..models.JWTRevocationToken import JWTRevocationToken
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature
import base64

def verify_rbac_token_signature(session: Session, signed_jwt: str):
    # 1. Decode without verification to get headers and payload
    try:
        payload = jwt.get_unverified_claims(signed_jwt)
    except JWTError:
        raise HTTPException(status_code=400, detail="Invalid JWT format")

    # 2. Extract Claims
    issuer_id = payload.get("iss")
    exp = payload.get("exp")
    jti = payload.get("jti")

    if not issuer_id or not exp or not jti:
        raise HTTPException(status_code=400, detail="Missing required claims (iss, exp, jti)")

    # 3. Check Expiration
    if exp < datetime.utcnow().timestamp():
        raise HTTPException(status_code=400, detail="Token has expired")

    # 4. Check Revocation
    revoked = session.get(JWTRevocationToken, jti)
    if revoked:
         raise HTTPException(status_code=403, detail="Token has been revoked")

    # 5. Fetch Issuer Public Key
    issuer = session.get(User, int(issuer_id))
    if not issuer or not issuer.public_key:
        raise HTTPException(status_code=400, detail="Issuer not found or missing public key")

    # 6. Verify Signature
    try:
        jwt.decode(signed_jwt, issuer.public_key, algorithms=["RS256"])
    except JWTError as e:
        raise HTTPException(status_code=400, detail=f"Invalid signature: {str(e)}")
    
    return payload

async def check_if_security_officer(
    current_user: Annotated[User, Depends(get_current_user)],
    session: Session = Depends(get_session),
    x_role_token: Annotated[str | None, Header()] = None
):
    # Strict check: Admin is NOT automatically a Security Officer for this purpose.
    # The user must provide a valid Security Officer token.
    
    if not x_role_token:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Missing X-Role-Token header"
        )

    # Verify signature and validity
    payload = verify_rbac_token_signature(session, x_role_token)

    # Verify ownership
    if payload.get("sub") != str(current_user.id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Token does not belong to user"
        )

    # Verify Role
    if payload.get("app_role") != Role.SECURITY_OFFICER:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Not a Security Officer"
        )
    
    return current_user

async def check_if_trusted_officer(
    current_user: Annotated[User, Depends(get_current_user)],
    session: Session = Depends(get_session),
    x_role_token: Annotated[str | None, Header()] = None
):
    if current_user.is_admin:
        return current_user

    if not x_role_token:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Missing X-Role-Token header"
        )

    # Verify signature and validity
    payload = verify_rbac_token_signature(session, x_role_token)

    if payload.get("sub") != str(current_user.id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Token does not belong to user"
        )

    if payload.get("app_role") != Role.TRUSTED_OFFICER:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Not a Trusted Officer"
        )
    
    return current_user

async def check_if_admin_or_security_officer(
    current_user: Annotated[User, Depends(get_current_user)],
    session: Session = Depends(get_session),
    x_role_token: Annotated[str | None, Header()] = None
):
    if current_user.is_admin:
        return current_user

    if not x_role_token:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Missing X-Role-Token header"
        )

    # Verify signature and validity
    payload = verify_rbac_token_signature(session, x_role_token)

    if payload.get("sub") != str(current_user.id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Token does not belong to user"
        )

    if payload.get("app_role") != Role.SECURITY_OFFICER:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Not a Security Officer"
        )
    
    return current_user

async def get_current_clearance(
    current_user: Annotated[User, Depends(get_current_user)],
    session: Session = Depends(get_session),
    x_mls_token: Annotated[str | None, Header()] = None
):
    """
    Dependency to extract and verify the MLS token from the X-MLS-Token header.
    Returns the verified token payload (dict).
    """
    if not x_mls_token:
        # If no token is provided, we return None. 
        # The endpoint logic will decide if it requires clearance or not.
        return None

    try:
        # 1. Decode without verification to get headers and payload
        payload = jwt.get_unverified_claims(x_mls_token)
        issuer_id = payload.get("iss")
        exp = payload.get("exp")
        sub = payload.get("sub")
        jti = payload.get("jti")
        
        if not issuer_id or not exp or not sub or not jti:
             raise HTTPException(status_code=400, detail="Invalid MLS Token claims")

        if str(sub) != str(current_user.id):
             raise HTTPException(status_code=403, detail="MLS Token does not belong to user")

        # 2. Fetch Issuer Public Key
        issuer = session.get(User, int(issuer_id))
        if not issuer or not issuer.public_key:
            raise HTTPException(status_code=400, detail="Issuer not found")

        # 3. Verify Signature
        jwt.decode(x_mls_token, issuer.public_key, algorithms=["RS256"])

        # 4. Check Revocation
        revoked = session.get(JWTRevocationToken, jti)
        if revoked:
            raise HTTPException(status_code=403, detail="MLS Token has been revoked")
            
        return payload

    except JWTError as e:
        raise HTTPException(status_code=400, detail=f"Invalid MLS Token: {str(e)}")
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"MLS Token verification failed: {str(e)}")
