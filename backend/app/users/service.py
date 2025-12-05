from fastapi import HTTPException, status
from sqlmodel import Session, select
from ..models.User import User, UserCreate
from ..auth.service import get_password_hash
from ..models.JWTAuthToken import JWTAuthToken

async def create_user(session: Session, user: UserCreate):
    statement = select(User).where(User.username == user.username)
    db_user = session.exec(statement).first()
    if db_user:
        raise HTTPException(status_code=400, detail="Username already registered")
    
    # Hash the OTP provided by the admin
    hashed_otp = get_password_hash(user.otp)
    
    db_user = User(
        username=user.username,
        email=user.email,
        full_name=user.full_name,
        otp_hash=hashed_otp,
        is_active=False, # User is inactive until they activate with OTP
        is_admin=False
    )
    session.add(db_user)
    session.commit()
    session.refresh(db_user)
    return db_user

async def delete_user(session: Session, user_id: int):
    db_user = session.get(User, user_id)
    if not db_user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Delete Auth Tokens
    statement_auth = select(JWTAuthToken).where(JWTAuthToken.user_id == user_id)
    auth_tokens = session.exec(statement_auth).all()
    for token in auth_tokens:
        session.delete(token)

    # Delete RBAC Tokens
    statement_rbac = select(JWTRBACToken).where(JWTRBACToken.sub == str(user_id))
    rbac_tokens = session.exec(statement_rbac).all()
    for token in rbac_tokens:
        session.delete(token)

    # Delete MLS Tokens
    statement_mls = select(JWTMLSToken).where(JWTMLSToken.user_id == user_id)
    mls_tokens = session.exec(statement_mls).all()
    for token in mls_tokens:
        session.delete(token)
    
    session.delete(db_user)
    session.commit()
    return True

from ..models.User import VaultUpdate

async def update_vault(session: Session, user: User, vault: VaultUpdate):
    user.encrypted_private_key = vault.encrypted_private_key
    session.add(user)
    session.commit()
    session.refresh(user)
    return user

from ..models.JWTRBACToken import JWTRBACToken, RBACPayload
from ..models.JWTRevocationToken import JWTRevocationToken
from ..models.Role import Role
from ..core.settings import settings
from jose import jwt, JWTError
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

async def verify_and_store_role_token(session: Session, signed_jwt: str):
    # 1. Decode without verification to get headers and payload
    try:
        payload = jwt.get_unverified_claims(signed_jwt)
    except JWTError:
        raise HTTPException(status_code=400, detail="Invalid JWT format")

    # 2. Extract Claims
    issuer_id = payload.get("iss")
    exp = payload.get("exp")
    sub = payload.get("sub")
    app_role = payload.get("app_role")
    jti = payload.get("jti")

    if not issuer_id or not exp or not sub or not app_role or not jti:
        raise HTTPException(status_code=400, detail="Missing required claims (iss, exp, sub, app_role, jti)")

    # 3. Fetch Issuer Public Key
    issuer_user = session.get(User, int(issuer_id))
    if not issuer_user or not issuer_user.public_key:
        raise HTTPException(status_code=400, detail="Issuer not found or has no public key")

    # 4. Verify Signature
    try:
        jwt.decode(signed_jwt, issuer_user.public_key, algorithms=["RS256"])
    except JWTError as e:
        raise HTTPException(status_code=400, detail=f"Invalid signature: {str(e)}")

    # 5. Check Revocation
    revoked = session.get(JWTRevocationToken, (jti, "RBAC"))
    if revoked:
        raise HTTPException(status_code=403, detail="Token has been revoked")

    # 6. Policy Check
    issuer_role = None
    if issuer_user.is_admin:
        issuer_role = Role.ADMINISTRATOR
    else:
        # Check if issuer has a valid Security Officer token
        statement = select(JWTRBACToken).where(
            JWTRBACToken.sub == str(issuer_user.id),
            JWTRBACToken.app_role == Role.SECURITY_OFFICER
        )
        so_token = session.exec(statement).first()
        if so_token:
            issuer_role = Role.SECURITY_OFFICER
    
    if not issuer_role:
        raise HTTPException(status_code=403, detail="Issuer does not have authority to assign roles")

    target_role = app_role
    
    # Admin -> Security Officer
    if target_role == Role.SECURITY_OFFICER and issuer_role != Role.ADMINISTRATOR:
         raise HTTPException(status_code=403, detail="Only Administrators can appoint Security Officers")
    
    # Admin/SO -> Trusted Officer
    if target_role == Role.TRUSTED_OFFICER and issuer_role not in [Role.ADMINISTRATOR, Role.SECURITY_OFFICER]:
        raise HTTPException(status_code=403, detail="Only Administrators or Security Officers can appoint Trusted Officers")

    # Admin/SO -> Auditor
    if target_role == Role.AUDITOR and issuer_role not in [Role.ADMINISTRATOR, Role.SECURITY_OFFICER]:
        raise HTTPException(status_code=403, detail="Only Administrators or Security Officers can appoint Auditors")

    # 7. Store Token
    token_data = JWTRBACToken(
        id=jti,
        iss=issuer_id,
        sub=sub,
        exp=exp,
        app_role=app_role,
        signed_jwt=signed_jwt
    )
    
    session.add(token_data)
    session.commit()
    session.refresh(token_data)
    return token_data

async def verify_and_store_revocation_token(session: Session, token_data: JWTRevocationToken):
    # 1. Verify Issuer is Security Officer
    if token_data.token_type not in ["MLS", "RBAC"]:
        raise HTTPException(status_code=400, detail="Invalid token type. Must be 'MLS' or 'RBAC'.")

    issuer_user = session.get(User, token_data.revoker_id)
    if not issuer_user:
        raise HTTPException(status_code=400, detail="Revoker not found")
        
    # Check if issuer has a valid Security Officer token
    statement = select(JWTRBACToken).where(
        JWTRBACToken.sub == str(issuer_user.id),
        JWTRBACToken.app_role == Role.SECURITY_OFFICER
    )
    so_token = session.exec(statement).first()
    
    if not so_token and not issuer_user.is_admin: # Assuming Admin can also revoke? Prompt said "Security Officer only" for this endpoint.
        # The prompt said "check if the caller is a sec officer only, not an 'admin or sec officer'"
        # So strict check.
        raise HTTPException(status_code=403, detail="Only Security Officers can revoke tokens")

    session.add(token_data)
    session.commit()
    session.refresh(token_data)
    return token_data

async def get_all_users(session: Session):
    statement = select(User)
    return session.exec(statement).all()

from ..models.JWTMLSToken import JWTMLSToken
from datetime import datetime

async def verify_and_store_mls_token(session: Session, signed_jwt: str):
    # 1. Decode without verification to get headers and payload (for iss and exp)
    try:
        # We use options={"verify_signature": False} to peek at the payload
        payload = jwt.get_unverified_claims(signed_jwt)
    except JWTError:
        raise HTTPException(status_code=400, detail="Invalid JWT format")

    # 2. Extract Issuer and Expiration
    issuer_id = payload.get("iss")
    exp = payload.get("exp")
    sub = payload.get("sub")
    jti = payload.get("jti")

    if not issuer_id or not exp or not sub or not jti:
        raise HTTPException(status_code=400, detail="Missing required claims (iss, exp, sub, jti)")

    # 3. Fetch Issuer Public Key
    issuer = session.get(User, int(issuer_id))
    if not issuer or not issuer.public_key:
        raise HTTPException(status_code=400, detail="Issuer not found or missing public key")

    # 4. Verify Signature
    try:
        # Verify using the issuer's public key
        # We need to construct the public key object or pass the PEM string if supported
        # jose.jwt.decode supports PEM string for public keys
        jwt.decode(signed_jwt, issuer.public_key, algorithms=["RS256"])
    except JWTError as e:
        raise HTTPException(status_code=400, detail=f"Invalid signature: {str(e)}")

    # 5. Check Revocation
    revoked = session.get(JWTRevocationToken, (jti, "MLS"))
    if revoked:
        raise HTTPException(status_code=403, detail="Token has been revoked")

    # 6. Store Token
    # We store the raw signed_jwt as requested
    mls_token = JWTMLSToken(
        token_id=jti,
        user_id=int(sub),
        issuer_id=int(issuer_id),
        signed_jwt=signed_jwt,
        expires_at=datetime.fromtimestamp(exp)
    )
    
    session.add(mls_token)
    session.commit()
    session.refresh(mls_token)
    return mls_token

