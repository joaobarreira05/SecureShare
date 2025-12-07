from datetime import datetime
import base64

from fastapi import HTTPException, status
from sqlmodel import Session, select
from jose import jwt, JWTError
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend

from ..models.User import User, UserCreate, VaultUpdate
from ..auth.service import get_password_hash
from ..models.JWTAuthToken import JWTAuthToken
from ..models.JWTRBACToken import JWTRBACToken, RBACPayload
from ..models.JWTRevocationToken import JWTRevocationToken
from ..models.JWTMLSToken import JWTMLSToken
from ..models.Role import Role
from ..models.Department import Department
from ..core.settings import settings

async def create_user(session: Session, user: UserCreate):
    statement = select(User).where(User.username == user.username)
    db_user = session.exec(statement).first()
    if db_user:
        raise HTTPException(status_code=400, detail="Username already registered")
    
    statement = select(User).where(User.email == user.email)
    db_user = session.exec(statement).first()
    if db_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    
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
    if db_user.is_admin:
        raise HTTPException(status_code=403, detail="Administrators cannot be deleted")
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



async def update_vault(session: Session, user: User, vault: VaultUpdate):
    user.encrypted_private_key = vault.encrypted_private_key
    session.add(user)
    session.commit()
    session.refresh(user)
    return user



async def verify_and_store_role_token(session: Session, signed_jwt: str):
    # 1. Get Issuer ID from Header
    try:
        header = jwt.get_unverified_header(signed_jwt)
        issuer_id = header.get("kid")
    except JWTError:
        raise HTTPException(status_code=400, detail="Invalid JWT format")

    if not issuer_id:
        raise HTTPException(status_code=400, detail="Missing 'kid' in JWT header")

    # 2. Fetch Issuer Public Key
    issuer_user = session.get(User, int(issuer_id))
    if not issuer_user or not issuer_user.public_key:
        raise HTTPException(status_code=400, detail="Issuer not found or has no public key")

    # 3. Verify Signature & Decode
    try:
        payload = jwt.decode(signed_jwt, issuer_user.public_key, algorithms=["RS256"])
    except JWTError as e:
        raise HTTPException(status_code=400, detail=f"Invalid signature: {str(e)}")

    # 4. Extract & Verify Claims (from VERIFIED payload)
    exp = payload.get("exp")
    sub = payload.get("sub")
    app_role = payload.get("app_role")
    jti = payload.get("jti")

    if not exp or not sub or not app_role or not jti:
        raise HTTPException(status_code=400, detail="Missing required claims (exp, sub, app_role, jti)")

    # 5. Check Revocation
    revoked = session.get(JWTRevocationToken, (jti, "RBAC"))
    if revoked:
        raise HTTPException(status_code=403, detail="Token has been revoked")

    # Check if target user is Admin (Admins cannot have roles)
    target_user = session.get(User, int(sub))
    if target_user and target_user.is_admin:
        raise HTTPException(status_code=403, detail="Administrators cannot be assigned roles")
    if target_user.id == issuer_user.id:
        raise HTTPException(status_code=403, detail="You cannot assign a role to yourself")
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
    
    # Nobody can assign ADMIN role
    if target_role == Role.ADMINISTRATOR:
        raise HTTPException(status_code=403, detail="The ADMINISTRATOR role cannot be assigned via token.")
    # Admin -> Security Officer
    if target_role == Role.SECURITY_OFFICER and issuer_role != Role.ADMINISTRATOR:
         raise HTTPException(status_code=403, detail="Only Administrators can appoint Security Officers")
    
    # Admin/SO -> Trusted Officer
    if target_role == Role.TRUSTED_OFFICER and issuer_role not in [Role.SECURITY_OFFICER]:
        raise HTTPException(status_code=403, detail="Only Administrators or Security Officers can appoint Trusted Officers")

    # Admin/SO -> Auditor
    if target_role == Role.AUDITOR and issuer_role not in [Role.ADMINISTRATOR]:
        raise HTTPException(status_code=403, detail="Only Administrators can appoint Auditors")

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
    
    if not so_token and not issuer_user.is_admin:
        raise HTTPException(status_code=403, detail="Only Security Officers can revoke tokens")

    # Convert timestamp to datetime if it's a string (SQLite needs datetime object)
    timestamp = token_data.timestamp
    if isinstance(timestamp, str):
        timestamp = datetime.fromisoformat(timestamp)
    
    # --- Signature Verification ---


    # Reconstruct the signed message: token_id|revoker_id|timestamp_str
    # Timestamp format must match CLI: %Y-%m-%dT%H:%M:%S
    timestamp_str = timestamp.strftime("%Y-%m-%dT%H:%M:%S")
    message = f"{token_data.token_id}|{token_data.revoker_id}|{timestamp_str}"
    
    try:
        # Load Issuer Public Key
        public_key = serialization.load_pem_public_key(
            issuer_user.public_key.encode() if isinstance(issuer_user.public_key, str) else issuer_user.public_key,
            backend=default_backend()
        )
        
        # Decode Signature
        signature_bytes = base64.b64decode(token_data.signature)
        
        # Verify
        public_key.verify(
            signature_bytes,
            message.encode(),
            padding.PKCS1v15(),
            hashes.SHA256()
        )
    except Exception as e:
        print(f"Signature verification failed: {e}")
        raise HTTPException(status_code=400, detail="Invalid revocation signature")

    # Create a new token with proper types for SQLAlchemy
    db_token = JWTRevocationToken(
        token_id=token_data.token_id,
        token_type=token_data.token_type,
        revoker_id=token_data.revoker_id,
        timestamp=timestamp,
        signature=token_data.signature
    )
    
    session.add(db_token)
    session.commit()
    session.refresh(db_token)
    return db_token

async def get_all_users(session: Session):
    statement = select(User)
    return session.exec(statement).all()



async def verify_and_store_mls_token(session: Session, signed_jwt: str):
    # 1. Get Issuer ID from Header
    try:
        header = jwt.get_unverified_header(signed_jwt)
        issuer_id = header.get("kid")
    except JWTError:
        raise HTTPException(status_code=400, detail="Invalid JWT format")

    if not issuer_id:
        raise HTTPException(status_code=400, detail="Missing 'kid' in JWT header")

    # 2. Fetch Issuer Public Key
    issuer = session.get(User, int(issuer_id))
    if not issuer or not issuer.public_key:
        raise HTTPException(status_code=400, detail="Issuer not found or missing public key")

    # 3. Verify Signature & Decode
    try:
        payload = jwt.decode(signed_jwt, issuer.public_key, algorithms=["RS256"])
    except JWTError as e:
        raise HTTPException(status_code=400, detail=f"Invalid signature: {str(e)}")

    # 4. Extract & Verify Claims (from VERIFIED payload)
    exp = payload.get("exp")
    sub = payload.get("sub")
    jti = payload.get("jti")
    
    if not exp or not sub or not jti:
        raise HTTPException(status_code=400, detail="Missing required claims (exp, sub, jti)")

    if int(issuer_id) == int(sub):
        raise HTTPException(status_code=400, detail="A security officer cannot issue a token for himself")

    # 5. Check Revocation
    revoked = session.get(JWTRevocationToken, (jti, "MLS"))
    if revoked:
        raise HTTPException(status_code=403, detail="Token has been revoked")

    # Check if target user is Admin (Admins cannot have clearances)
    target_user = session.get(User, int(sub))
    if target_user and target_user.is_admin:
        raise HTTPException(status_code=403, detail="Administrators cannot be assigned clearances")
    
    # 6. Validate Departments
    departments = payload.get("departments", [])
    if departments:

        # Check if all departments exist
        statement = select(Department.name).where(Department.name.in_(departments))
        existing_depts = session.exec(statement).all()
        
        existing_depts_set = set(existing_depts)
        for dept in departments:
            if dept not in existing_depts_set:
                raise HTTPException(
                    status_code=400, 
                    detail=f"Invalid department in token: {dept}"
                )

    # 7. Store Token
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

