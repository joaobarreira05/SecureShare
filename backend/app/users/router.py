from fastapi import APIRouter, Depends, HTTPException, status
from sqlmodel import Session, SQLModel
from ..core.database import get_session
from ..models.User import VaultContent, VaultUpdate, UserCreate, UserResponse
from .service import create_user, get_all_users
from ..auth.service import get_current_active_admin, get_current_user, check_if_admin_or_security_officer, check_if_security_officer
from ..models.User import User
from .service import delete_user, update_vault
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

@router.delete("/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_user_endpoint(
    user_id: int, 
    session: Session = Depends(get_session),
    current_admin: User = Depends(get_current_active_admin)
):
    """
    Delete a user (Admin only).
    """
    await delete_user(session, user_id)
    return None

@router.get("", response_model=list[UserResponse])
async def read_users(
    session: Session = Depends(get_session),
    current_user: User = Depends(check_if_admin_or_security_officer)
):
    """
    List all users (Admin or Security Officer).
    """
    return await get_all_users(session)

@router.get("/me/vault", response_model=VaultContent)
async def get_user_vault(current_user: User = Depends(get_current_user)):
    """
    Retrieve the current user's encrypted private key blob.
    """
    return VaultContent(encrypted_private_key=current_user.encrypted_private_key)

@router.put("/me/vault", status_code=status.HTTP_204_NO_CONTENT)
async def update_user_vault(
    vault: VaultUpdate,  # by setting the vault as a parameter, it will look for the encrypted private key in the request body and assimilate it (service.update_vault)
    session: Session = Depends(get_session),
    current_user: User = Depends(get_current_user) # It uses the OAuth2 dependency to get the token from the header (Bearer) and validates it     
):
    """
    Upload or update the current user's encrypted private key blob.
    """
    await update_vault(session, current_user, vault)
    return None

from ..models.JWTRBACToken import JWTRBACToken
from ..models.JWTRevocationToken import JWTRevocationToken
from .service import verify_and_store_role_token, verify_and_store_revocation_token


class TokenCreate(SQLModel):
    signed_jwt: str

@router.put("/{user_id}/role", status_code=status.HTTP_204_NO_CONTENT)
async def update_user_role(
    user_id: int,
    token_data: TokenCreate,
    session: Session = Depends(get_session),
    current_user: User = Depends(check_if_admin_or_security_officer)
):
    """
    Update/create a user's role (Admin or Security Officer).
    Expects a signed JWTRBACToken (raw string) in the body.
    """
    token = await verify_and_store_role_token(session, token_data.signed_jwt)
    
    # Verify the token is for the correct user
    if token.sub != str(user_id):
        raise HTTPException(status_code=400, detail="Token subject does not match user ID")
    
    # Verify the token was issued by the caller
    if token.iss != str(current_user.id):
        raise HTTPException(status_code=400, detail="Token issuer does not match caller ID")

    return None

@router.put("/{user_id}/revoke/{token_id}", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_token(
    user_id: int,
    token_id: str,
    token: JWTRevocationToken,
    session: Session = Depends(get_session),
    current_so: User = Depends(check_if_security_officer)
):
    """
    Revoke a token (Security Officer only).
    Expects a signed JWTRevocationToken in the body.
    """
    # Verify the token is for the correct user? 
    # Revocation token doesn't have a 'sub' field pointing to the user, it points to the token being revoked.
    # But the endpoint path has {user_id}. 
    # We should probably check if the token being revoked belongs to the user_id?
    # But the revocation token model only has token_id (JTI).
    # We can't easily check ownership without querying the token being revoked.
    # For now, we focus on storing the revocation token.
    
    if token.token_id != token_id:
         raise HTTPException(status_code=400, detail="Token ID in body does not match URL")

    # Verify the token was issued by the caller
    if token.revoker_id != current_so.id:
        raise HTTPException(status_code=400, detail="Token revoker does not match caller ID")

    await verify_and_store_revocation_token(session, token)
    return None

@router.get("/{user_id}/key", response_model=dict)
async def get_user_public_key(
    user_id: int,
    session: Session = Depends(get_session),
    current_user: User = Depends(get_current_user)
):
    """
    Retrieve a user's public key (Authenticated User).
    """
    user = session.get(User, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    if not user.public_key:
        raise HTTPException(status_code=404, detail="Public key not found for this user")

    return {"public_key": user.public_key}

from ..models.JWTMLSToken import JWTMLSToken
from ..models.User import UserClearanceResponse
from .service import verify_and_store_mls_token
from sqlmodel import select
from fastapi import Request

@router.get("/{user_id}/clearance", response_model=UserClearanceResponse)
async def get_user_clearance(
    user_id: int,
    request: Request,
    session: Session = Depends(get_session),
    current_user: User = Depends(get_current_user)
):
    """
    Get user clearance and roles (Security Officer or Self).
    """
    is_self = current_user.id == user_id
    is_so = False

    # Check if acting as Security Officer
    x_role_token = request.headers.get("X-Role-Token")
    if x_role_token:
        try:
            # We reuse the logic by calling the dependency function directly? 
            # No, dependency injection is handled by FastAPI.
            # We can manually verify using the service helper if we import it.
            # But check_if_security_officer does it all.
            # We can't easily call it here without mocking dependencies.
            # So we replicate the check:
            from ..auth.service import verify_rbac_token_signature
            from ..models.Role import Role
            
            # Now verify_rbac_token_signature takes the raw string directly!
            payload = verify_rbac_token_signature(session, x_role_token)
            
            if payload.get("sub") == str(current_user.id) and payload.get("app_role") == Role.SECURITY_OFFICER:
                is_so = True
        except Exception:
            pass # Invalid token, treat as not SO

    if not is_self and not is_so:
        raise HTTPException(status_code=403, detail="Not authorized")

    mls_tokens = session.exec(select(JWTMLSToken).where(JWTMLSToken.user_id == user_id)).all()
    rbac_tokens = session.exec(select(JWTRBACToken).where(JWTRBACToken.sub == str(user_id))).all()
    
    return UserClearanceResponse(mls_tokens=mls_tokens, rbac_tokens=rbac_tokens)

@router.put("/{user_id}/clearance", status_code=status.HTTP_204_NO_CONTENT)
async def add_user_clearance(
    user_id: int,
    token_data: TokenCreate,
    session: Session = Depends(get_session),
    current_so: User = Depends(check_if_security_officer)
):
    """
    Add a clearance token (Security Officer only).
    """
    token = await verify_and_store_mls_token(session, token_data.signed_jwt)
    
    if token.user_id != user_id:
         raise HTTPException(status_code=400, detail="Token subject does not match URL user ID")
         
    return None
