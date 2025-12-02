from fastapi import APIRouter, Depends, HTTPException, status
from .schemas import VaultContent, VaultUpdate

router = APIRouter(prefix="/users", tags=["users"])

@router.get("/me/vault", response_model=VaultContent)
async def get_user_vault(token: str = Depends(lambda: "dummy_token")):
    """
    Retrieve the current user's encrypted private key blob.
    """
    pass

@router.put("/me/vault", status_code=status.HTTP_204_NO_CONTENT)
async def update_user_vault(vault: VaultUpdate, token: str = Depends(lambda: "dummy_token")):
    """
    Upload or update the current user's encrypted private key blob.
    """
    pass
