from pydantic import BaseModel

class VaultContent(BaseModel):
    encrypted_private_key: str

class VaultUpdate(BaseModel):
    encrypted_private_key: str
