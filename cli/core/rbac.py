# cli/core/rbac.py
"""
RBAC Token creation and signing utilities.
Uses RS256 (RSA with SHA-256) for signing JWTs.
"""
import json
import uuid
from datetime import datetime, timezone
from typing import Optional

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_private_key
import base64


VALID_ROLES = [
    "SECURITY_OFFICER",
    "TRUSTED_OFFICER",
    "AUDITOR",
]


def create_rbac_payload(
    issuer_id: int,
    subject_id: int,
    role: str,
    expiration_days: int = 365
) -> dict:
    """
    Creates an RBAC token payload.
    
    Args:
        issuer_id: User ID of the issuer (Admin or SO)
        subject_id: User ID of the subject (who receives the role)
        role: The role being assigned
        expiration_days: Days until expiration
        
    Returns:
        dict: JWT payload
    """
    if role not in VALID_ROLES:
        raise ValueError(f"Invalid role. Must be one of: {VALID_ROLES}")
    
    now = int(datetime.now(timezone.utc).timestamp())
    exp = now + (expiration_days * 24 * 60 * 60)
    jti = str(uuid.uuid4())
    
    return {
        "iss": str(issuer_id),
        "sub": str(subject_id),
        "iat": now,
        "exp": exp,
        "app_role": role,
        "jti": jti
    }


def _base64url_encode(data: bytes) -> str:
    """Base64 URL-safe encoding without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("utf-8")


def sign_rbac_token(payload: dict, private_key_pem: bytes) -> str:
    """
    Signs the RBAC payload with the user's private key using RS256.
    
    Args:
        payload: The JWT payload dict
        private_key_pem: The user's private key in PEM format
        
    Returns:
        str: The complete JWT string (header.payload.signature)
    """
    # Load private key
    private_key = load_pem_private_key(private_key_pem, password=None)
    
    # Create header
    # We include 'kid' (Key ID) which corresponds to the issuer_id
    # This allows the backend to find the public key without peeking at the payload
    issuer_id = payload.get("iss")
    header = {"alg": "RS256", "typ": "JWT", "kid": str(issuer_id)}
    
    # Encode header and payload
    header_b64 = _base64url_encode(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    payload_b64 = _base64url_encode(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    
    # Create signing input
    signing_input = f"{header_b64}.{payload_b64}"
    
    # Sign with RS256 (RSASSA-PKCS1-v1_5 with SHA-256)
    signature = private_key.sign(
        signing_input.encode("utf-8"),
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    
    # Encode signature
    signature_b64 = _base64url_encode(signature)
    
    # Return complete JWT
    return f"{header_b64}.{payload_b64}.{signature_b64}"


def decode_rbac_token(token: str) -> Optional[dict]:
    """
    Decodes an RBAC token WITHOUT verifying the signature.
    Used for displaying token info to the user.
    
    Args:
        token: The JWT string
        
    Returns:
        dict: The payload, or None if invalid
    """
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        
        payload_b64 = parts[1]
        # Add padding
        payload_b64 += "=" * (-len(payload_b64) % 4)
        payload_json = base64.urlsafe_b64decode(payload_b64).decode("utf-8")
        return json.loads(payload_json)
    except Exception:
        return None
