from typing import Tuple
import os
import base64
import json

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

def derive_key_from_password(password: str, salt: bytes, length: int = 32) -> bytes:
    """
    Derives a symmetric key from a password using PBKDF2-HMAC-SHA256.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        iterations=480_000,
    )
    return kdf.derive(password.encode("utf-8"))

def encrypt_private_key_with_password(private_pem: bytes, password: str) -> str:
    """
    Encrypts the private key (PEM bytes) with a password using AES-GCM.
    Returns a JSON string representing the vault object.
    """
    # 1) Generate random salt and nonce
    salt = os.urandom(16)   # 128 bits
    nonce = os.urandom(12)  # Recommended for AES-GCM

    # 2) Derive symmetric key
    key = derive_key_from_password(password, salt, length=32)

    # 3) Encrypt private_pem
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, private_pem, associated_data=None)

    # 4) Create vault object
    vault_obj = {
        "kdf": "pbkdf2-hmac-sha256",
        "kdf_iterations": 480000,
        "cipher": "aes-256-gcm",
        "salt": base64.b64encode(salt).decode("utf-8"),
        "nonce": base64.b64encode(nonce).decode("utf-8"),
        "ciphertext": base64.b64encode(ciphertext).decode("utf-8"),
    }
    
    return json.dumps(vault_obj)

def generate_rsa_keypair() -> Tuple[bytes, bytes]:
    """
    Generates a 4096-bit RSA key pair.
    Returns (private_pem, public_pem) as bytes.
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096,
    )

    # Export private key in PEM format (PKCS8, No Encryption - we encrypt manually)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    # Export public key in PEM format (SubjectPublicKeyInfo)
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    return private_pem, public_pem
