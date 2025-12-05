from typing import Tuple

import os
import base64
import json
import getpass

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cli.core.session import load_token
from cli.core.api import api_get_vault


def derive_key_from_password(password: str, salt: bytes, length: int = 32) -> bytes:
    """
    Derives a symmetric key from a password using PBKDF2-HMAC-SHA256.
    - password: password as text (str)
    - salt: random bytes (unique per user / per vault)
    - length: derived key size, default 32 bytes (256 bits)
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        iterations=480_000,  # high iteration count to hinder brute-force
    )
    return kdf.derive(password.encode("utf-8"))

def encrypt_private_key_with_password(private_pem: bytes, password: str) -> dict:
    """
    Encrypts the private key in PEM format with a password.
    Uses:
      - PBKDF2-HMAC-SHA256 to derive the key
      - AES-256-GCM to encrypt
    Returns a dict ready to be serialized as JSON (vault).
    """
    # 1) Generate random salt (for KDF) and random nonce (for AES-GCM)
    salt = os.urandom(16)   # 128 bits
    nonce = os.urandom(12)  # recommended size for AES-GCM

    # 2) Derive 256-bit symmetric key (32 bytes)
    key = derive_key_from_password(password, salt, length=32)

    # 3) Encrypt private_pem with AES-GCM
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, private_pem, associated_data=None)

    # 4) Return everything in a JSON-serializable "vault" object
    return {
        "kdf": "pbkdf2-hmac-sha256",
        "kdf_iterations": 480000,
        "cipher": "aes-256-gcm",
        "salt": base64.b64encode(salt).decode("utf-8"),
        "nonce": base64.b64encode(nonce).decode("utf-8"),
        "ciphertext": base64.b64encode(ciphertext).decode("utf-8"),
    }

def decrypt_private_key_with_password(vault_obj: dict, password: str) -> bytes:
    """
    Decrypts the vault using the password.
    Returns the private key in PEM format (bytes).
    """
    if vault_obj.get("kdf") != "pbkdf2-hmac-sha256":
        raise ValueError("KDF not supported")
    if vault_obj.get("cipher") != "aes-256-gcm":
        raise ValueError("Cipher not supported")

    salt = base64.b64decode(vault_obj["salt"])
    nonce = base64.b64decode(vault_obj["nonce"])
    ciphertext = base64.b64decode(vault_obj["ciphertext"])

    key = derive_key_from_password(password, salt, length=32)

    aesgcm = AESGCM(key)
    private_pem = aesgcm.decrypt(nonce, ciphertext, associated_data=None)
    return private_pem



def generate_rsa_keypair() -> Tuple[bytes, bytes]:
    """
    Generates an RSA key pair (private and public key) in PEM format.
    Returns (private_pem, public_pem).
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096,  # 4096 bits as suggested in requirements
    )

    # Export private key in PEM, without encryption (we encrypt it ourselves later)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    # Export public key in PEM
    public_key = private_key.public_key()
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    return private_pem, public_pem


def decrypt_vault(encrypted_vault: str, password: str) -> bytes:
    """
    Decrypts the vault JSON string and returns the private key PEM bytes.
    Used for password rotation.
    """
    import json
    vault_obj = json.loads(encrypted_vault)
    
    salt = base64.b64decode(vault_obj["salt"])
    nonce = base64.b64decode(vault_obj["nonce"])
    ciphertext = base64.b64decode(vault_obj["ciphertext"])
    
    encryption_key = derive_key_from_password(password, salt, length=32)
    aesgcm = AESGCM(encryption_key)
    private_key_pem = aesgcm.decrypt(nonce, ciphertext, None)
    
    return private_key_pem


def load_private_key_from_vault() -> object:
    """
    Fetches the vault from the server via API,
    prompts user for password,
    returns a private_key object (RSA) ready to use.
    """

    
    # 1) Get session token
    token = load_token()
    if not token:
        raise ValueError("No active session. Please login first.")
    
    # 2) Fetch vault from server
    vault_json = api_get_vault(token)
    if not vault_json:
        raise FileNotFoundError("Vault not found on server. Was the account activated?")
    
    try:
        vault_obj = json.loads(vault_json)
    except json.JSONDecodeError:
        raise ValueError("Invalid vault received from server.")

    # 3) Prompt user for password
    password = getpass.getpass("Vault password: ")

    # 4) Decrypt
    try:
        private_pem = decrypt_private_key_with_password(vault_obj, password)
    except Exception as e:
        raise ValueError(f"Failed to decrypt vault: {e}")

    # 5) Convert PEM to private_key object
    private_key = load_pem_private_key(private_pem, password=None)

    return private_key

def generate_file_key() -> bytes:
    """
    Generates a symmetric AES-256 File Key (32 bytes).
    """
    return os.urandom(32)

def encrypt_file_with_aes_gcm(file_bytes: bytes, file_key: bytes) -> tuple[bytes, bytes]:
    """
    Encrypts the file with AES-256-GCM.
    Returns (nonce, ciphertext).
    """
    nonce = os.urandom(12)
    aesgcm = AESGCM(file_key)
    ciphertext = aesgcm.encrypt(nonce, file_bytes, None)
    return nonce, ciphertext

def encrypt_file_key_for_user(file_key: bytes, user_public_key_pem: bytes) -> bytes:
    """
    Encrypts the File Key with the recipient's public key (RSA-OAEP).
    """
    public_key = serialization.load_pem_public_key(user_public_key_pem)

    encrypted_key = public_key.encrypt(
        file_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return encrypted_key

def decrypt_file_with_aes_gcm(file_key: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
    """
    Decrypts a file encrypted with AES-256-GCM.
    """
    aesgcm = AESGCM(file_key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, associated_data=None)
    return plaintext