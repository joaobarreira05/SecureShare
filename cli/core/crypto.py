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
    Deriva uma chave simétrica a partir de uma password usando PBKDF2-HMAC-SHA256.
    - password: password em texto (str)
    - salt: bytes aleatórios (únicos por utilizador / por vault)
    - length: tamanho da chave derivada, por defeito 32 bytes (256 bits)
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        iterations=480_000,  # número elevado de iterações para dificultar brute-force
    )
    return kdf.derive(password.encode("utf-8"))

def encrypt_private_key_with_password(private_pem: bytes, password: str) -> dict:
    """
    Encripta a chave privada em PEM com uma password.
    Usa:
      - PBKDF2-HMAC-SHA256 para derivar a chave
      - AES-256-GCM para encriptar
    Devolve um dict pronto a ser serializado em JSON (vault).
    """
    # 1) gerar salt aleatório (para KDF) e nonce aleatório (para AES-GCM)
    salt = os.urandom(16)   # 128 bits
    nonce = os.urandom(12)  # tamanho recomendado para AES-GCM

    # 2) derivar chave simétrica de 256 bits (32 bytes)
    key = derive_key_from_password(password, salt, length=32)

    # 3) encriptar private_pem com AES-GCM
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, private_pem, associated_data=None)

    # 4) devolver tudo num objeto "vault" serializável em JSON
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
    Desencripta o vault usando a password.
    Devolve a chave privada em PEM (bytes).
    """
    if vault_obj.get("kdf") != "pbkdf2-hmac-sha256":
        raise ValueError("KDF não suportado")
    if vault_obj.get("cipher") != "aes-256-gcm":
        raise ValueError("Cipher não suportado")

    salt = base64.b64decode(vault_obj["salt"])
    nonce = base64.b64decode(vault_obj["nonce"])
    ciphertext = base64.b64decode(vault_obj["ciphertext"])

    key = derive_key_from_password(password, salt, length=32)

    aesgcm = AESGCM(key)
    private_pem = aesgcm.decrypt(nonce, ciphertext, associated_data=None)
    return private_pem



def generate_rsa_keypair() -> Tuple[bytes, bytes]:
    """
    Gera um par de chaves RSA (chave privada e chave pública) em formato PEM.
    Devolve (private_pem, public_pem).
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096,  # 4096 bits conforme o enunciado sugere
    )

    # Exportar a chave privada em PEM, sem encriptação (vamos encriptar nós depois)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    # Exportar a chave pública em PEM
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
    Busca o vault do servidor via API,
    pede password ao utilizador,
    devolve um objeto private_key (RSA) pronto a usar.
    """

    
    # 1) Obter token de sessão
    token = load_token()
    if not token:
        raise ValueError("Sem sessão ativa. Faz login primeiro.")
    
    # 2) Buscar vault do servidor
    vault_json = api_get_vault(token)
    if not vault_json:
        raise FileNotFoundError("Vault não encontrado no servidor. A conta foi ativada?")
    
    try:
        vault_obj = json.loads(vault_json)
    except json.JSONDecodeError:
        raise ValueError("Vault inválido recebido do servidor.")

    # 3) Pedir password ao user
    password = getpass.getpass("Password do vault: ")

    # 4) Desencriptar
    try:
        private_pem = decrypt_private_key_with_password(vault_obj, password)
    except Exception as e:
        raise ValueError(f"Falha ao desencriptar vault: {e}")

    # 5) Converter PEM → objeto private_key
    private_key = load_pem_private_key(private_pem, password=None)

    return private_key

def generate_file_key() -> bytes:
    """
    Gera uma File Key simétrica AES-256 (32 bytes).
    """
    return os.urandom(32)

def encrypt_file_with_aes_gcm(file_bytes: bytes, file_key: bytes) -> tuple[bytes, bytes]:
    """
    Cifra o ficheiro com AES-256-GCM.
    Devolve (nonce, ciphertext).
    """
    nonce = os.urandom(12)
    aesgcm = AESGCM(file_key)
    ciphertext = aesgcm.encrypt(nonce, file_bytes, None)
    return nonce, ciphertext

def encrypt_file_key_for_user(file_key: bytes, user_public_key_pem: bytes) -> bytes:
    """
    Cifra a File Key com a public key de um destinatário (RSA-OAEP).
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
    Desencripta um ficheiro cifrado com AES-256-GCM.
    """
    aesgcm = AESGCM(file_key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, associated_data=None)
    return plaintext