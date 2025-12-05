from pathlib import Path
from typing import List, Optional
import tempfile
import os

import typer
import base64
import json
from datetime import datetime, timedelta, timezone

from cli.core.session import load_token, load_mls_token, load_rbac_token
from cli.core.api import (
    api_get_user_public_key,
    api_upload_transfer,
    api_get_transfer,
    api_download_encrypted_file,
    api_list_transfers,
    api_delete_transfer,
)
from cli.core.crypto import (
    generate_file_key,
    encrypt_file_with_aes_gcm,
    encrypt_file_key_for_user,
    decrypt_file_with_aes_gcm,
    load_private_key_from_vault
)
from cli.core.config import BASE_URL
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes


LEVEL_MAP = {
    "TOP_SECRET": 4,
    "SECRET": 3,
    "CONFIDENTIAL": 2,
    "UNCLASSIFIED": 1
}

app = typer.Typer(help="File transfer commands (upload/download).")


@app.command("upload")
def upload(
    filepath: str = typer.Argument(..., help="Path to the file to upload"),
    recipients: Optional[List[int]] = typer.Option(
        None, "--to", "-t", help="Recipient IDs (required if not public)"
    ),
    level: str = typer.Option("UNCLASSIFIED", "--level", "-l", help="Security level (TOP_SECRET, SECRET, CONFIDENTIAL, UNCLASSIFIED)"),
    departments: Optional[List[str]] = typer.Option(None, "--dept", "-d", help="Associated departments"),
    expire_days: int = typer.Option(7, "--expire-days", help="Days until expiration"),
    public: bool = typer.Option(False, "--public", help="Create public share (link with key)"),
    justification: Optional[str] = typer.Option(None, "--justification", "-j", help="Justification for MLS bypass (Trusted Officer)"),
):
    """
    E2EE file upload.
    Use --to ID to specify recipients or --public for public share.
    Trusted Officers can use --justification for MLS bypass.
    """
    token = load_token()
    if not token:
        typer.echo("No active session. Please login first.")
        raise typer.Exit(code=1)

    # Validate arguments
    if not public and not recipients:
        typer.echo("You must specify at least one recipient (--to ID) or use --public.")
        raise typer.Exit(code=1)

    path = Path(filepath)
    # If file not found, try in current working directory
    if not path.is_file():
        path = Path.cwd() / filepath
    if not path.is_file():
        typer.echo(f"File not found: {filepath}")
        raise typer.Exit(code=1)

    # For public transfers: no level/departments (always UNCLASSIFIED and empty)
    if public:
        level = "UNCLASSIFIED"
        departments = []
    else:
        # Validate level only for private transfers
        if level not in LEVEL_MAP:
            typer.echo(f"Invalid level. Options: {', '.join(LEVEL_MAP.keys())}")
            raise typer.Exit(code=1)

    mls_token = load_mls_token()
    
    # --- MLS Checks (Client Side) - Only for private shares ---
    if not public and mls_token:
        try:
            payload_b64 = mls_token.split(".")[1]
            payload_b64 += "=" * (-len(payload_b64) % 4)
            payload = json.loads(base64.urlsafe_b64decode(payload_b64))
            
            user_level = payload.get("clearance", "UNCLASSIFIED")
            user_depts = set(payload.get("departments", []))
            
            # No Write Down: User Level <= File Level
            if LEVEL_MAP.get(user_level, 1) > LEVEL_MAP.get(level, 1):
                typer.echo(f"MLS Error: You cannot upload with level {level} (your level is {user_level}).")
                raise typer.Exit(code=1)

            # Departments Subset
            file_depts = set(departments or [])
            if not file_depts.issubset(user_depts):
                missing = file_depts - user_depts
                typer.echo(f"MLS Error: You don't have access to departments: {', '.join(missing)}")
                raise typer.Exit(code=1)

        except typer.Exit:
            raise
        except Exception as e:
            typer.echo(f"Warning: Could not validate MLS rules ({e}). Backend will perform final validation.")

    # 1) Read file
    file_data = path.read_bytes()
    filename = path.name

    # 2) Generate AES File Key
    file_key = generate_file_key()

    # 3) Encrypt file with AES-GCM
    nonce, encrypted_file = encrypt_file_with_aes_gcm(file_data, file_key)
    encrypted_blob = nonce + encrypted_file


    # 4) Resolve recipients -> IDs and encrypt keys
    recipient_keys: List[dict] = []
    
    if not public and recipients:
        for user_id in recipients:
            # Get public key directly by ID
            pubkey_pem = api_get_user_public_key(token, user_id)
            if not pubkey_pem:
                typer.echo(f"Failed to get public key for user ID {user_id}.")
                raise typer.Exit(code=1)

            # Convert to bytes if needed
            if isinstance(pubkey_pem, str):
                pubkey_pem = pubkey_pem.encode("utf-8")
            
            encrypted_key_bytes = encrypt_file_key_for_user(file_key, pubkey_pem)
            
            recipient_keys.append({
                "recipient_id": user_id,
                "encrypted_key": base64.b64encode(encrypted_key_bytes).decode("utf-8")
            })

    # 5) Write encrypted file to temp file (for multipart upload)
    with tempfile.NamedTemporaryFile(delete=False, suffix=".enc") as tmp:
        tmp.write(encrypted_blob)
        tmp_path = tmp.name

    try:
        # 6) Call API (multipart form)
        # If there's justification, load RBAC token (for Trusted Officer)
        rbac_token = load_rbac_token() if justification else None
        
        transfer_id = api_upload_transfer(
            token=token,
            file_path=tmp_path,
            classification=level,
            departments=departments or [],
            recipient_keys=recipient_keys,
            expires_in_days=expire_days,
            mls_token=mls_token,
            is_public=public,
            rbac_token=rbac_token,
            justification=justification
        )
        
        if transfer_id:
            typer.echo("Transfer sent successfully! 🚀")
            typer.echo(f"ID: {transfer_id}")
            if public:
                key_b64 = base64.urlsafe_b64encode(file_key).decode("utf-8")
                typer.echo(f"Public link: {BASE_URL}/transfers/download/{transfer_id}#{key_b64}")
        else:
            typer.echo("Failed to send transfer (backend or network error).")
            raise typer.Exit(code=1)
    finally:
        # Clean up temp file
        os.unlink(tmp_path)


@app.command("download")
def download(
    transfer_id: str = typer.Argument(..., help="Transfer ID to download"),
    output: str = typer.Option(
        None,
        "--output",
        "-o",
        help="Path to save the file (defaults to transfer filename)",
    ),
    justification: Optional[str] = typer.Option(None, "--justification", "-j", help="Justification for MLS bypass (Trusted Officer)"),
):
    """
    E2EE file download.
    Trusted Officers can use --justification for MLS bypass.
    """
    token = load_token()
    if not token:
        typer.echo("No active session. Please login first.")
        raise typer.Exit(code=1)

    mls_token = load_mls_token()
    rbac_token = load_rbac_token() if justification else None

    # Public Link Support (URL with fragment)
    public_key_fragment = None
    if "http" in transfer_id and "#" in transfer_id:
        try:
            url_part, fragment = transfer_id.split("#", 1)
            public_key_fragment = fragment
            if "/download/" in url_part:
                transfer_id = url_part.split("/download/")[-1]
            else:
                transfer_id = url_part.split("/")[-1]
        except Exception:
            pass

    # 1) Get metadata
    meta = api_get_transfer(token, transfer_id, mls_token=mls_token, rbac_token=rbac_token, justification=justification)
    if not meta:
        typer.echo("Failed to get transfer metadata.")
        raise typer.Exit(code=1)

    filename = meta.get("filename") or f"transfer_{transfer_id}"
    
    file_key = None
    encrypted_file_key = None
    
    # If we have public fragment, use directly
    if public_key_fragment:
        try:
            pk = public_key_fragment
            pk += "=" * (-len(pk) % 4)
            file_key = base64.urlsafe_b64decode(pk)
            typer.echo("Using key from public link.")
        except Exception as e:
            typer.echo(f"Error decoding link key: {e}")
            raise typer.Exit(code=1)
    elif meta.get("is_public"):
        # Transfer is public but we don't have the key - need full link
        typer.echo("This is a public transfer. Use the complete link with key:")
        typer.echo(f"  python3 -m cli.main transfers download '<LINK_WITH_KEY>'")
        raise typer.Exit(code=1)
    else:
        # Normal flow - encrypted_key comes from metadata
        encrypted_key_b64 = meta.get("encrypted_key")
        if not encrypted_key_b64:
            typer.echo("This transfer has no encrypted key for you.")
            raise typer.Exit(code=1)
             
        encrypted_file_key = base64.b64decode(encrypted_key_b64)

    # 2) Get the encrypted file (blob)
    encrypted_blob = api_download_encrypted_file(token, transfer_id, mls_token=mls_token, rbac_token=rbac_token, justification=justification)
    if encrypted_blob is None:
        typer.echo("Failed to download encrypted file.")
        raise typer.Exit(code=1)

    # Nonce está prepended ao ficheiro (12 bytes para GCM)
    nonce = encrypted_blob[:12]
    encrypted_file = encrypted_blob[12:]

    # 3) If we don't have file_key yet, decrypt with RSA
    if not file_key:
        try:
            private_key = load_private_key_from_vault()
        except Exception as e:
            typer.echo(f"Failed to load private key from vault: {e}")
            raise typer.Exit(code=1)

        try:
            file_key = private_key.decrypt(
                encrypted_file_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            )
        except Exception as e:
            typer.echo(f"Failed to decrypt File Key: {e}")
            raise typer.Exit(code=1)

    # 4) Decrypt file with AES-GCM
    try:
        plaintext = decrypt_file_with_aes_gcm(file_key, nonce, encrypted_file)
    except Exception as e:
        typer.echo(f"Failed to decrypt file: {e}")
        raise typer.Exit(code=1)

    # 5) Save file to disk
    out_path = Path(output) if output else Path(filename)
    if out_path.exists():
        typer.echo(f"File {out_path} already exists. Not overwriting.")
        raise typer.Exit(code=1)

    out_path.write_bytes(plaintext)
    typer.echo(f"File saved to: {out_path} 🗸")


@app.command("list")
def list_transfers():
    """
    Lists transfers created by the current user.
    """
    token = load_token()
    if not token:
        typer.echo("No active session. Please login first.")
        raise typer.Exit(code=1)

    mls_token = load_mls_token()

    transfers = api_list_transfers(token, mls_token=mls_token)
    if transfers is None:
        typer.echo("Failed to get transfers list (API error).")
        raise typer.Exit(code=1)

    if not transfers:
        typer.echo("You have no transfers yet.")
        raise typer.Exit(code=0)

    typer.echo(f"{'ID':36}  {'Filename':20}  {'Expires at':19}  {'Level'}")
    typer.echo("-" * 90)

    for t in transfers:
        tid = str(t.get("id", ""))[:36]
        filename = str(t.get("filename", ""))[:20]
        expires_at = str(t.get("expires_at", ""))[:19]
        level = t.get("classification_level", "")

        typer.echo(f"{tid:36}  {filename:20}  {expires_at:19}  {level}")


@app.command("delete")
def delete_transfer(
    transfer_id: str = typer.Argument(..., help="Transfer ID to delete"),
    force: bool = typer.Option(
        False,
        "--force",
        "-f",
        help="Skip confirmation before deleting",
    ),
):
    """
    Deletes a transfer (metadata + file) from the server.
    """
    token = load_token()
    if not token:
        typer.echo("No active session. Please login first.")
        raise typer.Exit(code=1)

    if not force:
        confirm = typer.confirm(
            f"Are you sure you want to delete transfer '{transfer_id}'?"
        )
        if not confirm:
            typer.echo("Operation cancelled.")
            raise typer.Exit(code=0)

    mls_token = load_mls_token()
    ok = api_delete_transfer(token, transfer_id, mls_token=mls_token)
    if ok:
        typer.echo(f"Transfer '{transfer_id}' deleted successfully. 🗑️")
    else:
        typer.echo("Failed to delete transfer (API error or permissions).")
        raise typer.Exit(code=1)
