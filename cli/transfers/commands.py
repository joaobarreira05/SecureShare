from pathlib import Path
from typing import List, Optional
import tempfile
import os

import typer
import base64
import json
from datetime import datetime, timedelta, timezone

from cli.core.session import load_token, load_mls_token
from cli.core.api import (
    api_get_user_by_username,
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
from cli.core.config import VAULT_FILE, BASE_URL
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes


LEVEL_MAP = {
    "TOP_SECRET": 4,
    "SECRET": 3,
    "CONFIDENTIAL": 2,
    "UNCLASSIFIED": 1
}

app = typer.Typer(help="Comandos de transferência de ficheiros (upload/download).")


@app.command("upload")
def upload(
    filepath: str = typer.Argument(..., help="Caminho para o ficheiro a enviar"),
    recipients: Optional[List[str]] = typer.Option(
        None, "--to", "-t", help="Usernames dos destinatários (obrigatório se não for público)"
    ),
    level: str = typer.Option("UNCLASSIFIED", "--level", "-l", help="Nível de segurança (TOP_SECRET, SECRET, CONFIDENTIAL, UNCLASSIFIED)"),
    departments: Optional[List[str]] = typer.Option(None, "--dept", "-d", help="Departamentos associados"),
    expire_days: int = typer.Option(7, "--expire-days", help="Dias para expirar"),
    public: bool = typer.Option(False, "--public", help="Criar partilha pública (link com chave)"),
):
    """
    Upload E2EE de um ficheiro.
    Suporta MLS (verificação de nível/departamentos) e partilhas públicas.
    """
    token = load_token()
    if not token:
        typer.echo("Não tens sessão ativa. Faz primeiro `secureshare auth login`.")
        raise typer.Exit(code=1)

    mls_token = load_mls_token()
    
    # Validação de argumentos
    if not public and not recipients:
        typer.echo("Tens de indicar pelo menos um destinatário com --to username (ou usar --public).")
        raise typer.Exit(code=1)

    path = Path(filepath)
    if not path.is_file():
        typer.echo(f"Ficheiro não encontrado: {filepath}")
        raise typer.Exit(code=1)

    # Validar Nível
    if level not in LEVEL_MAP:
        typer.echo(f"Nível inválido. Opções: {', '.join(LEVEL_MAP.keys())}")
        raise typer.Exit(code=1)

    # --- MLS Checks (Client Side) ---
    if mls_token:
        try:
            payload_b64 = mls_token.split(".")[1]
            payload_b64 += "=" * (-len(payload_b64) % 4)
            payload = json.loads(base64.urlsafe_b64decode(payload_b64))
            
            user_level = payload.get("clearance", "UNCLASSIFIED")
            user_depts = set(payload.get("departments", []))
            
            # No Write Down: User Level <= File Level
            if LEVEL_MAP.get(user_level, 1) > LEVEL_MAP.get(level, 1):
                typer.echo(f"Erro MLS: Não podes fazer upload com nível {level} (o teu nível é {user_level}). Regra: User Level <= File Level.")
                raise typer.Exit(code=1)

            # Departments Subset
            file_depts = set(departments or [])
            if not file_depts.issubset(user_depts):
                missing = file_depts - user_depts
                typer.echo(f"Erro MLS: Não tens acesso aos departamentos: {', '.join(missing)}")
                raise typer.Exit(code=1)

        except typer.Exit:
            raise
        except Exception as e:
            typer.echo(f"Aviso: Não foi possível validar regras MLS localmente ({e}). O backend fará a validação final.")

    # 1) Ler ficheiro
    file_bytes = path.read_bytes()

    # 2) Gerar File Key AES
    file_key = generate_file_key()

    # 3) Cifrar ficheiro com AES-GCM
    nonce, encrypted_file = encrypt_file_with_aes_gcm(file_bytes, file_key)
    
    # Prepend nonce to encrypted file (backend should store this way or we send separately)
    # Backend model doesn't have nonce field - it expects nonce prepended to file.
    encrypted_blob = nonce + encrypted_file

    # 4) Resolver recipients -> IDs e cifrar chaves
    recipient_keys: List[dict] = []
    
    if not public and recipients:
        for username in recipients:
            # Obter user info por username
            user_info = api_get_user_by_username(token, username)
            if not user_info:
                typer.echo(f"Utilizador '{username}' não encontrado.")
                raise typer.Exit(code=1)
            
            user_id = user_info.get("id")
            if not user_id:
                typer.echo(f"Falha ao obter ID do utilizador '{username}'.")
                raise typer.Exit(code=1)

            # Obter public key
            pubkey_pem = api_get_user_public_key(token, user_id)
            if not pubkey_pem:
                typer.echo(f"Falha ao obter a chave pública de '{username}'.")
                raise typer.Exit(code=1)

            encrypted_key_bytes = encrypt_file_key_for_user(file_key, pubkey_pem)
            
            recipient_keys.append({
                "recipient_id": user_id,
                "encrypted_key": base64.b64encode(encrypted_key_bytes).decode("utf-8")
            })

    # 5) Escrever ficheiro cifrado para temp file (para multipart upload)
    with tempfile.NamedTemporaryFile(delete=False, suffix=".enc") as tmp:
        tmp.write(encrypted_blob)
        tmp_path = tmp.name

    try:
        # 6) Chamar API (multipart form)
        transfer_id = api_upload_transfer(
            token=token,
            file_path=tmp_path,
            classification=level,
            departments=departments or [],
            recipient_keys=recipient_keys,
            expires_in_days=expire_days,
            mls_token=mls_token
        )
        
        if transfer_id:
            typer.echo("Transferência enviada com sucesso! 🚀")
            typer.echo(f"ID: {transfer_id}")
            if public:
                key_b64 = base64.urlsafe_b64encode(file_key).decode("utf-8")
                typer.echo(f"Link público: {BASE_URL}/transfers/download/{transfer_id}#{key_b64}")
        else:
            typer.echo("Falha ao enviar transferência (erro no backend ou na rede).")
            raise typer.Exit(code=1)
    finally:
        # Limpar ficheiro temporário
        os.unlink(tmp_path)


@app.command("download")
def download(
    transfer_id: str = typer.Argument(..., help="ID da transferência a descarregar"),
    output: str = typer.Option(
        None,
        "--output",
        "-o",
        help="Caminho para guardar o ficheiro (por omissão usa o filename da transferência)",
    ),
):
    """
    Download E2EE de um ficheiro.
    """
    token = load_token()
    if not token:
        typer.echo("Não tens sessão ativa. Faz primeiro `secureshare auth login`.")
        raise typer.Exit(code=1)

    mls_token = load_mls_token()

    # Suporte para Link Público (URL com fragmento)
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

    # 1) Obter metadata
    meta = api_get_transfer(token, transfer_id, mls_token=mls_token)
    if not meta:
        typer.echo("Falha ao obter metadata da transferência.")
        raise typer.Exit(code=1)

    filename = meta.get("filename") or f"transfer_{transfer_id}"
    
    file_key = None
    encrypted_file_key = None
    
    # Se temos fragmento público, usamos diretamente
    if public_key_fragment:
        try:
            pk = public_key_fragment
            pk += "=" * (-len(pk) % 4)
            file_key = base64.urlsafe_b64decode(pk)
            typer.echo("Usando chave fornecida no link público.")
        except Exception as e:
            typer.echo(f"Erro ao descodificar chave do link: {e}")
            raise typer.Exit(code=1)
    else:
        # Fluxo normal - encrypted_key vem da metadata
        encrypted_key_b64 = meta.get("encrypted_key")
        if not encrypted_key_b64:
            typer.echo("Esta transferência não tem chave cifrada para ti.")
            raise typer.Exit(code=1)
             
        encrypted_file_key = base64.b64decode(encrypted_key_b64)

    # 2) Obter o ficheiro cifrado (blob)
    encrypted_blob = api_download_encrypted_file(token, transfer_id, mls_token=mls_token)
    if encrypted_blob is None:
        typer.echo("Falha ao descarregar o ficheiro cifrado.")
        raise typer.Exit(code=1)

    # Nonce está prepended ao ficheiro (12 bytes para GCM)
    nonce = encrypted_blob[:12]
    encrypted_file = encrypted_blob[12:]

    # 3) Se ainda não temos file_key, desencriptar com RSA
    if not file_key:
        try:
            private_key = load_private_key_from_vault()
        except Exception as e:
            typer.echo(f"Falha ao carregar a private key a partir do vault: {e}")
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
            typer.echo(f"Falha ao desencriptar a File Key: {e}")
            raise typer.Exit(code=1)

    # 4) Desencriptar o ficheiro com AES-GCM
    try:
        plaintext = decrypt_file_with_aes_gcm(file_key, nonce, encrypted_file)
    except Exception as e:
        typer.echo(f"Falha ao desencriptar o ficheiro: {e}")
        raise typer.Exit(code=1)

    # 5) Guardar o ficheiro em disco
    out_path = Path(output) if output else Path(filename)
    if out_path.exists():
        typer.echo(f"O ficheiro {out_path} já existe. Não vou sobrescrever.")
        raise typer.Exit(code=1)

    out_path.write_bytes(plaintext)
    typer.echo(f"Ficheiro guardado em: {out_path} ✅")


@app.command("list")
def list_transfers():
    """
    Lista as transferências criadas pelo utilizador atual.
    """
    token = load_token()
    if not token:
        typer.echo("Não tens sessão ativa. Faz primeiro `secureshare auth login`.")
        raise typer.Exit(code=1)

    mls_token = load_mls_token()

    transfers = api_list_transfers(token, mls_token=mls_token)
    if transfers is None:
        typer.echo("Falha ao obter a lista de transferências (erro na API).")
        raise typer.Exit(code=1)

    if not transfers:
        typer.echo("Ainda não tens transferências criadas.")
        raise typer.Exit(code=0)

    typer.echo(f"{'ID':36}  {'Ficheiro':20}  {'Expira em':19}  {'Nível'}")
    typer.echo("-" * 90)

    for t in transfers:
        tid = str(t.get("id", ""))[:36]
        filename = str(t.get("filename", ""))[:20]
        expires_at = str(t.get("expires_at", ""))[:19]
        level = t.get("classification_level", "")

        typer.echo(f"{tid:36}  {filename:20}  {expires_at:19}  {level}")


@app.command("delete")
def delete_transfer(
    transfer_id: str = typer.Argument(..., help="ID da transferência a apagar"),
    force: bool = typer.Option(
        False,
        "--force",
        "-f",
        help="Não pedir confirmação antes de apagar",
    ),
):
    """
    Apaga uma transferência (metadata + ficheiro) do servidor.
    """
    token = load_token()
    if not token:
        typer.echo("Não tens sessão ativa. Faz primeiro `secureshare auth login`.")
        raise typer.Exit(code=1)

    if not force:
        confirm = typer.confirm(
            f"Tens a certeza que queres apagar a transferência '{transfer_id}'?"
        )
        if not confirm:
            typer.echo("Operação cancelada.")
            raise typer.Exit(code=0)

    mls_token = load_mls_token()
    ok = api_delete_transfer(token, transfer_id, mls_token=mls_token)
    if ok:
        typer.echo(f"Transferência '{transfer_id}' apagada com sucesso. 🗑️")
    else:
        typer.echo("Falha ao apagar transferência (erro na API ou permissões).")
        raise typer.Exit(code=1)
