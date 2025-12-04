from pathlib import Path
from typing import List

import typer
import base64
import json
import getpass

from cli.core.session import load_token
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
from cli.core.config import VAULT_FILE
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes


app = typer.Typer(help="Comandos de transferência de ficheiros (upload/download).")


@app.command("upload")
def upload(
    filepath: str = typer.Argument(..., help="Caminho para o ficheiro a enviar"),
    recipients: List[str] = typer.Option(
        ..., "--to", "-t", help="Usernames dos destinatários"
    ),
):
    """
    Upload E2EE de um ficheiro:
    - gera File Key AES-256
    - cifra ficheiro com AES-GCM
    - cifra File Key com RSA para cada destinatário
    - envia tudo para o backend
    """
    token = load_token()
    if not token:
        typer.echo("Não tens sessão ativa. Faz primeiro `secureshare auth login`.")
        raise typer.Exit(code=1)

    path = Path(filepath)
    if not path.is_file():
        typer.echo(f"Ficheiro não encontrado: {filepath}")
        raise typer.Exit(code=1)

    if not recipients:
        typer.echo("Tens de indicar pelo menos um destinatário com --to username.")
        raise typer.Exit(code=1)

    # 1) Ler ficheiro
    file_bytes = path.read_bytes()

    # 2) Gerar File Key AES
    file_key = generate_file_key()

    # 3) Cifrar ficheiro com AES-GCM
    nonce, encrypted_file = encrypt_file_with_aes_gcm(file_bytes, file_key)

    # 4) Para cada destinatário, ir buscar public key e cifrar a File Key
    encrypted_keys: dict[str, str] = {}

    for username in recipients:
        pubkey_pem = api_get_user_public_key(token, username)
        if not pubkey_pem:
            typer.echo(f"Falha ao obter a chave pública de '{username}'.")
            raise typer.Exit(code=1)

        encrypted_key_bytes = encrypt_file_key_for_user(file_key, pubkey_pem)

        # vamos enviar em base64 para o backend
        import base64

        encrypted_keys[username] = base64.b64encode(encrypted_key_bytes).decode("utf-8")

    # 5) Construir payload para o backend
    import base64

    transfer_data = {
        "filename": path.name,
        "cipher": "AES-256-GCM",
        "nonce": base64.b64encode(nonce).decode("utf-8"),
        "encrypted_file": base64.b64encode(encrypted_file).decode("utf-8"),
        "encrypted_keys": encrypted_keys,
        # campos MLS / expiração / etc. podem entrar aqui mais tarde
    }

    # 6) Chamar API
    ok = api_upload_transfer(token, transfer_data)
    if ok:
        typer.echo("Transferência enviada com sucesso. ")
    else:
        typer.echo("Falha ao enviar transferência (erro no backend ou na rede).")
        raise typer.Exit(code=1)


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
    Download E2EE de um ficheiro:
    - vai buscar metadata + encrypted_file_key
    - vai buscar o ficheiro cifrado
    - abre o vault (pede password)
    - usa a private key para desencriptar a File Key
    - usa a File Key para desencriptar o ficheiro
    """
    token = load_token()
    if not token:
        typer.echo("Não tens sessão ativa. Faz primeiro `secureshare auth login`.")
        raise typer.Exit(code=1)

    # 1) Obter metadata + encrypted_file_key
    meta = api_get_transfer(token, transfer_id)
    if not meta:
        typer.echo("Falha ao obter metadata da transferência.")
        raise typer.Exit(code=1)

    filename = meta.get("filename") or f"transfer_{transfer_id}"
    cipher = meta.get("cipher")
    if cipher != "AES-256-GCM":
        typer.echo(f"Cipher não suportado: {cipher}")
        raise typer.Exit(code=1)

    nonce_b64 = meta.get("nonce")
    encrypted_file_key_b64 = meta.get("encrypted_file_key")
    if not nonce_b64 or not encrypted_file_key_b64:
        typer.echo("Resposta da API em falta (nonce ou encrypted_file_key).")
        raise typer.Exit(code=1)

    nonce = base64.b64decode(nonce_b64)
    encrypted_file_key = base64.b64decode(encrypted_file_key_b64)

    # 2) Obter o ficheiro cifrado (blob)
    encrypted_file = api_download_encrypted_file(token, transfer_id)
    if encrypted_file is None:
        typer.echo("Falha ao descarregar o ficheiro cifrado.")
        raise typer.Exit(code=1)

    # 3) Abrir vault e obter private key
    try:
        private_key = load_private_key_from_vault()
    except Exception as e:
        typer.echo(f"Falha ao carregar a private key a partir do vault: {e}")
        raise typer.Exit(code=1)

    # 4) Desencriptar a File Key com RSA
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

    # 5) Desencriptar o ficheiro com AES-GCM
    try:
        plaintext = decrypt_file_with_aes_gcm(file_key, nonce, encrypted_file)
    except Exception as e:
        typer.echo(f"Falha ao desencriptar o ficheiro: {e}")
        raise typer.Exit(code=1)

    # 6) Guardar o ficheiro em disco
    out_path = Path(output) if output else Path(filename)
    if out_path.exists():
        typer.echo(f"O ficheiro {out_path} já existe. Não vou sobrescrever.")
        raise typer.Exit(code=1)

    out_path.write_bytes(plaintext)
    typer.echo(f"Ficheiro guardado em: {out_path} ")


@app.command("list")
def list_transfers():
    """
    Lista as transferências criadas pelo utilizador atual.
    Mostra: ID, filename, created_at, expires_at, nível (se existir).
    """
    token = load_token()
    if not token:
        typer.echo("Não tens sessão ativa. Faz primeiro `secureshare auth login`.")
        raise typer.Exit(code=1)

    transfers = api_list_transfers(token)
    if transfers is None:
        typer.echo("Falha ao obter a lista de transferências (erro na API).")
        raise typer.Exit(code=1)

    if not transfers:
        typer.echo("Ainda não tens transferências criadas.")
        raise typer.Exit(code=0)

    # Cabeçalho simples
    typer.echo(f"{'ID':36}  {'Ficheiro':20}  {'Criado em':19}  {'Expira em':19}  {'Nível'}")
    typer.echo("-" * 100)

    for t in transfers:
        tid = str(t.get("id", ""))[:36]
        filename = str(t.get("filename", ""))[:20]
        created_at = str(t.get("created_at", ""))[:19]
        expires_at = str(t.get("expires_at", ""))[:19]

        classification = t.get("classification") or {}
        level = classification.get("level", "")

        typer.echo(f"{tid:36}  {filename:20}  {created_at:19}  {expires_at:19}  {level}")

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

    ok = api_delete_transfer(token, transfer_id)
    if ok:
        typer.echo(f"Transferência '{transfer_id}' apagada com sucesso. 🗑️")
    else:
        typer.echo("Falha ao apagar transferência (erro na API ou permissões).")
        raise typer.Exit(code=1)

