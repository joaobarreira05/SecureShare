# cli/auth/commands.py
import getpass
import re

import typer
import json


from cli.core.session import save_token, load_token, clear_token
from cli.core.api import api_login, api_get_me
from cli.core.crypto import generate_rsa_keypair, encrypt_private_key_with_password
from cli.core.config import VAULT_FILE, PUBLIC_KEY_FILE


app = typer.Typer(help="Comandos de autenticação (login, me, logout)")

USERNAME_REGEX = re.compile(r"^[a-zA-Z0-9_.-]{3,64}$")


@app.command("login")
def login(
    username: str = typer.Option(None, "--username", "-u", help="Nome de utilizador"),
):
    """
    Login:
    - Fase 1: usa api_login() fake (sem backend)
    - Fase 2: api_login() passa a chamar /auth/login
    """
    if username is None:
        username = typer.prompt("Username")

    if not USERNAME_REGEX.match(username):
        typer.echo(
            "Username inválido.\n"
            "Use apenas letras, números, '.', '_' ou '-', com 3 a 64 caracteres."
        )
        raise typer.Exit(code=1)

    password = getpass.getpass("Password: ")

    if len(password) < 8:
        typer.echo("Password demasiado curta (mínimo 8 caracteres).")
        raise typer.Exit(code=1)

    # 🔗 Chamada à “API” (neste momento, fake)
    token = api_login(username, password)

    if token is None:
        typer.echo("Falha no login (credenciais inválidas ou erro de API).")
        raise typer.Exit(code=1)

    save_token(token)
    typer.echo("Login efetuado com sucesso (token guardado).")


@app.command("me")
def me():
    """
    Mostra info do utilizador autenticado:
    - Fase 1: usa api_get_me() fake.
    - Fase 2: api_get_me() chama /auth/me de verdade.
    """
    token = load_token()
    if not token:
        typer.echo("Não tens sessão ativa. Faz primeiro `secureshare auth login`.")
        raise typer.Exit(code=1)

    user_info = api_get_me(token)
    if user_info is None:
        typer.echo("Token inválido ou sessão expirada. Faz login outra vez.")
        raise typer.Exit(code=1)

    typer.echo("Utilizador autenticado:")
    typer.echo(f"  ID:        {user_info.get('id')}")
    typer.echo(f"  Username:  {user_info.get('username')}")
    typer.echo(f"  Email:     {user_info.get('email')}")
    typer.echo(f"  Ativo:     {user_info.get('is_active')}")


@app.command("logout")
def logout():
    """
    Termina a sessão local (apaga token guardado).
    """
    clear_token()
    typer.echo("Sessão terminada (token removido).")

@app.command("activate")
def activate():
    """
    Ativa a conta localmente:
    - Valida username, OTP, password.
    - Gera par de chaves RSA.
    - Encripta a chave privada com a password (vault).
    - Guarda vault.json e public_key.pem em ~/.secureshare.
    """
    username = typer.prompt("Username")

    if not USERNAME_REGEX.match(username):
        typer.echo(
            "Username inválido. Use apenas letras, números, '.', '_' ou '-', com 3 a 64 caracteres."
        )
        raise typer.Exit(code=1)

    otp = typer.prompt("OTP (código de ativação fornecido pelo administrador)")
    if not otp.strip():
        typer.echo("OTP não pode ser vazia.")
        raise typer.Exit(code=1)

    password = getpass.getpass("Nova password: ")
    password_confirm = getpass.getpass("Confirmação da password: ")

    if password != password_confirm:
        typer.echo("As passwords não coincidem.")
        raise typer.Exit(code=1)

    if len(password) < 8:
        typer.echo("Password demasiado curta (mínimo 8 caracteres).")
        raise typer.Exit(code=1)

    # Gerar chaves RSA
    private_pem, public_pem = generate_rsa_keypair()

    # Criar vault (private key encriptada com password)
    vault_obj = encrypt_private_key_with_password(private_pem, password)

    # Guardar vault.json
    with open(VAULT_FILE, "w", encoding="utf-8") as f:
        json.dump(vault_obj, f, indent=2)

    # Guardar chave pública
    with open(PUBLIC_KEY_FILE, "wb") as f:
        f.write(public_pem)

    typer.echo(f"Vault criado em: {VAULT_FILE}")
    typer.echo(f"Chave pública guardada em: {PUBLIC_KEY_FILE}")
    typer.echo("Ativação concluída.")


