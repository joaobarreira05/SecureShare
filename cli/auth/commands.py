# cli/auth/commands.py
import getpass
import re

import typer
import json


from cli.core.session import save_token, load_token, clear_token, is_logged_in
from cli.core.api import api_login, api_logout, api_get_vault
from cli.core.crypto import generate_rsa_keypair, encrypt_private_key_with_password


app = typer.Typer(help="Comandos de autenticação (login, logout)")

USERNAME_REGEX = re.compile(r"^[a-zA-Z0-9_.-]{3,64}$")


@app.command("login")
def login(
    username: str = typer.Option(None, "--username", "-u", help="Nome de utilizador"),
):
    """
    Login no sistema. Apenas permitido se não houver sessão ativa.
    """
    # Verificar se já há sessão ativa
    if is_logged_in():
        typer.echo("Já existe uma sessão ativa. Faz logout primeiro.")
        raise typer.Exit(code=1)

    if username is None:
        username = typer.prompt("Username")

    if not USERNAME_REGEX.match(username):
        typer.echo(
            "Username inválido.\n"
            "Use apenas letras, números, '.', '_' ou '-', com 3 a 64 caracteres."
        )
        raise typer.Exit(code=1)

    password = getpass.getpass("Password: ")

    if len(password) < 3:
        typer.echo("Password demasiado curta (mínimo 8 caracteres).")
        raise typer.Exit(code=1)

    # Login no backend
    token = api_login(username, password)

    if token is None:
        typer.echo("Falha no login (credenciais inválidas ou erro de API).")
        raise typer.Exit(code=1)

    save_token(token)
    typer.echo(f"Login efetuado com sucesso como '{username}'.")


@app.command("logout")
def logout():
    """
    Termina a sessão e apaga o token local.
    """
    token = load_token()
    if token:
        if api_logout(token):
            typer.echo("Logout efetuado no backend.")
        else:
            typer.echo("Aviso: Falha ao fazer logout no backend.")
    
    clear_token()
    typer.echo("Sessão terminada.")


@app.command("activate")
def activate():
    """
    Ativa uma conta. Apenas permitido se não houver sessão ativa.
    """
    # Verificar se já há sessão ativa
    if is_logged_in():
        typer.echo("Já existe uma sessão ativa. Faz logout primeiro.")
        raise typer.Exit(code=1)

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

    # Preparar dados para o backend
    from cli.core.api import api_activate
    activation_data = {
        "username": username,
        "otp": otp,
        "password": password,
        "public_key": public_pem.decode("utf-8"),
        "encrypted_private_key": json.dumps(vault_obj)
    }

    # Chamar API
    if not api_activate(activation_data):
        typer.echo("Falha na ativação. Verifica o OTP e o username.")
        raise typer.Exit(code=1)

    typer.echo("Ativação concluída com sucesso.")
    typer.echo("O vault está guardado no servidor. Podes agora fazer login.")




