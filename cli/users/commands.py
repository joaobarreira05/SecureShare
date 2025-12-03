import typer
import re
from typing import Optional
from cli.core.session import load_token
from cli.core.api import api_create_user

app = typer.Typer(help="Comandos de gestão de utilizadores (create, list, etc.)")

USERNAME_REGEX = re.compile(r"^[a-zA-Z0-9_.-]{3,64}$")
EMAIL_REGEX = re.compile(r"^[\w\.-]+@[\w\.-]+\.\w+$")

@app.command("create")
def create_user():
    """
    Cria um novo utilizador (Admin only).
    Pede: username, otp, email, full_name.
    """
    token = load_token()
    if not token:
        typer.echo("Não tens sessão ativa. Faz primeiro `secureshare auth login` como Admin.")
        raise typer.Exit(code=1)

    username = typer.prompt("Username")
    if not USERNAME_REGEX.match(username):
        typer.echo("Username inválido.")
        raise typer.Exit(code=1)

    otp = typer.prompt("OTP (One Time Password)")
    if not otp.strip():
        typer.echo("OTP não pode ser vazio.")
        raise typer.Exit(code=1)

    email = typer.prompt("Email")
    if not EMAIL_REGEX.match(email):
        typer.echo("Email inválido.")
        raise typer.Exit(code=1)

    full_name = typer.prompt("Nome Completo")
    if not full_name.strip():
        typer.echo("Nome não pode ser vazio.")
        raise typer.Exit(code=1)

    user_data = {
        "username": username,
        "otp": otp,
        "email": email,
        "full_name": full_name
    }

    if api_create_user(token, user_data):
        typer.echo(f"Utilizador '{username}' criado com sucesso!")
    else:
        typer.echo("Falha ao criar utilizador. Verifica se tens permissões de Admin ou se o user já existe.")
        raise typer.Exit(code=1)
