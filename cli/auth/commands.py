import getpass
import re

import typer

from cli.core.session import save_token, load_token, clear_token

app = typer.Typer(help="Comandos de autenticação (login, me, logout)")


USERNAME_REGEX = re.compile(r"^[a-zA-Z0-9_.-]{3,64}$")
# permite letras, números, underscore, ponto e hífen
# tamanho entre 3 e 64 chars


@app.command("login")
def login(
    username: str = typer.Option(None, "--username", "-u", help="Nome de utilizador"),
):
    """
    (Versão sem backend)
    Pede username e password, valida o username, gera um token falso e guarda-o.
    """
    # 1) Ler username se não vier por opção
    if username is None:
        username = typer.prompt("Username")

    # 2) Validar username
    if not USERNAME_REGEX.match(username):
        typer.echo(
            "Username inválido.\n"
            "Use apenas letras, números, '.', '_' ou '-', com 3 a 64 caracteres."
        )
        raise typer.Exit(code=1)

    # 3) Ler password (sem eco)
    password = getpass.getpass("Password: ")

    if len(password) < 8:
        typer.echo("Password demasiado curta (mínimo 8 caracteres).")
        raise typer.Exit(code=1)

    # 4) Gerar token falso (por agora)
    fake_token = f"fake-token-for-{username}"

    # 5) Guardar token em ~/.secureshare/session.json
    save_token(fake_token)

    typer.echo("Login efetuado (token falso guardado).")



@app.command("me")
def me():
    """
    Mostra informação baseada no token guardado (neste caso, só o próprio token).
    """
    token = load_token()
    if not token:
        typer.echo("Não tens sessão ativa. Faz primeiro `secureshare auth login`.")
        raise typer.Exit(code=1)

    typer.echo("Sessão atual (token guardado):")
    typer.echo(token)


@app.command("logout")
def logout():
    """
    Apaga o token guardado (termina a sessão local).
    """
    clear_token()
    typer.echo("Sessão terminada (token removido).")
