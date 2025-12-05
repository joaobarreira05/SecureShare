# cli/user/commands.py
"""
Comandos do utilizador atual (ver info, etc.)
"""
import typer
from cli.core.session import load_token
from cli.core.api import api_get_my_info, api_update_my_info

app = typer.Typer(help="Comandos do utilizador atual (info, etc.)")


@app.command("me")
def me():
    """
    Mostra informação do utilizador atual.
    """
    token = load_token()
    if not token:
        typer.echo("Não tens sessão ativa. Faz primeiro login.")
        raise typer.Exit(code=1)

    info = api_get_my_info(token)
    if not info:
        typer.echo("Falha ao obter informação do utilizador.")
        raise typer.Exit(code=1)

    typer.echo("\n👤 Informação do Utilizador:")
    typer.echo(f"   ID:       {info.get('id', '-')}")
    typer.echo(f"   Username: {info.get('username', '-')}")
    typer.echo(f"   Email:    {info.get('email', '-')}")
    typer.echo(f"   Nome:     {info.get('full_name', '-')}")
    typer.echo(f"   Ativo:    {'✅' if info.get('is_active') else '❌'}")
    typer.echo(f"   Admin:    {'✅' if info.get('is_admin') else '❌'}")


@app.command("update-password")
def update_password():
    """
    Altera a password do utilizador atual.
    """
    token = load_token()
    if not token:
        typer.echo("Não tens sessão ativa. Faz primeiro login.")
        raise typer.Exit(code=1)

    new_password = typer.prompt("Nova password", hide_input=True)
    confirm_password = typer.prompt("Confirma password", hide_input=True)

    if new_password != confirm_password:
        typer.echo("As passwords não coincidem.")
        raise typer.Exit(code=1)

    if len(new_password) < 8:
        typer.echo("A password deve ter pelo menos 8 caracteres.")
        raise typer.Exit(code=1)

    if api_update_my_info(token, {"password": new_password}):
        typer.echo("Password alterada com sucesso! 🔐")
    else:
        typer.echo("Falha ao alterar password.")
        raise typer.Exit(code=1)


@app.command("update-info")
def update_info(
    email: str = typer.Option(None, "--email", "-e", help="Novo email"),
    name: str = typer.Option(None, "--name", "-n", help="Novo nome completo"),
):
    """
    Atualiza informações do utilizador (email, nome).
    """
    token = load_token()
    if not token:
        typer.echo("Não tens sessão ativa. Faz primeiro login.")
        raise typer.Exit(code=1)

    if not email and not name:
        typer.echo("Indica pelo menos um campo para atualizar (--email ou --name).")
        raise typer.Exit(code=1)

    update_data = {}
    if email:
        update_data["email"] = email
    if name:
        update_data["full_name"] = name

    if api_update_my_info(token, update_data):
        typer.echo("Informação atualizada com sucesso! ✅")
    else:
        typer.echo("Falha ao atualizar informação.")
        raise typer.Exit(code=1)
