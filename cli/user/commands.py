# cli/user/commands.py
"""
Comandos do utilizador atual (ver info, etc.)
"""
import typer
from cli.core.session import load_token
from cli.core.api import api_get_my_info

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
