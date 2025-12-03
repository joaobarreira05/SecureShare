# cli/main.py
import typer

from cli.auth.commands import app as auth_app
from cli.users.commands import app as users_app

app = typer.Typer(help="SecureShare CLI")

# adiciona o grupo 'auth'
app.add_typer(auth_app, name="auth")
# adiciona o grupo 'users'
app.add_typer(users_app, name="users")


@app.command()
def hello(name: str = "mundo"):
    """
    Comando de teste: diz olá.
    """
    typer.echo(f"Olá, {name}!")


def main():
    app()


if __name__ == "__main__":
    main()
