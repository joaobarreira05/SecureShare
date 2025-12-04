# cli/main.py


import typer
from cli.auth.commands import app as auth_app
from cli.users.commands import app as users_app
from cli.transfers.commands import app as transfers_app
from cli.departments.commands import app as departments_app

app = typer.Typer()
app.add_typer(auth_app, name="auth")
app.add_typer(users_app, name="users")
app.add_typer(transfers_app, name="transfers")
app.add_typer(departments_app, name="departments")

if __name__ == "__main__":
    app()

