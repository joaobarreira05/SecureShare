import getpass
import re
import typer
import json

from cli.core.session import save_token, load_token, clear_token, is_logged_in
from cli.core.api import api_login, api_logout, api_get_vault, api_activate
from cli.core.crypto import generate_rsa_keypair, encrypt_private_key_with_password
from cli.core.utils import validate_password


app = typer.Typer(help="Authentication commands (login, logout)")

USERNAME_REGEX = re.compile(r"^[a-zA-Z0-9_.-]{3,64}$")


@app.command("login")
def login(
    username: str = typer.Option(None, "--username", "-u", help="Username"),
):
    """
    Login to the system. Only allowed if no session is active.
    """
    # Check if session is already active
    if is_logged_in():
        typer.echo("Session already active. Logout first to remove current session token.")
        raise typer.Exit(code=1)

    if username is None:
        username = typer.prompt("Username")

    if not USERNAME_REGEX.match(username):
        typer.echo(
            "Invalid username.\n"
            "Use only letters, numbers, '.', '_' or '-', with 3 to 64 characters."
        )
        raise typer.Exit(code=1)

    password = getpass.getpass("Password: ")

    if len(password) < 3:
        typer.echo("Password too short (minimum 8 characters).")
        raise typer.Exit(code=1)

    # Login to backend
    token = api_login(username, password)

    if token is None:
        typer.echo("Login failed (invalid credentials or API error).")
        raise typer.Exit(code=1)

    save_token(token)
    typer.echo(f"Login successful as '{username}'.")


@app.command("logout")
def logout():
    """
    End session and delete local token.
    """
    token = load_token()
    if token:
        if api_logout(token):
            typer.echo("Logged out from backend.")
        else:
            typer.echo("Warning: Failed to logout from backend. The token may have had already expired.")
    
    clear_token()
    typer.echo("Session ended.")


@app.command("activate")
def activate():
    """
    Activate an account. Only allowed if no session is active.
    """
    # Check if session is already active
    if is_logged_in():
        typer.echo("Session already active. Logout first.")
        raise typer.Exit(code=1)

    username = typer.prompt("Username")

    if not USERNAME_REGEX.match(username):
        typer.echo(
            "Invalid username. Use only letters, numbers, '.', '_' or '-', with 3 to 64 characters."
        )
        raise typer.Exit(code=1)

    otp = typer.prompt("OTP (activation code provided by administrator)")
    if not otp.strip():
        typer.echo("OTP cannot be empty.")
        raise typer.Exit(code=1)

    password = getpass.getpass("New password: ")
    password_confirm = getpass.getpass("Confirm password: ")

    if password != password_confirm:
        typer.echo("Passwords do not match.")
        raise typer.Exit(code=1)

    if not validate_password(password):
        raise typer.Exit(code=1)

    # Generate RSA keys
    private_pem, public_pem = generate_rsa_keypair()

    # Create vault (private key encrypted with password)
    vault_obj = encrypt_private_key_with_password(private_pem, password)

    # Prepare data for backend
    
    activation_data = {
        "username": username,
        "otp": otp,
        "password": password,
        "public_key": public_pem.decode("utf-8"),
        "encrypted_private_key": json.dumps(vault_obj)
    }

    # Call API
    if not api_activate(activation_data):
        typer.echo("Activation failed. Check OTP and username.")
        raise typer.Exit(code=1)

    typer.echo("Activation completed successfully.")
    typer.echo("Vault stored on server. You can now login.")




