# cli/user/commands.py
"""
Current user commands (view info, etc.)
"""
import typer
import json
from cli.core.session import load_token
from cli.core.api import api_get_my_info, api_update_my_info, api_get_vault, api_update_vault
from cli.core.crypto import decrypt_vault, encrypt_private_key_with_password
from cli.core.utils import validate_password

app = typer.Typer(help="Current user commands (info, etc.)")


@app.command("me")
def me():
    """
    Show current user information.
    """
    token = load_token()
    if not token:
        typer.echo("No active session. Please login first.")
        raise typer.Exit(code=1)

    info = api_get_my_info(token)
    if not info:
        typer.echo("Failed to get user information.")
        raise typer.Exit(code=1)

    typer.echo("\n👤 User Information:")
    typer.echo(f"   ID:       {info.get('id', '-')}")
    typer.echo(f"   Username: {info.get('username', '-')}")
    typer.echo(f"   Email:    {info.get('email', '-')}")
    typer.echo(f"   Name:     {info.get('full_name', '-')}")
    typer.echo(f"   Active:   {'🗸' if info.get('is_active') else '☓'}")
    typer.echo(f"   Admin:    {'🗸' if info.get('is_admin') else '☓'}")


@app.command("update-password")
def update_password():
    """
    Changes the current user's password.
    Also re-encrypts the vault with the new password.
    """

    
    token = load_token()
    if not token:
        typer.echo("No active session. Please login first.")
        raise typer.Exit(code=1)

    # 1) Get current vault
    encrypted_vault = api_get_vault(token)
    if not encrypted_vault:
        typer.echo("Failed to get vault from server.")
        raise typer.Exit(code=1)

    # 2) Ask for current password to decrypt
    current_password = typer.prompt("Current password", hide_input=True)
    
    try:
        private_key_pem = decrypt_vault(encrypted_vault, current_password)
    except Exception as e:
        typer.echo(f"Failed to decrypt vault. Incorrect password?")
        raise typer.Exit(code=1)

    # 3) Ask for new password
    new_password = typer.prompt("New password", hide_input=True)
    confirm_password = typer.prompt("Confirm new password", hide_input=True)

    if new_password != confirm_password:
        typer.echo("Passwords do not match.")
        raise typer.Exit(code=1)

    if not validate_password(new_password):
        raise typer.Exit(code=1)

    # 4) Re-encrypt vault with new password
    try:
        new_vault = encrypt_private_key_with_password(private_key_pem, new_password)
        new_vault_str = json.dumps(new_vault)
    except Exception as e:
        typer.echo(f"Failed to encrypt vault: {e}")
        raise typer.Exit(code=1)

    # 5) Update vault on server
    if not api_update_vault(token, new_vault_str):
        typer.echo("Failed to update vault on server.")
        raise typer.Exit(code=1)

    # 6) Update password on server
    if api_update_my_info(token, {"password": new_password}):
        typer.echo("Password changed successfully! 🔐")
    else:
        typer.echo("Warning: Vault updated but password change failed.")
        raise typer.Exit(code=1)



@app.command("update-info")
def update_info(
    email: str = typer.Option(None, "--email", "-e", help="New email"),
    name: str = typer.Option(None, "--name", "-n", help="New full name"),
):
    """
    Update user information (email, name).
    """
    token = load_token()
    if not token:
        typer.echo("No active session. Please login first.")
        raise typer.Exit(code=1)

    if not email and not name:
        typer.echo("Specify at least one field to update (--email or --name).")
        raise typer.Exit(code=1)

    update_data = {}
    if email:
        update_data["email"] = email
    if name:
        update_data["full_name"] = name

    if api_update_my_info(token, update_data):
        typer.echo("Info updated successfully! 🗸")
    else:
        typer.echo("Failed to update info.")
        raise typer.Exit(code=1)

