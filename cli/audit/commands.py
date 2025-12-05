import typer
from cli.core.session import load_token, load_rbac_token
from cli.core.api import api_get_audit_logs, api_validate_audit_log
from cli.core.rbac import decode_rbac_token

app = typer.Typer(help="Audit management commands (Auditor only).")

@app.command("log")
def get_log():
    """
    Retrieve the audit log.
    Requires: Auditor role.
    """
    token = load_token()
    if not token:
        typer.echo("No active session. Please login first.")
        raise typer.Exit(code=1)

    rbac_token = load_rbac_token()
    if not rbac_token:
        typer.echo("No active role. Use 'users role' to select an Auditor role first.")
        raise typer.Exit(code=1)

    # Verify Auditor role
    payload = decode_rbac_token(rbac_token)
    if not payload or payload.get("app_role") != "AUDITOR":
        typer.echo("Only Auditors can access the audit log.")
        raise typer.Exit(code=1)

    logs = api_get_audit_logs(token, rbac_token)
    if logs is None:
        typer.echo("Failed to retrieve audit logs. Check permissions.")
        raise typer.Exit(code=1)

    if not logs:
        typer.echo("Audit log is empty.")
        return

    # Print table
    typer.echo(f"{'ID':<5} {'Timestamp':<20} {'Actor':<5} {'Action':<20} {'Details':<30} {'Signature':<10}")
    typer.echo("-" * 100)
    for log in logs:
        lid = str(log.get("id", ""))
        ts = log.get("timestamp", "")
        actor = str(log.get("actor_id", ""))
        action = log.get("action", "")
        details = str(log.get("details", "")) or ""
        sig = "YES" if log.get("signature") else "NO"
        
        # Truncate details if too long
        if len(details) > 27:
            details = details[:27] + "..."
            
        typer.echo(f"{lid:<5} {ts:<20} {actor:<5} {action:<20} {details:<30} {sig:<10}")


@app.command("validate")
def validate_log(
    log_id: int = typer.Argument(..., help="ID of the log entry to validate"),
    signature: str = typer.Argument(..., help="Signature of the log entry"),
):
    """
    Add a validation entry to the audit log.
    Requires: Auditor role.
    """
    token = load_token()
    if not token:
        typer.echo("No active session. Please login first.")
        raise typer.Exit(code=1)

    rbac_token = load_rbac_token()
    if not rbac_token:
        typer.echo("No active role. Use 'users role' to select an Auditor role first.")
        raise typer.Exit(code=1)

    # Verify Auditor role
    payload = decode_rbac_token(rbac_token)
    if not payload or payload.get("app_role") != "AUDITOR":
        typer.echo("Only Auditors can validate log entries.")
        raise typer.Exit(code=1)

    result = api_validate_audit_log(token, log_id, signature, rbac_token)
    if result:
        typer.echo(f"Validation entry created successfully for Log ID {log_id}! 🗸")
    else:
        typer.echo("Failed to validate log entry. Check if ID exists or permissions.")
        raise typer.Exit(code=1)
