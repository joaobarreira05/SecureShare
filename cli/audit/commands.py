import typer
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
import hashlib
from datetime import datetime

from cli.core.session import load_token, load_rbac_token
from cli.core.api import api_get_audit_logs, api_validate_audit_log
from cli.core.rbac import decode_rbac_token
from cli.core.crypto import load_private_key_from_vault

app = typer.Typer(help="Audit management commands (Auditor only).")


def calculate_hash(log_entry: dict, previous_hash: str) -> str:
    """
    Replicates the backend's hash calculation logic.
    """
    # Timestamp format from backend is ISO 8601 (e.g., "2023-10-27T10:00:00")
    # We use it directly as a string since that's how it was hashed
    ts_str = log_entry.get("timestamp", "")
    
    # Backend logic: previous_hash + timestamp + actor_id + action + details
    data = (
        previous_hash +
        ts_str +
        str(log_entry.get("actor_id", "")) +
        log_entry.get("action", "") +
        (log_entry.get("details", "") or "")
    )
    return hashlib.sha256(data.encode("utf-8")).hexdigest()

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
    typer.echo(f"{'ID':<5} {'Timestamp':<20} {'Actor':<5} {'Action':<20} {'Details':<30} {'Is Signed':<10}")
    typer.echo("-" * 100)
    for log in logs:
        lid = str(log.get("id", ""))
        ts = log.get("timestamp", "")
        actor = str(log.get("actor_id", ""))
        action = log.get("action", "")
        details = str(log.get("details", "")) or ""
        
        # Check if it's a validation entry or has a signature field
        is_signed = "YES" if action == "LOG_VALIDATION" or log.get("signature") else "NO"
            
        typer.echo(f"{lid:<5} {ts:<20} {actor:<5} {action:<20} {details:<30} {is_signed:<10}")




@app.command("validate")
def validate_log(
    log_id: int = typer.Argument(..., help="ID of the log entry to validate"),
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

    # 1. Fetch the log entry to sign
    logs = api_get_audit_logs(token, rbac_token)
    if not logs:
        typer.echo("Could not retrieve logs to validate.")
        raise typer.Exit(code=1)

    target_log = next((l for l in logs if str(l.get("id")) == str(log_id)), None)
    if not target_log:
        typer.echo(f"Log ID {log_id} not found.")
        raise typer.Exit(code=1)

    # 2. Verify Hash Chain up to target_log
    typer.echo("Verifying hash chain integrity...")
    
    # Sort logs by ID to ensure correct order
    sorted_logs = sorted(logs, key=lambda x: x.get("id"))
    
    previous_hash = "00000000000000000000000000000000"
    
    for log in sorted_logs:
        # Calculate expected hash
        expected_hash = calculate_hash(log, previous_hash)
        stored_hash = log.get("current_hash", "")
        
        if expected_hash != stored_hash:
            typer.echo(f" Hash mismatch at Log ID {log.get('id')}!")
            typer.echo(f"  Expected: {expected_hash}")
            typer.echo(f"  Stored:   {stored_hash}")
            typer.echo("Chain is broken. Cannot validate.")
            raise typer.Exit(code=1)
            
        # Update previous_hash for next iteration
        previous_hash = stored_hash
        
        # Stop if we reached the target log (we verified it and everything before it)
        if str(log.get("id")) == str(log_id):
            break
            
    typer.echo("Hash chain verified successfully. Adding a validation entry...")

    # 3. Construct data to sign
    # Format: ID|TIMESTAMP|ACTOR|ACTION|DETAILS
    # We must handle None values safely
    lid = str(target_log.get("id", ""))
    ts = str(target_log.get("timestamp", ""))
    actor = str(target_log.get("actor_id", ""))
    action = str(target_log.get("action", ""))
    details = str(target_log.get("details", "") or "")
    
    data_to_sign = f"{lid}|{ts}|{actor}|{action}|{details}"
    typer.echo(f"Signing log entry: {data_to_sign}")

    # 3. Load Private Key
    try:
        private_key = load_private_key_from_vault()
    except Exception as e:
        typer.echo(f"Failed to load private key: {e}")
        raise typer.Exit(code=1)

    # 4. Sign
    try:
        signature = private_key.sign(
            data_to_sign.encode("utf-8"),
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        signature_b64 = base64.b64encode(signature).decode("utf-8")
    except Exception as e:
        typer.echo(f"Failed to sign log entry: {e}")
        raise typer.Exit(code=1)

    # 5. Send to backend
    result = api_validate_audit_log(token, log_id, signature_b64, rbac_token)
    if result:
        typer.echo(f"Validation entry created successfully for Log ID {log_id}!")
    else:
        typer.echo("Failed to validate log entry. Check if ID exists or permissions.")
        raise typer.Exit(code=1)
