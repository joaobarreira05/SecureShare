import re
import typer

def validate_password(password: str) -> bool:
    """
    Validates password strength:
    - At least 8 characters
    - At least one letter
    - At least one number
    - At least one special character
    """
    if len(password) < 8:
        typer.echo("Password must be at least 8 characters long.")
        return False
        
    if not re.search(r"[a-zA-Z]", password):
        typer.echo("Password must contain at least one letter.")
        return False
        
    if not re.search(r"\d", password):
        typer.echo("Password must contain at least one number.")
        return False
        
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        typer.echo("Password must contain at least one special character (!@#$%^&*(),.?\":{}|<>).")
        return False
        
    return True
