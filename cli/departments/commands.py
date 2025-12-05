# cli/departments/commands.py
import typer
from cli.core.session import load_token
from cli.core.api import api_list_departments, api_create_department, api_delete_department

app = typer.Typer(help="Department management commands (Admin only).")


@app.command("list")
def list_departments():
    """
    List all departments.
    """
    token = load_token()
    if not token:
        typer.echo("No active session. Please login first.")
        raise typer.Exit(code=1)

    departments = api_list_departments(token)
    if departments is None:
        typer.echo("Failed to get departments (API error or permissions).")
        raise typer.Exit(code=1)

    if not departments:
        typer.echo("No departments found.")
        return

    typer.echo(f"{'ID':6}  {'Name':30}")
    typer.echo("-" * 40)
    for dept in departments:
        did = str(dept.get("id", ""))[:6]
        name = str(dept.get("name", ""))[:30]
        typer.echo(f"{did:6}  {name:30}")


@app.command("create")
def create_department(
    name: str = typer.Argument(..., help="Department name"),
):
    """
    Create a new department (Admin only).
    """
    token = load_token()
    if not token:
        typer.echo("No active session. Please login first.")
        raise typer.Exit(code=1)

    result = api_create_department(token, name)
    if result:
        typer.echo(f"Department '{name}' created successfully! ✅")
    else:
        typer.echo("Failed to create department. Check Admin permissions.")
        raise typer.Exit(code=1)


@app.command("delete")
def delete_department(
    dept_id: int = typer.Argument(..., help="Department ID to delete"),
    force: bool = typer.Option(False, "--force", "-f", help="Skip confirmation"),
):
    """
    Delete a department (Admin only).
    """
    token = load_token()
    if not token:
        typer.echo("No active session. Please login first.")
        raise typer.Exit(code=1)

    if not force:
        confirm = typer.confirm(f"Are you sure you want to delete department {dept_id}?")
        if not confirm:
            typer.echo("Operation cancelled.")
            raise typer.Exit(code=0)

    if api_delete_department(token, dept_id):
        typer.echo(f"Department {dept_id} deleted successfully! 🗑️")
    else:
        typer.echo("Failed to delete department. Check Admin permissions.")
        raise typer.Exit(code=1)
