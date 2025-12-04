# cli/departments/commands.py
import typer
from cli.core.session import load_token
from cli.core.api import api_list_departments, api_create_department, api_delete_department

app = typer.Typer(help="Comandos de gestão de departamentos (Admin only).")


@app.command("list")
def list_departments():
    """
    Lista todos os departamentos.
    """
    token = load_token()
    if not token:
        typer.echo("Não tens sessão ativa. Faz primeiro `secureshare auth login`.")
        raise typer.Exit(code=1)

    departments = api_list_departments(token)
    if departments is None:
        typer.echo("Falha ao obter departamentos (erro na API ou permissões).")
        raise typer.Exit(code=1)

    if not departments:
        typer.echo("Não existem departamentos.")
        return

    typer.echo(f"{'ID':6}  {'Nome':30}")
    typer.echo("-" * 40)
    for dept in departments:
        did = str(dept.get("id", ""))[:6]
        name = str(dept.get("name", ""))[:30]
        typer.echo(f"{did:6}  {name:30}")


@app.command("create")
def create_department(
    name: str = typer.Argument(..., help="Nome do departamento"),
):
    """
    Cria um novo departamento (Admin only).
    """
    token = load_token()
    if not token:
        typer.echo("Não tens sessão ativa. Faz primeiro `secureshare auth login`.")
        raise typer.Exit(code=1)

    result = api_create_department(token, name)
    if result:
        typer.echo(f"Departamento '{name}' criado com sucesso! ✅")
    else:
        typer.echo("Falha ao criar departamento. Verifica se tens permissões de Admin.")
        raise typer.Exit(code=1)


@app.command("delete")
def delete_department(
    dept_id: int = typer.Argument(..., help="ID do departamento a apagar"),
    force: bool = typer.Option(False, "--force", "-f", help="Não pedir confirmação"),
):
    """
    Apaga um departamento (Admin only).
    """
    token = load_token()
    if not token:
        typer.echo("Não tens sessão ativa. Faz primeiro `secureshare auth login`.")
        raise typer.Exit(code=1)

    if not force:
        confirm = typer.confirm(f"Tens a certeza que queres apagar o departamento {dept_id}?")
        if not confirm:
            typer.echo("Operação cancelada.")
            raise typer.Exit(code=0)

    if api_delete_department(token, dept_id):
        typer.echo(f"Departamento {dept_id} apagado com sucesso! 🗑️")
    else:
        typer.echo("Falha ao apagar departamento. Verifica se tens permissões de Admin.")
        raise typer.Exit(code=1)
