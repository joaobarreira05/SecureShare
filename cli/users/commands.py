import typer
import re
from typing import Optional
import json
import base64
from cli.core.session import load_token, save_mls_token
from cli.core.api import api_create_user, api_get_user_clearances

app = typer.Typer(help="Comandos de gestão de utilizadores (create, list, etc.)")

USERNAME_REGEX = re.compile(r"^[a-zA-Z0-9_.-]{3,64}$")
EMAIL_REGEX = re.compile(r"^[\w\.-]+@[\w\.-]+\.\w+$")

@app.command("create")
def create_user():
    """
    Cria um novo utilizador (Admin only).
    Pede: username, otp, email, full_name.
    """
    token = load_token()
    if not token:
        typer.echo("Não tens sessão ativa. Faz primeiro `secureshare auth login` como Admin.")
        raise typer.Exit(code=1)

    username = typer.prompt("Username")
    if not USERNAME_REGEX.match(username):
        typer.echo("Username inválido.")
        raise typer.Exit(code=1)

    otp = typer.prompt("OTP (One Time Password)")
    if not otp.strip():
        typer.echo("OTP não pode ser vazio.")
        raise typer.Exit(code=1)

    email = typer.prompt("Email")
    if not EMAIL_REGEX.match(email):
        typer.echo("Email inválido.")
        raise typer.Exit(code=1)

    full_name = typer.prompt("Nome Completo")
    if not full_name.strip():
        typer.echo("Nome não pode ser vazio.")
        raise typer.Exit(code=1)

    user_data = {
        "username": username,
        "otp": otp,
        "email": email,
        "full_name": full_name
    }

    if api_create_user(token, user_data):
        typer.echo(f"Utilizador '{username}' criado com sucesso!")
    else:
        typer.echo("Falha ao criar utilizador. Verifica se tens permissões de Admin ou se o user já existe.")
        raise typer.Exit(code=1)


@app.command("clearance")
def select_clearance():
    """
    Lista e seleciona uma clearance (MLS Token) ativa.
    """
    token = load_token()
    if not token:
        typer.echo("Não tens sessão ativa. Faz primeiro `secureshare auth login`.")
        raise typer.Exit(code=1)

    # Precisamos do user_id ou "me". O endpoint diz /users/{userId}/clearance.
    # Vamos assumir que "me" funciona ou temos de ir buscar o info do user.
    # Por agora vou tentar "me" se a API suportar, senão tenho de fazer api_get_me.
    # O enunciado diz GET /user/me/info.
    
    # Vamos tentar obter info do user primeiro para saber o ID, ou usar "me" no endpoint de clearance se suportado.
    # O enunciado diz GET /users/{userId}/clearance.
    # Vou assumir que o CLI sabe o ID ou usa "me". Vou tentar "me".
    
    clearances = api_get_user_clearances(token, "me")
    if clearances is None:
        # Fallback: se "me" falhar, tentar obter user info
        # Mas não tenho api_get_user_info implementado aqui ainda.
        # Vou assumir que "me" funciona ou o utilizador tem de saber o ID?
        # Melhor: implementar api_get_user_info rapidinho se precisar.
        typer.echo("Falha ao obter clearances. (O backend suporta 'me' em /users/me/clearance?)")
        raise typer.Exit(code=1)

    if not clearances:
        typer.echo("Não tens clearances atribuídas.")
        return

    typer.echo("Clearances disponíveis:")
    valid_tokens = []
    for idx, jwt_token in enumerate(clearances):
        try:
            # Decode sem verificar assinatura só para mostrar info
            # O formato é header.payload.signature
            payload_b64 = jwt_token.split(".")[1]
            # Padding
            payload_b64 += "=" * (-len(payload_b64) % 4)
            payload_json = base64.urlsafe_b64decode(payload_b64).decode("utf-8")
            payload = json.loads(payload_json)
            
            lvl = payload.get("clearance", "N/A")
            depts = payload.get("departments", [])
            exp = payload.get("exp", "N/A")
            
            typer.echo(f"{idx + 1}) Nível: {lvl} | Depts: {depts} | Expira: {exp}")
            valid_tokens.append(jwt_token)
        except Exception:
            typer.echo(f"{idx + 1}) [Token Inválido/Corrompido]")
            valid_tokens.append(None)

    choice = typer.prompt("Escolhe uma clearance (número)", type=int)
    if choice < 1 or choice > len(valid_tokens):
        typer.echo("Opção inválida.")
        raise typer.Exit(code=1)

    selected = valid_tokens[choice - 1]
    if not selected:
        typer.echo("Token inválido selecionado.")
        raise typer.Exit(code=1)

    save_mls_token(selected)
    typer.echo("Clearance ativa atualizada com sucesso! 🛡️")
