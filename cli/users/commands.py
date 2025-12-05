import typer
import re
from typing import Optional, List
import json
import base64
from cli.core.session import load_token, save_mls_token, load_rbac_token, save_rbac_token
from cli.core.api import api_create_user, api_get_user_clearances, api_get_user_by_username, api_assign_role, api_get_my_info, api_assign_clearance
from cli.core.rbac import create_rbac_payload, sign_rbac_token, decode_rbac_token, VALID_ROLES
from cli.core.mls import create_mls_payload, sign_mls_token, VALID_LEVELS
from cli.core.crypto import load_private_key_from_vault

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


@app.command("list")
def list_users():
    """
    Lista todos os utilizadores (Admin ou Security Officer).
    """
    token = load_token()
    if not token:
        typer.echo("Não tens sessão ativa. Faz primeiro login.")
        raise typer.Exit(code=1)

    # Obter RBAC token se existir
    rbac_token = load_rbac_token()
    
    from cli.core.api import api_get_all_users
    users = api_get_all_users(token, rbac_token)
    
    if users is None:
        typer.echo("Falha ao listar utilizadores. Verifica se tens permissões (Admin ou Security Officer).")
        raise typer.Exit(code=1)

    if not users:
        typer.echo("Nenhum utilizador encontrado.")
        return

    typer.echo(f"\n{'ID':<5} {'Username':<20} {'Email':<30} {'Ativo':<6} {'Admin':<6}")
    typer.echo("-" * 70)
    for u in users:
        active = "✅" if u.get("is_active") else "❌"
        admin = "✅" if u.get("is_admin") else "❌"
        typer.echo(f"{u.get('id', '-'):<5} {u.get('username', '-'):<20} {u.get('email', '-'):<30} {active:<6} {admin:<6}")


@app.command("clearance")
def select_clearance():
    """
    Lista e seleciona uma clearance (MLS Token) ativa.
    """
    token = load_token()
    if not token:
        typer.echo("Não tens sessão ativa. Faz primeiro `secureshare auth login`.")
        raise typer.Exit(code=1)

    # Obter info do user para saber o ID
    my_info = api_get_my_info(token)
    if not my_info:
        typer.echo("Falha ao obter informação do utilizador.")
        raise typer.Exit(code=1)
    
    user_id = my_info.get("id")
    if not user_id:
        typer.echo("Falha ao obter ID do utilizador.")
        raise typer.Exit(code=1)

    clearances_response = api_get_user_clearances(token, user_id)
    if clearances_response is None:
        typer.echo("Falha ao obter clearances.")
        raise typer.Exit(code=1)

    # Response has mls_tokens and rbac_tokens
    mls_tokens = clearances_response.get("mls_tokens", [])
    
    if not mls_tokens:
        typer.echo("Não tens clearances MLS atribuídas.")
        return

    typer.echo("Clearances MLS disponíveis:")
    valid_tokens = []
    for idx, token_obj in enumerate(mls_tokens):
        try:
            jwt_token = token_obj.get("signed_jwt") if isinstance(token_obj, dict) else token_obj
            payload_b64 = jwt_token.split(".")[1]
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


@app.command("role")
def select_role():
    """
    Lista e seleciona um RBAC Token (Role) ativo.
    """
    token = load_token()
    if not token:
        typer.echo("Não tens sessão ativa. Faz primeiro `secureshare auth login`.")
        raise typer.Exit(code=1)

    my_info = api_get_my_info(token)
    if not my_info:
        typer.echo("Falha ao obter informação do utilizador.")
        raise typer.Exit(code=1)
    
    user_id = my_info.get("id")

    clearances_response = api_get_user_clearances(token, user_id)
    if clearances_response is None:
        typer.echo("Falha ao obter roles.")
        raise typer.Exit(code=1)

    rbac_tokens = clearances_response.get("rbac_tokens", [])
    
    if not rbac_tokens:
        typer.echo("Não tens roles RBAC atribuídos.")
        return

    typer.echo("Roles RBAC disponíveis:")
    valid_tokens = []
    for idx, token_obj in enumerate(rbac_tokens):
        try:
            jwt_token = token_obj.get("signed_jwt") if isinstance(token_obj, dict) else token_obj
            payload = decode_rbac_token(jwt_token)
            if not payload:
                raise ValueError("Invalid token")
            
            role = payload.get("app_role", "N/A")
            exp = payload.get("exp", "N/A")
            iss = payload.get("iss", "N/A")
            
            typer.echo(f"{idx + 1}) Role: {role} | Issuer: {iss} | Expira: {exp}")
            valid_tokens.append(jwt_token)
        except Exception:
            typer.echo(f"{idx + 1}) [Token Inválido/Corrompido]")
            valid_tokens.append(None)

    choice = typer.prompt("Escolhe um role (número)", type=int)
    if choice < 1 or choice > len(valid_tokens):
        typer.echo("Opção inválida.")
        raise typer.Exit(code=1)

    selected = valid_tokens[choice - 1]
    if not selected:
        typer.echo("Token inválido selecionado.")
        raise typer.Exit(code=1)

    save_rbac_token(selected)
    typer.echo("Role ativo atualizado com sucesso! 🔑")


@app.command("assign-role")
def assign_role(
    target_username: str = typer.Argument(..., help="Username do utilizador alvo"),
    role: str = typer.Option(..., "--role", "-r", help=f"Role a atribuir: {', '.join(VALID_ROLES)}"),
    expire_days: int = typer.Option(365, "--expire-days", help="Dias até expiração"),
):
    """
    Atribui um role a um utilizador.
    Requer: Admin ou Security Officer.
    """
    token = load_token()
    if not token:
        typer.echo("Não tens sessão ativa. Faz primeiro `secureshare auth login`.")
        raise typer.Exit(code=1)

    if role not in VALID_ROLES:
        typer.echo(f"Role inválido. Opções: {', '.join(VALID_ROLES)}")
        raise typer.Exit(code=1)

    # Obter meu info (issuer)
    my_info = api_get_my_info(token)
    if not my_info:
        typer.echo("Falha ao obter informação do utilizador.")
        raise typer.Exit(code=1)
    
    issuer_id = my_info.get("id")

    # Obter info do alvo
    target_user = api_get_user_by_username(token, target_username)
    if not target_user:
        typer.echo(f"Utilizador '{target_username}' não encontrado.")
        raise typer.Exit(code=1)
    
    subject_id = target_user.get("id")

    # Carregar private key do vault
    try:
        private_key = load_private_key_from_vault()
        # Convert to PEM bytes
        from cryptography.hazmat.primitives import serialization
        private_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
    except Exception as e:
        typer.echo(f"Falha ao carregar private key: {e}")
        raise typer.Exit(code=1)

    # Criar e assinar token
    try:
        payload = create_rbac_payload(issuer_id, subject_id, role, expire_days)
        signed_jwt = sign_rbac_token(payload, private_key_pem)
    except Exception as e:
        typer.echo(f"Falha ao criar token: {e}")
        raise typer.Exit(code=1)

    # Carregar meu RBAC token (se não for admin)
    my_rbac_token = load_rbac_token()

    # Enviar para backend
    if api_assign_role(token, subject_id, signed_jwt, my_rbac_token):
        typer.echo(f"Role '{role}' atribuído a '{target_username}' com sucesso! ✅")
    else:
        typer.echo("Falha ao atribuir role. Verifica se tens permissões (Admin ou Security Officer).")
        raise typer.Exit(code=1)


@app.command("assign-clearance")
def assign_clearance(
    target_username: str = typer.Argument(..., help="Username do utilizador alvo"),
    level: str = typer.Option(..., "--level", "-l", help=f"Nível de segurança: {', '.join(VALID_LEVELS)}"),
    departments: List[str] = typer.Option([], "--dept", "-d", help="Departamentos (pode repetir)"),
    expire_days: int = typer.Option(365, "--expire-days", help="Dias até expiração"),
):
    """
    Atribui uma clearance (MLS Token) a um utilizador.
    Requer: Security Officer com role ativo.
    """
    token = load_token()
    if not token:
        typer.echo("Não tens sessão ativa. Faz primeiro login.")
        raise typer.Exit(code=1)

    # Validar nível
    if level not in VALID_LEVELS:
        typer.echo(f"Nível inválido. Deve ser um de: {', '.join(VALID_LEVELS)}")
        raise typer.Exit(code=1)

    # Obter RBAC token (deve ser SO)
    my_rbac_token = load_rbac_token()
    if not my_rbac_token:
        typer.echo("Precisas de ter um role ativo. Usa 'users role' para selecionar.")
        raise typer.Exit(code=1)

    # Verificar se é Security Officer
    rbac_payload = decode_rbac_token(my_rbac_token)
    if not rbac_payload or rbac_payload.get("app_role") != "SECURITY_OFFICER":
        typer.echo("Apenas Security Officers podem atribuir clearances.")
        raise typer.Exit(code=1)

    # Obter minha info (issuer)
    my_info = api_get_my_info(token)
    if not my_info:
        typer.echo("Falha ao obter informação do utilizador atual.")
        raise typer.Exit(code=1)
    issuer_id = my_info.get("id")


    # Obter info do target
    target_user = api_get_user_by_username(token, target_username, my_rbac_token)
    if not target_user:
        typer.echo(f"Utilizador '{target_username}' não encontrado.")
        raise typer.Exit(code=1)
    subject_id = target_user.get("id")

    # Carregar private key
    typer.echo("A carregar chave privada...")
    try:
        private_key = load_private_key_from_vault()
        private_key_pem = private_key.private_bytes(
            encoding=__import__('cryptography.hazmat.primitives.serialization', fromlist=['Encoding']).Encoding.PEM,
            format=__import__('cryptography.hazmat.primitives.serialization', fromlist=['PrivateFormat']).PrivateFormat.PKCS8,
            encryption_algorithm=__import__('cryptography.hazmat.primitives.serialization', fromlist=['NoEncryption']).NoEncryption()
        )
    except Exception as e:
        typer.echo(f"Falha ao carregar private key: {e}")
        raise typer.Exit(code=1)

    # Criar e assinar MLS token
    try:
        payload = create_mls_payload(issuer_id, subject_id, level, departments, expire_days)
        signed_jwt = sign_mls_token(payload, private_key_pem)
    except Exception as e:
        typer.echo(f"Falha ao criar token: {e}")
        raise typer.Exit(code=1)

    # Enviar para backend
    if api_assign_clearance(token, subject_id, signed_jwt, my_rbac_token):
        dept_str = ", ".join(departments) if departments else "(nenhum)"
        typer.echo(f"Clearance '{level}' atribuída a '{target_username}' com sucesso! ✅")
        typer.echo(f"Departamentos: {dept_str}")
    else:
        typer.echo("Falha ao atribuir clearance. Verifica se tens permissões de Security Officer.")
        raise typer.Exit(code=1)

