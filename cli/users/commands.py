import typer
import re
from typing import Optional, List
import json
import base64
from datetime import datetime, timezone
from cryptography.hazmat.primitives import serialization, hashes, padding
from cli.core.session import load_token, save_mls_token, load_rbac_token, save_rbac_token
from cli.core.api import api_create_user, api_delete_user, api_get_user_clearances, api_get_user_by_username, api_assign_role, api_get_my_info, api_assign_clearance, api_get_all_users, api_revoke_token
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


@app.command("delete")
def delete_user(
    username: str = typer.Argument(..., help="Username do utilizador a apagar"),
    force: bool = typer.Option(False, "--force", "-f", help="Apagar sem confirmação"),
):
    """
    Apaga um utilizador (Admin only).
    """
    token = load_token()
    if not token:
        typer.echo("Não tens sessão ativa. Faz primeiro login.")
        raise typer.Exit(code=1)

    # Obter RBAC token para aceder à lista de users
    rbac_token = load_rbac_token()

    # Obter info do user a apagar
    target_user = api_get_user_by_username(token, username, rbac_token)
    if not target_user:
        typer.echo(f"Utilizador '{username}' não encontrado.")
        raise typer.Exit(code=1)

    user_id = target_user.get("id")
    
    # Confirmação
    if not force:
        confirm = typer.confirm(f"Tens a certeza que queres apagar o utilizador '{username}' (ID: {user_id})?")
        if not confirm:
            typer.echo("Operação cancelada.")
            raise typer.Exit(code=0)

    if api_delete_user(token, user_id):
        typer.echo(f"Utilizador '{username}' apagado com sucesso! 🗑️")
    else:
        typer.echo("Falha ao apagar utilizador. Verifica se tens permissões de Admin.")
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
    
    users = api_get_all_users(token, rbac_token)
    
    if not users:
        typer.echo("Nenhum utilizador encontrado ou sem permissões.")
        return

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
    is_admin = my_info.get("is_admin", False)

    # Obter meu RBAC token (se existir)
    my_rbac_token = load_rbac_token()
    is_security_officer = False
    
    if my_rbac_token:
        rbac_payload = decode_rbac_token(my_rbac_token)
        if rbac_payload and rbac_payload.get("app_role") == "SECURITY_OFFICER":
            is_security_officer = True

    # Verificar permissões de atribuição de roles
    # Admin → SECURITY_OFFICER, AUDITOR (NÃO pode dar TRUSTED_OFFICER)
    # Security Officer → TRUSTED_OFFICER
    if role == "TRUSTED_OFFICER":
        if not is_security_officer:
            typer.echo("Apenas Security Officers podem atribuir o role TRUSTED_OFFICER.")
            raise typer.Exit(code=1)
    elif role in ["SECURITY_OFFICER", "AUDITOR"]:
        if not is_admin:
            typer.echo(f"Apenas Administradores podem atribuir o role {role}.")
            raise typer.Exit(code=1)
    else:
        # Outros roles (se existirem)
        if not is_admin and not is_security_officer:
            typer.echo("Não tens permissões para atribuir roles.")
            raise typer.Exit(code=1)

    # Obter info do alvo
    target_user = api_get_user_by_username(token, target_username, my_rbac_token)
    if not target_user:
        typer.echo(f"Utilizador '{target_username}' não encontrado.")
        raise typer.Exit(code=1)
    
    subject_id = target_user.get("id")

    # Carregar private key do vault
    try:
        private_key = load_private_key_from_vault()
        # Convert to PEM bytes
        
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

    # Enviar para backend

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

    # Verificar auto-atribuição: SO não pode dar clearance a si próprio
    if subject_id == issuer_id:
        typer.echo("Não podes atribuir clearance a ti próprio. Pede a outro Security Officer.")
        raise typer.Exit(code=1)

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

    # Send to backend
    if api_assign_clearance(token, subject_id, signed_jwt, my_rbac_token):
        dept_str = ", ".join(departments) if departments else "(none)"
        typer.echo(f"Clearance '{level}' assigned to '{target_username}' successfully! ✅")
        typer.echo(f"Departments: {dept_str}")
    else:
        typer.echo("Failed to assign clearance. Check if you have Security Officer permissions.")
        raise typer.Exit(code=1)


@app.command("revoke-role")
def revoke_role(
    target_username: str = typer.Argument(..., help="Username of the target user"),
    token_index: int = typer.Option(None, "--token", "-t", help="Token index to revoke (from clearance list)"),
):
    """
    Revoke a role (RBAC token) from a user.
    Requires: Security Officer with active role.
    """
    token = load_token()
    if not token:
        typer.echo("No active session. Please login first.")
        raise typer.Exit(code=1)

    # Get my RBAC token (must be SO)
    my_rbac_token = load_rbac_token()
    if not my_rbac_token:
        typer.echo("No active role. Use 'users role' to select a Security Officer role first.")
        raise typer.Exit(code=1)

    rbac_payload = decode_rbac_token(my_rbac_token)
    if not rbac_payload or rbac_payload.get("app_role") != "SECURITY_OFFICER":
        typer.echo("Only Security Officers can revoke tokens.")
        raise typer.Exit(code=1)

    issuer_id = int(rbac_payload.get("sub", 0))

    # Get target user info
    target_user = api_get_user_by_username(token, target_username, my_rbac_token)
    if not target_user:
        typer.echo(f"User '{target_username}' not found.")
        raise typer.Exit(code=1)

    user_id = target_user.get("id")

    # Get target's clearances to show RBAC tokens
    clearances = api_get_user_clearances(token, user_id, my_rbac_token)
    if not clearances:
        typer.echo(f"Could not get clearances for '{target_username}'.")
        raise typer.Exit(code=1)

    rbac_tokens = clearances.get("rbac_tokens", [])
    
    # Filter only TRUSTED_OFFICER tokens (SO can only revoke TRUSTED_OFFICER)
    trusted_officer_tokens = [
        tk for tk in rbac_tokens 
        if (tk.get("role") or tk.get("app_role")) == "TRUSTED_OFFICER"
    ]
    
    if not trusted_officer_tokens:
        typer.echo(f"User '{target_username}' has no TRUSTED_OFFICER tokens to revoke.")
        raise typer.Exit(code=0)

    # Display tokens
    typer.echo(f"\nTRUSTED_OFFICER tokens for '{target_username}':")
    for i, tk in enumerate(trusted_officer_tokens, 1):
        jti = tk.get("jti", "?")
        typer.echo(f"  {i}) Role: TRUSTED_OFFICER | JTI: {jti[:16]}...")

    # Select token if not provided
    if token_index is None:
        token_index = int(typer.prompt("Token number to revoke"))

    if token_index < 1 or token_index > len(trusted_officer_tokens):
        typer.echo("Invalid token number.")
        raise typer.Exit(code=1)

    selected_token = trusted_officer_tokens[token_index - 1]
    token_jti = selected_token.get("jti")
    if not token_jti:
        typer.echo("Token has no JTI.")
        raise typer.Exit(code=1)

    # Load private key and sign revocation
    try:
        private_key = load_private_key_from_vault()
        private_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
    except Exception as e:
        typer.echo(f"Failed to load private key: {e}")
        raise typer.Exit(code=1)

    # Create revocation data

    
    now = datetime.now(timezone.utc)
    timestamp_str = now.strftime("%Y-%m-%dT%H:%M:%S")  # Format for JSON
    message = f"{token_jti}|{issuer_id}|{timestamp_str}"
    signature = private_key.sign(
        message.encode(),
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    signature_b64 = base64.b64encode(signature).decode()

    revocation_data = {
        "token_id": token_jti,
        "token_type": "RBAC",
        "revoker_id": issuer_id,
        "timestamp": timestamp_str,
        "signature": signature_b64
    }

    # Send to backend
    if api_revoke_token(token, user_id, token_jti, revocation_data, my_rbac_token):
        typer.echo(f"TRUSTED_OFFICER role revoked successfully! 🗑️")
    else:
        typer.echo("Failed to revoke token. Check permissions.")
        raise typer.Exit(code=1)


@app.command("revoke-clearance")
def revoke_clearance(
    target_username: str = typer.Argument(..., help="Username of the target user"),
    token_index: int = typer.Option(None, "--token", "-t", help="Token index to revoke (from clearance list)"),
):
    """
    Revoke a clearance (MLS token) from a user.
    Requires: Security Officer with active role.
    """
    token = load_token()
    if not token:
        typer.echo("No active session. Please login first.")
        raise typer.Exit(code=1)

    # Get my RBAC token (must be SO)
    my_rbac_token = load_rbac_token()
    if not my_rbac_token:
        typer.echo("No active role. Use 'users role' to select a Security Officer role first.")
        raise typer.Exit(code=1)

    rbac_payload = decode_rbac_token(my_rbac_token)
    if not rbac_payload or rbac_payload.get("app_role") != "SECURITY_OFFICER":
        typer.echo("Only Security Officers can revoke clearances.")
        raise typer.Exit(code=1)

    issuer_id = int(rbac_payload.get("sub", 0))

    # Get target user info
    target_user = api_get_user_by_username(token, target_username, my_rbac_token)
    if not target_user:
        typer.echo(f"User '{target_username}' not found.")
        raise typer.Exit(code=1)

    user_id = target_user.get("id")

    # Get target's clearances
    clearances = api_get_user_clearances(token, user_id, my_rbac_token)
    if not clearances:
        typer.echo(f"Could not get clearances for '{target_username}'.")
        raise typer.Exit(code=1)

    mls_tokens = clearances.get("mls_tokens", [])
    if not mls_tokens:
        typer.echo(f"User '{target_username}' has no MLS clearances to revoke.")
        raise typer.Exit(code=0)

    # Display tokens - need to decode signed_jwt to get payload
    typer.echo(f"\nMLS clearances for '{target_username}':")
    decoded_tokens = []
    for i, tk in enumerate(mls_tokens, 1):
        signed_jwt = tk.get("signed_jwt", "")
        token_id = tk.get("token_id", "?")
        
        # Decode JWT payload
        try:
            payload_b64 = signed_jwt.split(".")[1]
            payload_b64 += "=" * (-len(payload_b64) % 4)
            payload = json.loads(base64.urlsafe_b64decode(payload_b64))
            level = payload.get("clearance", "?")
            depts = payload.get("departments", [])
            jti = payload.get("jti", token_id)
        except:
            level = "?"
            depts = []
            jti = token_id
        
        decoded_tokens.append({"jti": jti, "level": level, "depts": depts})
        typer.echo(f"  {i}) Level: {level} | Depts: {', '.join(depts) if depts else 'none'} | JTI: {jti[:16]}...")

    # Select token if not provided
    if token_index is None:
        token_index = int(typer.prompt("Token number to revoke"))

    if token_index < 1 or token_index > len(decoded_tokens):
        typer.echo("Invalid token number.")
        raise typer.Exit(code=1)

    selected_token = decoded_tokens[token_index - 1]
    token_jti = selected_token.get("jti")
    if not token_jti or token_jti == "?":
        typer.echo("Token has no JTI.")
        raise typer.Exit(code=1)

    # Load private key and sign revocation
    try:
        private_key = load_private_key_from_vault()
        private_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
    except Exception as e:
        typer.echo(f"Failed to load private key: {e}")
        raise typer.Exit(code=1)

    # Create revocation data
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding
    
    now = datetime.now(timezone.utc)
    timestamp_str = now.strftime("%Y-%m-%dT%H:%M:%S")  # Format for JSON
    message = f"{token_jti}|{issuer_id}|{timestamp_str}"
    signature = private_key.sign(
        message.encode(),
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    signature_b64 = base64.b64encode(signature).decode()

    revocation_data = {
        "token_id": token_jti,
        "token_type": "MLS",
        "revoker_id": issuer_id,
        "timestamp": timestamp_str,
        "signature": signature_b64
    }

    # Send to backend
    if api_revoke_token(token, user_id, token_jti, revocation_data, my_rbac_token):
        typer.echo(f"MLS clearance revoked successfully! 🗑️")
    else:
        typer.echo("Failed to revoke clearance. Check permissions.")
        raise typer.Exit(code=1)
