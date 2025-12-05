import requests
from typing import Optional, List
from .config import BASE_URL, CA_CERT
import json
import os

# Get verify setting - use CA cert if exists, else True (system certs)
def _get_verify():
    if CA_CERT and os.path.exists(CA_CERT):
        return CA_CERT
    return True  # Use system default

def api_login(username: str, password: str) -> Optional[str]:
    """
    Faz login no backend e devolve o access_token.
    """
    url = f"{BASE_URL}/auth/login"
    data = {"username": username, "password": password}
    
    try:
        resp = requests.post(url, json=data, verify=_get_verify(), timeout=5)
        if resp.status_code != 200:
            return None
        return resp.json().get("access_token")
    except Exception:
        return None

def api_logout(token: str) -> bool:
    """
    Faz logout no backend.
    """
    url = f"{BASE_URL}/auth/logout"
    headers = {"Authorization": f"Bearer {token}"}
    
    try:
        resp = requests.post(url, headers=headers, verify=_get_verify(), timeout=5)
        return resp.status_code == 200
    except Exception:
        return False

def api_activate(activation_data: dict) -> bool:
    """
    Ativa a conta no backend.
    """
    url = f"{BASE_URL}/auth/activate"
    try:
        resp = requests.post(url, json=activation_data, verify=_get_verify(), timeout=10)
        return resp.status_code == 200
    except Exception:
        return False


def api_get_vault(token: str) -> Optional[str]:
    """
    Obtém o vault (encrypted_private_key) do servidor.
    Retorna o JSON string do vault ou None se falhar.
    """
    url = f"{BASE_URL}/users/me/vault"
    headers = {"Authorization": f"Bearer {token}"}
    try:
        resp = requests.get(url, headers=headers, verify=_get_verify(), timeout=10)
        if resp.status_code != 200:
            return None
        data = resp.json()
        return data.get("encrypted_private_key")
    except Exception:
        return None

def api_create_user(token: str, user_data: dict) -> bool:
    """
    Cria um novo utilizador no backend (Admin only).
    """
    url = f"{BASE_URL}/users"
    headers = {"Authorization": f"Bearer {token}"}
    
    try:
        resp = requests.post(url, json=user_data, headers=headers, verify=_get_verify(), timeout=10)
        return resp.status_code == 201
    except Exception:
        return False

def api_get_all_users(token: str, rbac_token: Optional[str] = None) -> Optional[List[dict]]:
    """
    Obtém a lista de todos os utilizadores (Admin or Security Officer).
    """
    url = f"{BASE_URL}/users"
    headers = {"Authorization": f"Bearer {token}"}
    if rbac_token:
        headers["X-Role-Token"] = rbac_token
    try:
        resp = requests.get(url, headers=headers, verify=_get_verify(), timeout=10)
        if resp.status_code != 200:
            return None
        return resp.json()
    except Exception:
        return None


def api_get_user_by_username(token: str, username: str, rbac_token: Optional[str] = None) -> Optional[dict]:
    """
    Obtém o utilizador pelo username.
    Primeiro tenta via /users/lookup (qualquer user autenticado).
    Se falhar, tenta via lista (Admin/SO).
    """
    # Tentar lookup direto (funciona para qualquer user autenticado)
    user = api_lookup_user(token, username)
    if user:
        return user
    
    # Fallback: tentar via lista (só Admin/SO)
    users = api_get_all_users(token, rbac_token)
    if not users:
        return None
    for u in users:
        if u.get("username") == username:
            return u
    return None


def api_lookup_user(token: str, username: str) -> Optional[dict]:
    """
    Lookup user by username via /users/lookup/{username}.
    Funciona para qualquer utilizador autenticado.
    """
    url = f"{BASE_URL}/users/lookup/{username}"
    headers = {"Authorization": f"Bearer {token}"}
    try:
        resp = requests.get(url, headers=headers, verify=_get_verify(), timeout=5)
        if resp.status_code != 200:
            return None
        return resp.json()
    except Exception:
        return None


def api_get_user_public_key(token: str, user_id: int) -> Optional[str]:
    """
    Obtém a public key de um utilizador pelo ID.
    """
    url = f"{BASE_URL}/users/{user_id}/key"
    headers = {"Authorization": f"Bearer {token}"}
    try:
        resp = requests.get(url, headers=headers, verify=_get_verify(), timeout=5)
        if resp.status_code != 200:
            return None
        data = resp.json()
        return data.get("public_key")
    except Exception:
        return None

def api_get_user_clearances(token: str, user_id: int) -> Optional[dict]:
    """
    Obtém clearances e roles do utilizador.
    Retorna dict com mls_tokens e rbac_tokens.
    """
    url = f"{BASE_URL}/users/{user_id}/clearance"
    headers = {"Authorization": f"Bearer {token}"}
    try:
        resp = requests.get(url, headers=headers, verify=_get_verify(), timeout=10)
        if resp.status_code != 200:
            return None
        return resp.json()
    except Exception:
        return None

def api_get_my_info(token: str) -> Optional[dict]:
    """
    Obtém informação do utilizador autenticado.
    """
    url = f"{BASE_URL}/user/me/info"
    headers = {"Authorization": f"Bearer {token}"}
    try:
        resp = requests.get(url, headers=headers, verify=_get_verify(), timeout=5)
        if resp.status_code != 200:
            return None
        return resp.json()
    except Exception:
        return None

def api_upload_transfer(
    token: str,
    file_path: str,
    classification: str,
    departments: List[str],
    recipient_keys: List[dict],
    expires_in_days: int = 7,
    mls_token: Optional[str] = None
) -> Optional[str]:
    """
    Faz upload de uma transferência E2EE usando multipart form.
    Retorna o transfer_id se sucesso, ou None se erro.
    
    Args:
        file_path: Caminho para o ficheiro cifrado.
        classification: Nível de classificação (TOP_SECRET, SECRET, etc.)
        departments: Lista de departamentos.
        recipient_keys: Lista de [{recipient_id: int, encrypted_key: str}].
        expires_in_days: Dias até expiração.
        mls_token: Token MLS (opcional).
    """
    url = f"{BASE_URL}/transfers"
    headers = {"Authorization": f"Bearer {token}"}
    if mls_token:
        headers["X-MLS-Token"] = mls_token

    try:
        with open(file_path, "rb") as f:
            files = {"file": f}
            data = {
                "classification": classification,
                "departments": json.dumps(departments),
                "recipient_keys": json.dumps(recipient_keys),
                "expires_in_days": expires_in_days
            }
            resp = requests.post(url, headers=headers, files=files, data=data, verify=_get_verify(), timeout=60)
        
        if resp.status_code in (200, 201):
            try:
                result = resp.json()
                return str(result.get("transfer_id"))
            except:
                return None
        return None
    except Exception:
        return None

def api_get_transfer(token: str, transfer_id: str, mls_token: Optional[str] = None) -> Optional[dict]:
    """
    Vai buscar metadata da transferência.
    """
    url = f"{BASE_URL}/transfers/{transfer_id}"
    headers = {"Authorization": f"Bearer {token}"}
    if mls_token:
        headers["X-MLS-Token"] = mls_token
    try:
        resp = requests.get(url, headers=headers, verify=_get_verify(), timeout=10)
        if resp.status_code != 200:
            print(f"DEBUG: Transfer GET failed: {resp.status_code} - {resp.text}")
            return None
        return resp.json()
    except Exception as e:
        print(f"DEBUG: Transfer GET exception: {e}")
        return None

def api_download_encrypted_file(token: str, transfer_id: str, mls_token: Optional[str] = None) -> Optional[bytes]:
    """
    Vai buscar o ficheiro cifrado bruto.
    Endpoint: GET /transfers/download/{transfer_id}
    """
    url = f"{BASE_URL}/transfers/download/{transfer_id}"
    headers = {"Authorization": f"Bearer {token}"}
    if mls_token:
        headers["X-MLS-Token"] = mls_token
    try:
        resp = requests.get(url, headers=headers, verify=_get_verify(), timeout=30)
        if resp.status_code != 200:
            return None
        return resp.content
    except Exception:
        return None

def api_list_transfers(token: str, mls_token: Optional[str] = None) -> Optional[List[dict]]:
    """
    Lista as transferências criadas pelo utilizador atual.
    """
    url = f"{BASE_URL}/transfers"
    headers = {"Authorization": f"Bearer {token}"}
    if mls_token:
        headers["X-MLS-Token"] = mls_token
    try:
        resp = requests.get(url, headers=headers, verify=_get_verify(), timeout=10)
        if resp.status_code != 200:
            return None
        return resp.json()
    except Exception:
        return None

def api_delete_transfer(token: str, transfer_id: str, mls_token: Optional[str] = None) -> bool:
    """
    Apaga uma transferência (metadata + ficheiro) do servidor.
    """
    url = f"{BASE_URL}/transfers/{transfer_id}"
    headers = {"Authorization": f"Bearer {token}"}
    if mls_token:
        headers["X-MLS-Token"] = mls_token
    try:
        resp = requests.delete(url, headers=headers, verify=_get_verify(), timeout=10)
        return resp.status_code in (200, 204)
    except Exception:
        return False


def api_assign_role(
    token: str,
    user_id: int,
    signed_jwt: str,
    rbac_token: Optional[str] = None
) -> bool:
    """
    Atribui um role a um utilizador (Admin or SO).
    PUT /users/{user_id}/role
    
    Args:
        token: Auth token
        user_id: Target user ID
        signed_jwt: The signed RBAC JWT to assign
        rbac_token: Caller's RBAC token (for SO)
    """
    url = f"{BASE_URL}/users/{user_id}/role"
    headers = {"Authorization": f"Bearer {token}"}
    if rbac_token:
        headers["X-Role-Token"] = rbac_token
    
    try:
        # Backend expects {"signed_jwt": "<jwt_string>"}
        resp = requests.put(url, verify=_get_verify(), json={"signed_jwt": signed_jwt}, headers=headers, timeout=10)
        return resp.status_code == 204
    except Exception:
        return False


def api_assign_clearance(
    token: str,
    user_id: int,
    signed_jwt: str,
    rbac_token: str
) -> bool:
    """
    Atribui uma clearance (MLS Token) a um utilizador (SO only).
    PUT /users/{user_id}/clearance
    
    Args:
        token: Auth token
        user_id: Target user ID
        signed_jwt: The signed MLS JWT to assign
        rbac_token: Caller's RBAC token (SO)
    """
    url = f"{BASE_URL}/users/{user_id}/clearance"
    headers = {
        "Authorization": f"Bearer {token}",
        "X-Role-Token": rbac_token
    }
    
    try:
        resp = requests.put(url, verify=_get_verify(), json={"signed_jwt": signed_jwt}, headers=headers, timeout=10)
        return resp.status_code == 204
    except Exception:
        return False


def api_revoke_token(
    token: str,
    user_id: int,
    token_id: str,
    revocation_token: dict,
    rbac_token: str
) -> bool:
    """
    Revoga um token (SO only).
    PUT /users/{user_id}/revoke/{token_id}
    
    Args:
        token: Auth token
        user_id: User whose token is being revoked
        token_id: JTI of the token to revoke
        revocation_token: The revocation object
        rbac_token: Caller's SO RBAC token
    """
    url = f"{BASE_URL}/users/{user_id}/revoke/{token_id}"
    headers = {
        "Authorization": f"Bearer {token}",
        "X-Role-Token": rbac_token
    }
    
    try:
        resp = requests.put(url, verify=_get_verify(), json=revocation_token, headers=headers, timeout=10)
        return resp.status_code == 204
    except Exception:
        return False


def api_list_departments(token: str) -> Optional[List[dict]]:
    """
    Lista todos os departamentos (Admin only).
    """
    url = f"{BASE_URL}/departments"
    headers = {"Authorization": f"Bearer {token}"}
    try:
        resp = requests.get(url, headers=headers, verify=_get_verify(), timeout=10)
        if resp.status_code != 200:
            return None
        return resp.json()
    except Exception:
        return None


def api_create_department(token: str, name: str) -> bool:
    """
    Cria um novo departamento (Admin only).
    """
    url = f"{BASE_URL}/departments"
    headers = {"Authorization": f"Bearer {token}"}
    try:
        resp = requests.post(url, json={"name": name}, headers=headers, verify=_get_verify(), timeout=10)
        return resp.status_code == 201
    except Exception:
        return False


def api_delete_department(token: str, dept_id: int) -> bool:
    """
    Apaga um departamento (Admin only).
    """
    url = f"{BASE_URL}/departments/{dept_id}"
    headers = {"Authorization": f"Bearer {token}"}
    try:
        resp = requests.delete(url, headers=headers, verify=_get_verify(), timeout=10)
        return resp.status_code == 204
    except Exception:
        return False