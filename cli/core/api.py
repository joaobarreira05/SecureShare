import requests
from typing import Optional, List
from .config import BASE_URL
import json

def api_login(username: str, password: str) -> Optional[str]:
    """
    Faz login no backend e devolve o access_token.
    """
    url = f"{BASE_URL}/auth/login"
    data = {"username": username, "password": password}
    
    try:
        resp = requests.post(url, json=data, timeout=5)
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
        resp = requests.post(url, headers=headers, timeout=5)
        return resp.status_code == 200
    except Exception:
        return False

def api_activate(activation_data: dict) -> bool:
    """
    Ativa a conta no backend.
    """
    url = f"{BASE_URL}/auth/activate"
    try:
        resp = requests.post(url, json=activation_data, timeout=10)
        return resp.status_code == 200
    except Exception:
        return False

def api_create_user(token: str, user_data: dict) -> bool:
    """
    Cria um novo utilizador no backend (Admin only).
    """
    url = f"{BASE_URL}/users"
    headers = {"Authorization": f"Bearer {token}"}
    
    try:
        resp = requests.post(url, json=user_data, headers=headers, timeout=10)
        return resp.status_code == 201
    except Exception:
        return False

def api_get_all_users(token: str) -> Optional[List[dict]]:
    """
    Obtém a lista de todos os utilizadores (Admin or Security Officer).
    """
    url = f"{BASE_URL}/users"
    headers = {"Authorization": f"Bearer {token}"}
    try:
        resp = requests.get(url, headers=headers, timeout=10)
        if resp.status_code != 200:
            return None
        return resp.json()
    except Exception:
        return None

def api_get_user_by_username(token: str, username: str) -> Optional[dict]:
    """
    Obtém o utilizador pelo username (pesquisa na lista).
    """
    users = api_get_all_users(token)
    if not users:
        return None
    for user in users:
        if user.get("username") == username:
            return user
    return None

def api_get_user_public_key(token: str, user_id: int) -> Optional[str]:
    """
    Obtém a public key de um utilizador pelo ID.
    """
    url = f"{BASE_URL}/users/{user_id}/key"
    headers = {"Authorization": f"Bearer {token}"}
    try:
        resp = requests.get(url, headers=headers, timeout=5)
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
        resp = requests.get(url, headers=headers, timeout=10)
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
        resp = requests.get(url, headers=headers, timeout=5)
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
            resp = requests.post(url, headers=headers, files=files, data=data, timeout=60)
        
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
        resp = requests.get(url, headers=headers, timeout=10)
        if resp.status_code != 200:
            return None
        return resp.json()
    except Exception:
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
        resp = requests.get(url, headers=headers, timeout=30)
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
        resp = requests.get(url, headers=headers, timeout=10)
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
        resp = requests.delete(url, headers=headers, timeout=10)
        return resp.status_code in (200, 204)
    except Exception:
        return False