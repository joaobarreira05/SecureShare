import requests
from typing import Optional
from .config import BASE_URL

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

def api_get_user_public_key(token: str, userId: str) -> Optional[str]:
    """

    """
    url = f"{BASE_URL}/users/{userId}/key"
    headers = {"Authorization": f"Bearer {token}"}
    try:
        resp = requests.get(url, headers=headers, timeout=5)
        if resp.status_code != 200:
            return None
        data = resp.json()
        return data.get("public_key")
    except Exception:
        return None

def api_get_user_clearances(token: str, user_id: str) -> Optional[List[str]]:
    """
    Obtém a lista de tokens de clearance do utilizador.
    Supõe endpoint GET /users/{userId}/clearance que devolve uma lista de strings (JWTs).
    """
    url = f"{BASE_URL}/users/{user_id}/clearance"
    headers = {"Authorization": f"Bearer {token}"}
    try:
        resp = requests.get(url, headers=headers, timeout=10)
        if resp.status_code != 200:
            return None
        # O endpoint deve devolver algo como { "clearances": ["jwt1", "jwt2"] } ou lista direta
        data = resp.json()
        if isinstance(data, list):
            return data
        return data.get("clearances", [])
    except Exception:
        return None

def api_upload_transfer(token: str, transfer_data: dict, mls_token: Optional[str] = None) -> bool:
    """
    Faz upload de uma transferência E2EE.
    Supõe endpoint POST /transfers que aceita um JSON com:
      - filename
      - nonce
      - encrypted_file
      - encrypted_keys
    """
    url = f"{BASE_URL}/transfers"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }
    if mls_token:
        headers["X-MLS-Token"] = mls_token

def api_upload_transfer(token: str, transfer_data: dict, mls_token: Optional[str] = None) -> Optional[str]:
    """
    Faz upload de uma transferência E2EE.
    Retorna o ID da transferência se sucesso, ou None se erro.
    """
    url = f"{BASE_URL}/transfers"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }
    if mls_token:
        headers["X-MLS-Token"] = mls_token

    try:
        resp = requests.post(url, json=transfer_data, headers=headers, timeout=15)
        if resp.status_code in (200, 201):
            # Tenta obter o ID da resposta JSON
            try:
                data = resp.json()
                return data.get("id") or data.get("transfer_id")
            except:
                # Se não devolver JSON mas for 200, retornamos algo para indicar sucesso?
                # Mas precisamos do ID para o link público.
                # Vamos assumir que o backend devolve JSON com id.
                return None
        return None
    except Exception:
        return None
    
def api_get_transfer(token: str, transfer_id: str, mls_token: Optional[str] = None) -> Optional[dict]:
    """
    Vai buscar metadata da transferência e a encrypted_file_key para o user atual.
    Supõe endpoint GET /transfers/{transfer_id}.
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
    Supõe endpoint GET /download/{transfer_id} que devolve bytes.
    """
    url = f"{BASE_URL}/download/{transfer_id}"
    headers = {"Authorization": f"Bearer {token}"}
    if mls_token:
        headers["X-MLS-Token"] = mls_token
    try:
        resp = requests.get(url, headers=headers, timeout=30)
        if resp.status_code != 200:
            return None
        return resp.content  # bytes
    except Exception:
        return None
    
def api_list_transfers(token: str, mls_token: Optional[str] = None) -> Optional[List[dict]]:
    """
    Lista as transferências criadas pelo utilizador atual.
    Supõe endpoint GET /transfers que devolve uma lista de objetos JSON.
    """
    url = f"{BASE_URL}/transfers"
    headers = {"Authorization": f"Bearer {token}"}
    if mls_token:
        headers["X-MLS-Token"] = mls_token
    try:
        resp = requests.get(url, headers=headers, timeout=10)
        if resp.status_code != 200:
            return None
        return resp.json()  # deve ser uma lista
    except Exception:
        return None


def api_delete_transfer(token: str, transfer_id: str, mls_token: Optional[str] = None) -> bool:
    """
    Apaga uma transferência (metadata + ficheiro) do servidor.
    Supõe endpoint DELETE /transfers/{transfer_id}.
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