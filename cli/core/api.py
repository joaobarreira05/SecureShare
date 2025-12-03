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

