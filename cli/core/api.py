# cli/core/api.py
from typing import Optional

from .config import BASE_URL

# no futuro:
# import requests


def api_login(username: str, password: str) -> Optional[str]:
    """
    Faz login no backend e devolve o access_token.
    FASE 1: versão fake.
    FASE 2: substituir por requests.post() para /auth/login.
    """
    # ------------- FASE 1: LÓGICA FAKE -------------
    # aqui podes aplicar validações extra se quiseres
    # se quiseres simular falha:
    if username == "" or password == "":
        return None

    # simula um token "real"
    fake_token = f"fake-token-for-{username}"
    return fake_token

    # ------------- FASE 2 (quando houver backend) -------------
    # Exemplo futuro:
    # import requests
    #
    # url = f"{BASE_URL}/auth/login"
    # data = {"username": username, "password": password}
    # resp = requests.post(url, data=data, timeout=5)
    #
    # if resp.status_code != 200:
    #     return None
    #
    # body = resp.json()
    # return body.get("access_token")


def api_get_me(token: str) -> Optional[dict]:
    """
    Devolve info sobre o user autenticado.
    FASE 1: versão fake usando o token.
    FASE 2: substituir por requests.get() para /auth/me.
    """
    # ------------- FASE 1: LÓGICA FAKE -------------
    if not token.startswith("fake-token-for-"):
        return None

    username = token.replace("fake-token-for-", "", 1)

    # simula um objeto igual ao que o backend devolveria
    return {
        "id": 1,
        "username": username,
        "email": f"{username}@example.com",
        "is_active": True,
    }

    # ------------- FASE 2 (quando houver backend) -------------
    # Exemplo futuro:
    # import requests
    #
    # url = f"{BASE_URL}/auth/me"
    # headers = {"Authorization": f"Bearer {token}"}
    # resp = requests.get(url, headers=headers, timeout=5)
    #
    # if resp.status_code != 200:
    #     return None
    #
    # return resp.json()
