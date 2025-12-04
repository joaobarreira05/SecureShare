# cli/core/session.py
import json
from typing import Optional

from .config import SESSION_FILE, MLS_TOKEN_FILE, RBAC_TOKEN_FILE


def save_token(access_token: str) -> None:
    """
    Guarda o access_token num ficheiro JSON (SESSION_FILE).
    """
    data = {"access_token": access_token}
    with open(SESSION_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f)


def load_token() -> Optional[str]:
    """
    Lê o access_token do ficheiro de sessão.
    Devolve None se o ficheiro não existir ou estiver inválido.
    """
    if not SESSION_FILE.exists():
        return None

    try:
        with open(SESSION_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data.get("access_token")
    except Exception:
        return None


def clear_token() -> None:
    """
    Apaga o ficheiro de sessão, terminando a sessão local.
    """
    if SESSION_FILE.exists():
        SESSION_FILE.unlink()
    if MLS_TOKEN_FILE.exists():
        MLS_TOKEN_FILE.unlink()
    if RBAC_TOKEN_FILE.exists():
        RBAC_TOKEN_FILE.unlink()


def save_mls_token(token: str) -> None:
    """
    Guarda o token MLS (clearance) num ficheiro JSON.
    """
    data = {"mls_token": token}
    with open(MLS_TOKEN_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f)


def load_mls_token() -> Optional[str]:
    """
    Lê o token MLS do ficheiro.
    """
    if not MLS_TOKEN_FILE.exists():
        return None

    try:
        with open(MLS_TOKEN_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data.get("mls_token")
    except Exception:
        return None


def save_rbac_token(token: str) -> None:
    """
    Guarda o token RBAC (role) num ficheiro JSON.
    """
    data = {"rbac_token": token}
    with open(RBAC_TOKEN_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f)


def load_rbac_token() -> Optional[str]:
    """
    Lê o token RBAC do ficheiro.
    """
    if not RBAC_TOKEN_FILE.exists():
        return None

    try:
        with open(RBAC_TOKEN_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data.get("rbac_token")
    except Exception:
        return None


def clear_rbac_token() -> None:
    """
    Limpa o token RBAC.
    """
    if RBAC_TOKEN_FILE.exists():
        RBAC_TOKEN_FILE.unlink()
