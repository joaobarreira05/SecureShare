# cli/core/session.py
import json
from typing import Optional

from .config import SESSION_FILE, MLS_TOKEN_FILE, RBAC_TOKEN_FILE


def is_logged_in() -> bool:
    """Verifica se há uma sessão ativa."""
    return SESSION_FILE.exists() and load_token() is not None


def save_token(access_token: str) -> None:
    """Guarda o access_token."""
    data = {"access_token": access_token}
    with open(SESSION_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f)


def load_token() -> Optional[str]:
    """Lê o access_token da sessão."""
    if not SESSION_FILE.exists():
        return None
    try:
        with open(SESSION_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data.get("access_token")
    except Exception:
        return None


def clear_token() -> None:
    """Apaga todos os ficheiros de sessão."""
    if SESSION_FILE.exists():
        SESSION_FILE.unlink()
    if MLS_TOKEN_FILE.exists():
        MLS_TOKEN_FILE.unlink()
    if RBAC_TOKEN_FILE.exists():
        RBAC_TOKEN_FILE.unlink()


def save_mls_token(token: str) -> None:
    data = {"mls_token": token}
    with open(MLS_TOKEN_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f)


def load_mls_token() -> Optional[str]:
    if not MLS_TOKEN_FILE.exists():
        return None
    try:
        with open(MLS_TOKEN_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data.get("mls_token")
    except Exception:
        return None


def save_rbac_token(token: str) -> None:
    data = {"rbac_token": token}
    with open(RBAC_TOKEN_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f)


def load_rbac_token() -> Optional[str]:
    if not RBAC_TOKEN_FILE.exists():
        return None
    try:
        with open(RBAC_TOKEN_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data.get("rbac_token")
    except Exception:
        return None


def clear_rbac_token() -> None:
    if RBAC_TOKEN_FILE.exists():
        RBAC_TOKEN_FILE.unlink()


