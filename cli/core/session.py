# cli/core/session.py
import json
from typing import Optional

from .config import SESSION_FILE


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
        # Se der erro a ler o ficheiro, consideramos que não há sessão válida
        return None


def clear_token() -> None:
    """
    Apaga o ficheiro de sessão, terminando a sessão local.
    """
    if SESSION_FILE.exists():
        SESSION_FILE.unlink()
