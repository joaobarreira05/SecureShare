# cli/core/config.py
from pathlib import Path

# URL do backend FastAPI
BASE_URL = "http://localhost:8000"

# Pasta onde a CLI vai guardar dados locais (token, etc.)
APP_DIR = Path.home() / ".secureshare"

# Ficheiro onde vamos guardar o token de sessão
SESSION_FILE = APP_DIR / "session.json"

# Garantir que a pasta existe
APP_DIR.mkdir(parents=True, exist_ok=True)
