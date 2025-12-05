# cli/core/config.py
from pathlib import Path
import os

# URL do backend FastAPI (HTTPS)
BASE_URL = os.environ.get("SECURESHARE_URL", "https://localhost:8000")

# CA Certificate for SSL verification
CA_CERT = os.environ.get("SECURESHARE_CA_CERT", str(Path(__file__).parent.parent.parent / "certs" / "ca.crt"))

# Pasta de dados da CLI
APP_DIR = Path.home() / ".secureshare"
APP_DIR.mkdir(parents=True, exist_ok=True)

# Ficheiros de sessão (apenas um user ativo de cada vez)
SESSION_FILE = APP_DIR / "session.json"
MLS_TOKEN_FILE = APP_DIR / "mls_token.json"
RBAC_TOKEN_FILE = APP_DIR / "rbac_token.json"



