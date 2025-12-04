# cli/core/config.py
from pathlib import Path
import os

# URL do backend FastAPI (HTTPS)
BASE_URL = os.environ.get("SECURESHARE_URL", "https://localhost:8000")

# CA Certificate for SSL verification (None = use default, path = custom CA)
# Set to False to disable verification (NOT recommended for production)
CA_CERT = os.environ.get("SECURESHARE_CA_CERT", str(Path(__file__).parent.parent.parent / "certs" / "ca.crt"))

# Pasta onde a CLI vai guardar dados locais (token, etc.)
APP_DIR = Path.home() / ".secureshare"

# Ficheiro onde vamos guardar o token de sessão
SESSION_FILE = APP_DIR / "session.json"
MLS_TOKEN_FILE = APP_DIR / "mls_token.json"
RBAC_TOKEN_FILE = APP_DIR / "rbac_token.json"

# Garantir que a pasta existe
APP_DIR.mkdir(parents=True, exist_ok=True)

VAULT_FILE = APP_DIR / "vault.json"
PUBLIC_KEY_FILE = APP_DIR / "public_key.pem"
