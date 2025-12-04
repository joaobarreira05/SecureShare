./venv/bin/
uvicorn backend.app.main:app --host 0.0.0.0 --port 8000 --ssl-keyfile=certs/server.key --ssl-certfile=certs/server.crt