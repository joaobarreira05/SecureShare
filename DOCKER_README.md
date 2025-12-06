# Docker Instructions

## Build the Image
Run this command in the root directory of the project (where the `Dockerfile` is located):

```bash
docker build -t secureshare .
```

> [!IMPORTANT]
> If you modify the code, you must **rebuild the image** for changes to take effect.

## Run the Container
To run the container and map port 8000 (HTTPS):

```bash
docker run -p 8000:8000 --env-file .env secureshare
```

## Multi-Container CLI Setup
We provide 3 pre-configured CLI containers (`cli-1`, `cli-2`, `cli-3`) that are ready to connect to the backend.

1.  **Start the environment**:
    ```bash
    docker-compose up -d --build
    ```

2.  **Access a CLI container**:
    You can open a shell in any of the CLI containers to act as different users.
    ```bash
    # Terminal 1 (User A)
    docker exec -it project-2-secureshare-119792_119876_120054-cli-1-1 /bin/bash
    
    # Terminal 2 (User B)
    docker exec -it project-2-secureshare-119792_119876_120054-cli-2-1 /bin/bash
    ```
    *(Note: The container names might vary slightly depending on your folder name. Use `docker ps` to check)*

3.  **Run CLI commands**:
    Inside the container, run commands using the python module syntax:
    ```bash
    python3 -m cli.main auth login
    python3 -m cli.main users list
    ```

## Run with Persistent Database
If you want the SQLite database to persist between container restarts, mount a volume for the `data` directory (or wherever the db is stored, usually root or a specific folder):

```bash
# Assuming the app creates 'secureshare.db' in the root /app
docker run -p 8000:8000 --env-file .env -v $(pwd)/secureshare.db:/app/secureshare.db secureshare
```

*Note: You might need to create an empty `secureshare.db` file first if it doesn't exist, or let the app create it inside the container and then copy it out if you want to persist it later.*

## Verify Connection
You can test if the server is running by sending a request to the root endpoint. Since the server uses self-signed certificates, use `-k` (insecure) or provide the CA certificate.

**Insecure (Skip verification):**
```bash
curl -k https://localhost:8000/
```

**Secure (Verify with CA):**
```bash
curl --cacert certs/ca.crt https://localhost:8000/
```

Expected output:
```json
{"message":"Welcome to SecureShare"}
```
