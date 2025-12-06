# SecureShare

SecureShare is a single-tenant secure file transfer web application designed to ensure end-to-end encryption and strict access control. It implements a robust security model including Role-Based Access Control (RBAC) and Multi-Level Security (MLS) with Bell-LaPadula enforcement.

## Project Structure

The project is organized as follows:

```
.
├── backend/                # FastAPI Backend Application
│   ├── app/                # Application Source Code
│   │   ├── auth/           # Authentication Logic
│   │   ├── audit/          # Audit Logging & Validation
│   │   ├── core/           # Core Config & Database
│   │   ├── departments/    # Department Management
│   │   ├── models/         # Database Models
│   │   ├── transfers/      # File Transfer Logic
│   │   └── users/          # User Management
├── cli/                    # Command Line Interface Tool
├── certs/                  # TLS Certificates
├── data/                   # Database Storage (SQLite)
├── storage/                # Encrypted File Storage
├── tests/                  # Test Suite
├── docker-compose.yml      # Docker Orchestration
├── setup_env.py            # Environment Setup Script
└── requirements.txt        # Python Dependencies
```

## Setup & Run

### Prerequisites
- **Docker & Docker Compose**: For running the backend and services.
- **Python 3.x**: Required to run the initial setup script and the CLI.

### Step-by-Step Installation

1.  **Clone the Repository**
    ```bash
    git clone <repository-url>
    cd project-2-secureshare
    ```

2.  **Generate Environment Configuration**
    **CRITICAL STEP**: You must run the setup script before starting the application. This script generates the `.env` file containing secure RSA keys for token signing and the password pepper.
    ```bash
    python3 setup_env.py
    ```
    *This will create a `.env` file based on `.env.example` and populate it with new cryptographic keys.*

3.  **Start the Application (Docker)**
    Build and start the backend and SonarQube services.
    ```bash
    docker compose up --build
    ```
    *The backend will be available at `https://localhost:8000` (via Nginx/TLS if configured) or `http://localhost:8000` depending on your Docker setup.*

4.  **CLI Setup (Client)**
    To interact with the system, set up the Python CLI tool in a virtual environment.
    ```bash
    python3 -m venv venv
    source venv/bin/activate
    pip install -r requirements.txt
    
    # Verify installatio    # Run CLI
    python3 -m cli.main --help
    ```

### Certificates (TLS)
The application uses TLS for secure communication. You must generate the certificates before running the system.
```bash
./generate_certs.sh
```
This script creates a Certificate Authority (CA) and issues a certificate for `localhost` and `secureshare` (internal Docker DNS). The certificates are stored in the `certs/` directory and mounted into the containers.

### Running Multiple CLIs (Docker)
For testing multi-user scenarios, the Docker Compose setup includes three pre-configured CLI containers (`cli-1`, `cli-2`, `cli-3`). These containers have the CA certificate installed and are ready to connect to the backend.

To access a CLI container:
```bash
docker compose exec cli-1 bash
# Inside the container:
python3 -m cli.main --help
```
You can open multiple terminal tabs and access `cli-2` and `cli-3` simultaneously to simulate different users interacting with the system.

## Configuration

The application is configured via the `.env` file.

| Variable | Description |
| :--- | :--- |
| `PROJECT_NAME` | Name of the application. |
| `DATABASE_URL` | Connection string for the database (default: SQLite). |
| `ALGORITHM` | Algorithm used for JWT signing (e.g., `RS256`). |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | Lifespan of access tokens in minutes. |
| `ADMIN_USERNAME` | Username for the initial Administrator account. |
| `ADMIN_PASSWORD` | Password for the initial Administrator account. |
| `SERVER_PRIVATE_KEY` | **Critical**. RSA Private Key for signing tokens (Generated). |
| `SERVER_PUBLIC_KEY` | RSA Public Key for verifying tokens (Generated). |
| `PASSWORD_PEPPER` | **Critical**. Secret pepper added to passwords before hashing. |

## CLI Command Reference

### Authentication

```bash
# Login with username and password. Creates an active session.
python3 -m cli.main auth login

# Ends the active session.
python3 -m cli.main auth logout

# Activates a new account with OTP and sets password. Generates key pair.
python3 -m cli.main auth activate
```

### Current User

```bash
# Change password
python3 -m cli.main user update-password

# Update email and/or name
python3 -m cli.main user update-info --email new@email.com --name "New Name"

# Shows current user information (ID, username, email, etc.)
python3 -m cli.main user me
```

### User Management (Admin/SO)

```bash
# Delete user with confirmation
python3 -m cli.main users delete user3

# Delete without confirmation
python3 -m cli.main users delete user3 --force

# Lists all users (requires Admin or Security Officer)
python3 -m cli.main users list

# Creates a new user (requires Admin)
python3 -m cli.main users create

# Lists and selects an active RBAC Token (role)
python3 -m cli.main users role

# Lists and selects an active MLS clearance
python3 -m cli.main users clearance

# Assigns a role to a user (requires Admin or SO)
# Roles: ADMINISTRATOR, SECURITY_OFFICER, TRUSTED_OFFICER, AUDITOR, STANDARD_USER
python3 -m cli.main users assign-role <USERNAME> --role <ROLE>

# Assigns MLS clearance to a user (requires SO)
# Levels: TOP_SECRET, SECRET, CONFIDENTIAL, UNCLASSIFIED
python3 -m cli.main users assign-clearance <USERNAME> --level <LEVEL> --dept <DEPT>
```

### Transfers

```bash
# E2EE upload of a file for specific recipient(s)
python3 -m cli.main transfers upload <FILEPATH> --to <USER_ID> --level <LEVEL> --dept <DEPT>

# Public upload with link + key in fragment
python3 -m cli.main transfers upload <FILEPATH> --public

# E2EE download of a file. Requires appropriate clearance.
python3 -m cli.main transfers download <TRANSFER_ID> [--output <PATH>]

# Lists transfers where you are sender or recipient
python3 -m cli.main transfers list

# Deletes a transfer (owner only)
python3 -m cli.main transfers delete <TRANSFER_ID> [--force]
```

### Departments (Admin)

```bash
# Lists all departments
python3 -m cli.main departments list

# Creates a new department (requires Admin)
python3 -m cli.main departments create <NAME>

# Deletes a department (requires Admin)
python3 -m cli.main departments delete <ID> [--force]
```
