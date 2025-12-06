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
    
    # Verify installation
    python3 -m cli.main --help
    ```

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

## Use Cases / Flows

### 1. User Login & Key Retrieval
**Flow:** `User enters credentials` -> `Client authenticates with Server` -> `Client retrieves Encrypted Private Key` -> `Client decrypts Private Key locally`
- The server never sees the plaintext private key.
- The client uses the password to decrypt the private key blob stored on the server.

### 2. File Upload (Secure Share)
**Flow:** `User selects file` -> `Client generates random File Key` -> `Client encrypts file with File Key` -> `Client encrypts File Key with Recipient's Public Key` -> `Client uploads Encrypted File + Encrypted Keys`
- Files are always encrypted client-side before upload.

### 3. File Download
**Flow:** `User requests file` -> `Client downloads Encrypted File + Encrypted File Key` -> `Client decrypts File Key with User's Private Key` -> `Client decrypts File with File Key`
- Decryption happens entirely on the client side.

### 4. User Creation & Activation
**Flow:** `Admin creates User` -> `Server generates OTP` -> `User receives OTP` -> `User activates account with OTP` -> `User sets Password & generates Key Pair`
- The user's cryptographic identity is established during activation.

## API Endpoints

### Authentication
- `POST /auth/login`: Authenticates a user and returns a token/session.
- `POST /auth/logout`: Logs out the current user.
- `POST /auth/activate`: Activates a new account using a username and OTP.

### Department Management (Admin Only)
- `POST /departments`: Creates a new department.
- `GET /departments`: Retrieves a list of all departments.
- `DELETE /departments/{deptId}`: Deletes a department.

### User Management
- `POST /users`: Creates a new user (Admin only).
- `GET /users`: Retrieves all users (Admin/Security Officer).
- `DELETE /users/{userId}`: Removes a user (Admin only).
- `PUT /users/{userId}/role`: Updates a user's role (Security Officer/Admin).
- `GET /users/{userId}/clearance`: Gets clearance tokens (Security Officer/Auth User).
- `PUT /users/{userId}/clearance`: Adds a clearance token (Security Officer).
- `PUT /users/{userId}/revoke/{tokenId}`: Revokes a token (Security Officer).
- `GET /users/{userId}/key`: Retrieves a user's **public** key.
- `PUT /users/me/vault`: Uploads/updates the **encrypted private key**.
- `GET /users/me/vault`: Retrieves the **encrypted private key**.
- `GET /user/me/info`: Get current user info.
- `POST /user/me/info`: Update user info.

### File Transfers
- `GET /transfers`: Lists existing transfers.
- `POST /transfers`: Uploads an encrypted file and metadata.
- `GET /transfers/{transferId}`: Retrieves transfer metadata and encrypted keys.
- `DELETE /transfers/{transferId}`: Deletes a transfer.
- `GET /download/{transferId}`: Downloads the raw encrypted file blob.

### Audit
- `GET /audit/log`: Retrieves the audit log (Auditor only).
- `PUT /audit/validate`: Adds a validation to the log (Auditor only).
