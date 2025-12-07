# Project Structure & Responsibilities

This document outlines the file structure of the SecureShare project and the responsibilities of each component.

```
.
├── backend/                                # Backend application logic (FastAPI)
│   └── app/                                # Main application package
│       ├── api/                            # (Optional) General API endpoints
│       ├── audit/                          # Audit Logging module
│       │   ├── __init__.py                 # Makes the directory a package
│       │   ├── router.py                   # API route definitions for audit logs
│       │   └── service.py                  # Business logic for audit logging and validation
│       ├── auth/                           # Authentication module
│       │   ├── __init__.py                 # Makes the directory a package
│       │   ├── router.py                   # API route definitions (Login, Logout, Activate)
│       │   └── service.py                  # Business logic (Auth, Token generation, Argon2 hashing)
│       ├── core/                           # Core application configuration
│       │   ├── __init__.py                 # Makes the directory a package
│       │   ├── config.py                   # (Deprecated) Old config file
│       │   ├── crypto.py                   # Cryptographic utilities (Key generation)
│       │   ├── database.py                 # Database connection and session management
│       │   ├── init_db.py                  # Database initialization script
│       │   └── settings.py                 # Application settings (Database URL, Secrets, Token expiry)
│       ├── departments/                    # Departments module
│       │   ├── __init__.py                 # Makes the directory a package
│       │   ├── router.py                   # API route definitions for departments
│       │   └── service.py                  # Business logic for departments
│       ├── models/                         # Database Models & DTOs (SQLModel)
│       │   ├── __init__.py                 # Makes the directory a package
│       │   ├── Audit.py                    # Audit Log database models
│       │   ├── JWTAuthToken.py             # JWT Token database model
│       │   ├── JWTMLSToken.py              # MLS Token database model
│       │   ├── JWTRBACToken.py             # RBAC Token database model
│       │   ├── JWTRevocationToken.py       # Token revocation database model
│       │   ├── Role.py                     # Role definitions
│       │   └── User.py                     # User model and related DTOs
│       ├── transfers/                      # Transfers module (File Sharing)
│       │   ├── __init__.py                 # Makes the directory a package
│       │   ├── dependencies.py             # MLS security checks (No Read Up, No Write Down)
│       │   ├── router.py                   # API route definitions for transfers
│       │   └── service.py                  # Business logic for transfers
│       ├── users/                          # User Management module
│       │   ├── __init__.py                 # Makes the directory a package
│       │   ├── router.py                   # API route definitions (Create User, Vault operations)
│       │   └── service.py                  # Business logic (User creation, Vault management)
│       ├── __init__.py                     # Makes the directory a package
│       └── main.py                         # Application entry point, initializes FastAPI app
├── certs/                                  # Directory for SSL/TLS certificates
│   ├── ca.crt                              # Root CA Certificate
│   ├── ca.key                              # Root CA Private Key
│   ├── server.crt                          # Server Certificate
│   └── server.key                          # Server Private Key
├── cli/                                    # Command Line Interface application
│   ├── audit/                              # CLI Audit module
│   │   ├── __init__.py                     # Makes the directory a package
│   │   └── commands.py                     # Audit-related CLI commands (log, validate)
│   ├── auth/                               # CLI Authentication module
│   │   ├── __init__.py                     # Makes the directory a package
│   │   ├── commands.py                     # Auth-related CLI commands (login, logout, activate)
│   │   └── utils.py                        # Auth utilities
│   ├── commands/                           # General CLI commands
│   │   └── __init__.py                     # Makes the directory a package
│   ├── core/                               # Core CLI utilities
│   │   ├── __init__.py                     # Makes the directory a package
│   │   ├── api.py                          # HTTP client for backend communication
│   │   ├── config.py                       # CLI configuration (paths, URLs)
│   │   ├── crypto.py                       # Cryptographic functions (RSA key generation, encryption)
│   │   ├── mls.py                          # MLS Token handling
│   │   ├── rbac.py                         # RBAC Token handling
│   │   └── session.py                      # Session management (Token storage)
│   ├── departments/                        # CLI Departments module
│   │   ├── __init__.py                     # Makes the directory a package
│   │   └── commands.py                     # Department-related CLI commands
│   ├── transfers/                          # CLI Transfers module
│   │   ├── __init__.py                     # Makes the directory a package
│   │   └── commands.py                     # Transfer-related CLI commands
│   ├── users/                              # CLI User Management module
│   │   ├── __init__.py                     # Makes the directory a package
│   │   └── commands.py                     # User-related CLI commands (create user, assign role/clearance)
│   ├── __init__.py                         # Makes the directory a package
│   └── main.py                             # CLI entry point (Typer app)
├── data/                                   # Directory for storing local data (SQLite DB, files)
├── storage/                                # Directory for uploaded files
├── venv/                                   # Python virtual environment
├── .env                                    # Environment variables
├── .env.example                            # Example environment variables
├── .gitignore                              # Git ignore rules
├── CLIauthandvault.md                      # Documentation on CLI Auth and Vault
├── DOCKER_README.md                        # Documentation for Docker setup
├── Dockerfile                              # Docker image definition
├── MULTI_USER_SETUP.md                     # Guide for multi-user simulation with Docker
├── PROJECT_STRUCTURE.md                    # This file
├── README.md                               # Project documentation
├── SYSTEM_FLOWS.md                         # Detailed system flow documentation
├── certificates_docs.md                    # Documentation on CA and HTTPS setup
├── docker-compose.yml                      # Docker Compose configuration (Backend, SonarQube, CLIs)
├── generate_certs.sh                       # Script to generate CA and Server certificates
├── requirements.txt                        # Python dependencies
├── secureshare.db                          # SQLite database file
├── setup_env.py                            # Script to setup environment variables
├── sonar-project.properties                # SonarQube project configuration
├── test_api_flow.py                        # Comprehensive API test script
└── ...
```

## Module Responsibilities

### Backend (`backend/app`)
- **`auth/`**: Handles everything related to user identity and session.
    - **`router.py`**: Endpoints for `login`, `logout`, and `activate`.
    - **`service.py`**: Core logic for authentication, including **Argon2** password hashing, JWT token generation/validation (RS256), and user activation logic.
- **`audit/`**: Handles audit logging and validation.
    - **`router.py`**: Endpoints for retrieving logs and validating entries (`GET /audit/log`, `PUT /audit/validate`).
    - **`service.py`**: Logic for creating immutable audit logs (blockchain-like hashing) and validation entries.
- **`departments/`**: Manages department-related data.
    - **`router.py`**: Endpoints for department operations.
    - **`service.py`**: Logic for handling department data.
- **`transfers/`**: Manages file transfers and MLS security.
    - **`router.py`**: Endpoints for uploading, downloading, and listing files.
    - **`service.py`**: Logic for file handling and metadata storage.
    - **`dependencies.py`**: Implements **MLS Security Policies** (Bell-LaPadula: No Read Up, No Write Down) and Trusted Officer bypass logic.
- **`models/`**: Contains all SQLModel classes (Database Entities) and Pydantic models (DTOs).
    - **`User.py`**: Defines the `User` table and DTOs like `UserCreate`, `LoginRequest`.
    - **`Audit.py`**: Defines `AuditLog` and `AuditValidationRequest`.
    - **`JWTAuthToken.py`**: Defines the `JWTAuthToken` table for stateful token tracking.
    - **`JWTMLSToken.py`**: Defines the structure for MLS tokens.
    - **`JWTRBACToken.py`**: Defines the structure for RBAC tokens.
- **`users/`**: Handles user-specific operations.
    - **`router.py`**: Endpoints for creating users (Admin only) and vault management (`GET/PUT /users/me/vault`).
    - **`service.py`**: Logic for creating users (hashing OTPs) and managing user vaults.
- **`core/`**: Contains infrastructure code.
    - **`settings.py`**: Centralized configuration (Secrets, Database URL, Algorithm).
    - **`database.py`**: Database connection setup (`create_engine`) and session dependency (`get_session`).
    - **`crypto.py`**: Utilities for generating RSA keys.
- **`main.py`**: The application entry point. Configures FastAPI, includes all routers, and handles startup/shutdown events.

### CLI (`cli/`)
- **`auth/`**: Manages user authentication commands.
    - **`commands.py`**: Implements `login`, `logout`, and `activate` commands.
- **`audit/`**: Manages audit commands.
    - **`commands.py`**: Implements `log` (view logs) and `validate` (validate log integrity) commands.
- **`users/`**: Manages user administration commands.
    - **`commands.py`**: Implements `create` command for admins, and role/clearance assignment.
- **`core/`**: Shared utilities for the CLI.
    - **`api.py`**: Wraps `requests` to communicate with the backend API.
    - **`crypto.py`**: Handles client-side cryptography (RSA keypair generation, AES encryption for the vault).
    - **`session.py`**: Manages the local session file (saving/loading tokens).
    - **`config.py`**: Constants for file paths and API URLs.
    - **`mls.py`**: Handles MLS token signing and verification.
    - **`rbac.py`**: Handles RBAC token signing and verification.
- **`main.py`**: The main Typer application that aggregates all commands and sub-commands.

### Root Files
- **`certificates_docs.md`**: Detailed explanation of the CA setup and HTTPS implementation.
- **`generate_certs.sh`**: Shell script to generate the Root CA and sign Server certificates (supports `secureshare` hostname).
- **`test_api_flow.py`**: A comprehensive test suite that verifies the entire API flow, including Authentication, User Management, and Transfers (with MLS/RBAC checks), supporting HTTPS.
- **`setup_env.py`**: Automates the setup of the `.env` file.
- **`SYSTEM_FLOWS.md`**: Detailed explanation of the system's operational flows (Login, Create User, Activate, etc.).
- **`requirements.txt`**: Lists all Python dependencies, including `fastapi`, `sqlmodel`, `typer`, `argon2-cffi`, `python-jose`, and `cryptography`.
- **`Dockerfile`**: Defines the Docker image for the application (Backend and CLI), including the `secureshare` alias script.
- **`docker-compose.yml`**: Orchestrates the multi-container environment (Backend, SonarQube, 3x CLI).
- **`DOCKER_README.md`**: Instructions for running the application with Docker and SonarQube.
- **`MULTI_USER_SETUP.md`**: Guide for simulating multi-user scenarios using the Docker environment.
- **`sonar-project.properties`**: Configuration for SonarQube code analysis.
