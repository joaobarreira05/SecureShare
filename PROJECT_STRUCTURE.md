# Project Structure & Responsibilities

This document outlines the file structure of the SecureShare project and the responsibilities of each component.

```
.
├── backend/                                # Backend application logic (FastAPI)
│   └── app/                                # Main application package
│       ├── api/                            # (Optional) General API endpoints
│       ├── auth/                           # Authentication module
│       │   ├── __init__.py                 # Makes the directory a package
│       │   ├── router.py                   # API route definitions (Login, Logout, Activate)
│       │   └── service.py                  # Business logic (Auth, Token generation, Argon2 hashing)
│       ├── core/                           # Core application configuration
│       │   ├── __init__.py                 # Makes the directory a package
│       │   ├── config.py                   # (Deprecated) Old config file
│       │   ├── database.py                 # Database connection and session management
│       │   └── settings.py                 # Application settings (Database URL, Secrets, Token expiry)
│       ├── departments/                    # Departments module
│       │   ├── __init__.py                 # Makes the directory a package
│       │   ├── router.py                   # API route definitions for departments
│       │   └── service.py                  # Business logic for departments
│       ├── models/                         # Database Models & DTOs (SQLModel)
│       │   ├── __init__.py                 # Makes the directory a package
│       │   ├── JWTAuthToken.py             # JWT Token database model
│       │   └── User.py                     # User model and related DTOs
│       ├── users/                          # User Management module
│       │   ├── __init__.py                 # Makes the directory a package
│       │   ├── router.py                   # API route definitions (Create User, Vault operations)
│       │   └── service.py                  # Business logic (User creation, Vault management)
│       ├── __init__.py                     # Makes the directory a package
│       └── main.py                         # Application entry point, initializes FastAPI app
├── cli/                                    # Command Line Interface application
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
│   │   └── session.py                      # Session management (Token storage)
│   ├── users/                              # CLI User Management module
│   │   ├── __init__.py                     # Makes the directory a package
│   │   └── commands.py                     # User-related CLI commands (create user)
│   ├── __init__.py                         # Makes the directory a package
│   └── main.py                             # CLI entry point (Typer app)
├── data/                                   # Directory for storing local data (SQLite DB, files)
├── venv/                                   # Python virtual environment
├── .gitignore                              # Git ignore rules
├── CLIauthandvault.md                      # Documentation on CLI Auth and Vault
├── PROJECT_STRUCTURE.md                    # This file
├── README.md                               # Project documentation
├── SYSTEM_FLOWS.md                         # Detailed system flow documentation
├── requirements.txt                        # Python dependencies
├── secureshare.db                          # SQLite database file
├── simulate_admin.py                       # Script to simulate admin actions
├── test_auth_flow.py                       # Test script for auth flow
└── test_departments_flow.py                # Test script for departments flow
```

## Module Responsibilities

### Backend (`backend/app`)
- **`auth/`**: Handles everything related to user identity and session.
    - **`router.py`**: Endpoints for `login`, `logout`, and `activate`.
    - **`service.py`**: Core logic for authentication, including **Argon2** password hashing, JWT token generation/validation, and user activation logic.
- **`departments/`**: Manages department-related data.
    - **`router.py`**: Endpoints for department operations.
    - **`service.py`**: Logic for handling department data.
- **`models/`**: Contains all SQLModel classes (Database Entities) and Pydantic models (DTOs).
    - **`User.py`**: Defines the `User` table and DTOs like `UserCreate`, `LoginRequest`.
    - **`JWTAuthToken.py`**: Defines the `JWTAuthToken` table for stateful token tracking.
- **`users/`**: Handles user-specific operations.
    - **`router.py`**: Endpoints for creating users (Admin only) and vault management (`GET/PUT /users/me/vault`).
    - **`service.py`**: Logic for creating users (hashing OTPs) and managing user vaults.
- **`core/`**: Contains infrastructure code.
    - **`settings.py`**: Centralized configuration (Secrets, Database URL, Algorithm).
    - **`database.py`**: Database connection setup (`create_engine`) and session dependency (`get_session`).
- **`main.py`**: The application entry point. Configures FastAPI, includes all routers, and handles startup/shutdown events.

### CLI (`cli/`)
- **`auth/`**: Manages user authentication commands.
    - **`commands.py`**: Implements `login`, `logout`, and `activate` commands.
- **`users/`**: Manages user administration commands.
    - **`commands.py`**: Implements `create` command for admins.
- **`core/`**: Shared utilities for the CLI.
    - **`api.py`**: Wraps `requests` to communicate with the backend API.
    - **`crypto.py`**: Handles client-side cryptography (RSA keypair generation, AES encryption for the vault).
    - **`session.py`**: Manages the local session file (saving/loading tokens).
    - **`config.py`**: Constants for file paths and API URLs.
- **`main.py`**: The main Typer application that aggregates all commands and sub-commands.

### Root Files
- **`SYSTEM_FLOWS.md`**: Detailed explanation of the system's operational flows (Login, Create User, Activate, etc.).
- **`simulate_admin.py`**: A utility script to perform admin actions or seed data for testing.
- **`test_*.py`**: Standalone scripts to test specific flows (Auth, Departments) end-to-end.
- **`requirements.txt`**: Lists all Python dependencies, including `fastapi`, `sqlmodel`, `typer`, and `argon2-cffi`.
