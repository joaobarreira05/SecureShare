# Project Structure & Responsibilities

This document outlines the file structure of the SecureShare project and the responsibilities of each component.

```
.
├── backend/                                # Backend application logic (FastAPI)
│   └── app/                                # Main application package
│       ├── api/                            # General API endpoints (if not modularized)
│       ├── auth/                           # Authentication module
│       │   ├── __init__.py                 # Makes the directory a package
│       │   ├── router.py                   # API route definitions (Register, Login, Me)
│       │   └── service.py                  # Business logic (Password hashing, JWT generation)
│       ├── models/                         # Database Models & DTOs (SQLModel)
│       │   ├── __init__.py                 # Makes the directory a package
│       │   ├── User.py                     # User model and related DTOs
│       │   └── JWTAuthToken.py             # JWT Token models
│       ├── users/                          # User Management module
│       │   ├── __init__.py                 # Makes the directory a package
│       │   ├── router.py                   # API route definitions (Vault retrieval)
│       │   └── service.py                  # Business logic (Vault retrieval/update)
│       ├── core/                           # Core application configuration
│       │   ├── config.py                   # (Deprecated) Old config file
│       │   ├── settings.py                 # Application settings (Database URL, Secrets)
│       │   └── database.py                 # Database connection and session management
│       ├── __init__.py                     # Makes the directory a package
│       └── main.py                         # Application entry point, initializes FastAPI app
├── cli/                                    # Command Line Interface application
│   ├── auth/                               # CLI Authentication module
│   │   ├── __init__.py                     # Makes the directory a package
│   │   └── commands.py                     # Auth-related CLI commands (login, register)
│   ├── commands/                           # General CLI commands
│   ├── core/                               # Core CLI utilities (config, state management)
│   ├── __init__.py                         # Makes the directory a package
│   └── main.py                             # CLI entry point
├── data/                                   # Directory for storing local data (SQLite DB, files)
├── requirements.txt                        # Python dependencies for the project
└── README.md                               # Project documentation
```

## Module Responsibilities

### Backend (`backend/app`)
- **`auth/`**: Handles everything related to user identity.
    - **`router.py`**: The interface layer. Receives HTTP requests, calls `service.py`, and returns responses.
    - **`service.py`**: The logic layer. Handles password hashing, token creation, and database interactions.
- **`models/`**: Contains all SQLModel classes (Database Entities) and Pydantic models (DTOs).
    - **`User.py`**: Defines the `User` table and DTOs like `UserCreate`, `LoginRequest`.
    - **`JWTAuthToken.py`**: Defines the `Token` response structure.
- **`users/`**: Handles user-specific operations.
    - **`router.py`**: Endpoints for user management, including vault retrieval (`GET /users/me/vault`).
    - **`service.py`**: Business logic for user operations (e.g., fetching vault from DB).
- **`core/`**: Contains infrastructure code.
    - **`settings.py`**: Application configuration (Database URL, Secrets).
    - **`database.py`**: Database connection and session management.
- **`main.py`**: The glue that brings everything together. It configures the API, includes routers, and starts the server.

### CLI (`cli/`)
- **`auth/`**: Manages user sessions locally.
- **`main.py`**: Parses arguments and dispatches commands to the appropriate modules.

## Dependencies (`requirements.txt`)

- **`fastapi`**: High-performance web framework for building the backend API.
- **`uvicorn[standard]`**: ASGI server implementation to run the FastAPI application.
- **`sqlalchemy`**: SQL Toolkit and Object Relational Mapper (ORM) for database interactions.
- **`pydantic`**: Data validation and settings management using Python type hints.
- **`pydantic-settings`**: Robust settings management (reading environment variables) for Pydantic.
- **`python-jose[cryptography]`**: Library for encoding, decoding, and verifying JSON Web Tokens (JWT) for authentication.
- **`passlib[bcrypt]`**: Password hashing library to securely store user passwords.
- **`python-multipart`**: Required by FastAPI for parsing form data (e.g., extracting username and password from login requests).
- **`typer[all]`**: Library for building the Command Line Interface (CLI) application.
- **`requests`**: Synchronous HTTP library, likely used by the CLI to communicate with the backend.
- **`cryptography`**: Cryptographic primitives, required by `python-jose` for secure token operations.
- **`pytest`**: Framework for running automated tests.
- **`httpx`**: Asynchronous HTTP client, used for testing FastAPI endpoints.
