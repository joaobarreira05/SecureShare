# Backend and CLI Flow for Authentication

This document details the step-by-step flow of authentication data between the Command Line Interface (CLI) and the Backend API, highlighting the specific responsibilities of each file and function.

## 1. User Registration

**Goal:** Create a new user account.

### Flow
1.  **CLI (`cli/auth/commands.py`)**:
    *   **Action**: The `register` command prompts the user for an email and password.
    *   **Logic**: It validates the input and sends a `POST` request to `/auth/register` with the JSON payload `{"email": "...", "password": "..."}`.
    *   **Dependency**: Uses `requests` or `httpx` to make the call.

2.  **Backend Router (`backend/app/auth/router.py`)**:
    *   **Function**: `register(user: UserCreate)`
    *   **Action**: Receives the request. FastAPI automatically validates the body against the `UserCreate` schema defined in `backend/app/auth/schemas.py`.
    *   **Handoff**: Calls `auth_service.create_user(user)`.

3.  **Backend Service (`backend/app/auth/service.py`)**:
    *   **Function**: `create_user(user: UserCreate)`
    *   **Action**:
        1.  Checks if the user already exists.
        2.  Hashes the password using `get_password_hash`.
        3.  Creates a new `User` model instance (defined in `backend/app/auth/models.py`).
        4.  Saves the instance to the database via `db.add()` and `db.commit()`.

4.  **Backend Response**:
    *   Returns a `201 Created` status with the created user's public info (id, email).

---

## 2. User Login & Key Retrieval

**Goal:** Authenticate the user and securely retrieve their encrypted private key.

### Flow
1.  **CLI (`cli/auth/commands.py`)**:
    *   **Action**: The `login` command prompts for email and password.
    *   **Logic**: Sends a `POST` request to `/auth/token` (form-data) with `username` (email) and `password`.

2.  **Backend Router (`backend/app/auth/router.py`)**:
    *   **Function**: `login(form_data: OAuth2PasswordRequestForm)`
    *   **Action**: Receives the credentials.
    *   **Handoff**: Calls `auth_service.authenticate_user(email, password)`.

3.  **Backend Service (`backend/app/auth/service.py`)**:
    *   **Function**: `authenticate_user(email, password)`
    *   **Action**:
        1.  Fetches the user from the DB using `get_user_by_email`.
        2.  Verifies the password using `verify_password(plain, hashed)`.
        3.  If valid, returns the user object.
    *   **Token Creation**: The router then calls `create_access_token(data={"sub": user.email})` to generate a JWT signed with the server's `SECRET_KEY`.

4.  **Backend Response**:
    *   Returns the JWT (`access_token`) to the CLI.

5.  **CLI (`cli/auth/commands.py`)**:
    *   **Action**: Stores the JWT in memory or a secure session file.
    *   **Next Step**: Immediately requests the user's vault to get the private key.
    *   **Logic**: Sends a `GET` request to `/users/me/vault` with the header `Authorization: Bearer <token>`.

6.  **Backend Router (`backend/app/users/router.py`)**:
    *   **Function**: `get_user_vault(token: str = Depends(...))`
    *   **Action**:
        1.  **Dependency Injection**: The `get_current_user` dependency (in `auth/service.py`) intercepts the request, decodes the JWT, and verifies the user exists.
        2.  If valid, the `get_user_vault` function is executed.
    *   **Handoff**: Calls `user_service.get_vault(user_id)`.

7.  **Backend Service (`backend/app/users/service.py`)**:
    *   **Function**: `get_vault(user_id)`
    *   **Action**: Queries the database (via `auth/models.py` or a dedicated `Vault` model) for the `encrypted_private_key` blob associated with that user.

8.  **Backend Response**:
    *   Returns the `VaultContent` schema (defined in `backend/app/users/schemas.py`) containing the encrypted blob.

9.  **CLI (`cli/auth/commands.py`)**:
    *   **Action**: Receives the encrypted blob.
    *   **Local Decryption**: Uses the user's password (still in memory) to decrypt the blob using a KDF (e.g., Argon2).
    *   **Result**: The CLI now has the **Plaintext Private Key** in memory, ready to decrypt files.
