# Backend and CLI Flow for Authentication

This document details the step-by-step flow of authentication data between the Command Line Interface (CLI) and the Backend API, highlighting the specific responsibilities of each file and function.

## 1. User Creation & Activation

**Goal:** Admin creates a user, and the user activates their account.

### Flow A: Admin Creates User
1.  **CLI (Admin)**:
    *   **Command**: `user create <username>`
    *   **Action**: Sends `POST /users` with `{"username": "..."}`.
    *   **Auth**: Requires Administrator JWT.

2.  **Backend (`backend/app/users/router.py`)**:
    *   **Action**: Generates a **One-Time Password (OTP)**.
    *   **Database**: Creates a `User` record with status `inactive` and stores the hashed OTP.
    *   **Response**: Returns the OTP in the JSON response (e.g., `{"otp": "123456"}`).
    *   **Note**: The Admin is responsible for securely sharing this OTP with the user (e.g., in person or via secure chat).

### Flow B: User Activates Account
1.  **CLI (User)**:
    *   **Command**: `auth activate <username> <otp>`
    *   **Action**: Prompts for a **New Password**.
    *   **Logic**:
        1.  Generates a **RSA Key Pair** locally.
        2.  Encrypts the **Private Key** with the *New Password* (using Argon2/PBKDF2).
        3.  Sends `POST /auth/activate` with `{"username": "...", "otp": "...", "password": "...", "public_key": "...", "encrypted_private_key": "..."}`.

2.  **Backend (`backend/app/auth/router.py`)**:
    *   **Action**:
        1.  Verifies the OTP matches the user's stored (hashed) OTP.
        2.  Updates the user's record: sets `hashed_password`, stores `public_key` and `encrypted_private_key`.
        3.  Sets status to `active`.
    *   **Response**: `200 OK`.

---

## 2. User Login & Key Retrieval

**Goal:** Authenticate the user and securely retrieve their encrypted private key.

### Flow
1.  **CLI (`cli/auth/commands.py`)**:
    *   **Action**: The `login` command prompts for email and password.
    *   **Logic**: Sends a `POST` request to `/auth/login` (form-data) with `username` (email) and `password`.

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
