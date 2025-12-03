# System Flows Documentation

This document details the operational flows of the SecureShare system, covering the CLI interactions, HTTP communication, and Backend processing for the primary user lifecycle.

## 1. Admin Login
**Goal**: Authenticate an administrator to perform privileged actions (like creating users).

### Flow
1.  **CLI**: User runs `secureshare auth login`.
2.  **CLI**: Prompts for `username` and `password`.
3.  **CLI**: Sends a login request to the backend.
    *   **Function**: `api_login(username, password)` in `cli/core/api.py`
    *   **Request**: `POST /auth/login`
    *   **Body**: `{"username": "admin", "password": "admin_password"}`
4.  **Backend**: Receives the request at `backend/app/auth/router.py`.
    *   **Function**: `login(login_data)`
    *   **Logic**:
        *   Calls `authenticate_user` in `backend/app/auth/service.py`.
        *   Verifies username exists and `is_active` is True.
        *   Verifies password hash using `verify_password`.
        *   If valid, calls `create_access_token`.
        *   Generates a JWT containing `sub` (username) and `scopes` (["admin"] if user is admin).
    *   **Response**: `200 OK` with JSON `{"access_token": "...", "token_type": "bearer"}`.
5.  **CLI**: Receives the token.
    *   **Action**: Saves the token to `~/.secureshare/session.json`.
    *   **Output**: "Login efetuado com sucesso (token guardado)."

---

## 2. Create User (Admin Only)
**Goal**: Admin registers a new user in the system. The user is created in an "inactive" state.

### Flow
1.  **CLI**: Admin runs `secureshare users create`.
2.  **CLI**: Checks for a valid local token.
3.  **CLI**: Prompts for `username`, `OTP` (One Time Password), `email`, and `full_name`.
4.  **CLI**: Sends a creation request to the backend.
    *   **Function**: `api_create_user(token, user_data)` in `cli/core/api.py`
    *   **Request**: `POST /users`
    *   **Headers**: `Authorization: Bearer <admin_token>`
    *   **Body**:
        ```json
        {
          "username": "newuser",
          "otp": "secret_otp",
          "email": "user@example.com",
          "full_name": "New User"
        }
        ```
5.  **Backend**: Receives the request at `backend/app/users/router.py`.
    *   **Function**: `create_new_user(user)`
    *   **Dependency**: `get_current_active_admin` validates the JWT and ensures the `admin` scope is present.
    *   **Logic**:
        *   Calls `create_user` in `backend/app/users/service.py`.
        *   Checks if `username` already exists.
        *   Hashes the provided `OTP` using `get_password_hash`.
        *   Creates a new `User` record with:
            *   `is_active = False`
            *   `otp_hash = <hashed_otp>`
            *   `is_admin = False`
    *   **Response**: `201 Created` with `{"message": "Created new user Successfully"}`.
6.  **CLI**: Receives success response.
    *   **Output**: "Utilizador 'newuser' criado com sucesso!"

---

## 3. Activate Account (User)
**Goal**: The new user activates their account using the OTP provided by the admin, sets their password, and generates their cryptographic keys.

### Flow
1.  **CLI**: User runs `secureshare auth activate`.
2.  **CLI**: Prompts for `username` and the `OTP` (provided offline by Admin).
3.  **CLI**: Prompts for a new `password` (and confirmation).
4.  **CLI**: Performs client-side cryptographic setup.
    *   **Key Generation**: Generates an RSA 2048-bit keypair (`private_pem`, `public_pem`).
    *   **Vault Creation**: Encrypts the `private_pem` using the user's new `password` (AES-GCM derived from password). This creates the "Vault".
5.  **CLI**: Sends activation data to the backend.
    *   **Function**: `api_activate(activation_data)` in `cli/core/api.py`
    *   **Request**: `POST /auth/activate`
    *   **Body**:
        ```json
        {
          "username": "newuser",
          "otp": "secret_otp",
          "password": "new_secure_password",
          "public_key": "-----BEGIN PUBLIC KEY...",
          "encrypted_private_key": "{\"iv\": \"...\", \"salt\": \"...\", \"data\": \"...\"}"
        }
        ```
6.  **Backend**: Receives the request at `backend/app/auth/router.py`.
    *   **Function**: `activate_account(activation_data)`
    *   **Logic**:
        *   Calls `activate_user_account` in `backend/app/auth/service.py`.
        *   Finds user by `username`.
        *   Verifies user is NOT already active.
        *   Verifies `otp` matches the stored `otp_hash`.
        *   Updates user record:
            *   `hashed_password` = hash of `new_secure_password`
            *   `public_key` = provided public key
            *   `encrypted_private_key` = provided vault blob
            *   `is_active` = True
            *   `otp_hash` = None (clears OTP)
    *   **Response**: `200 OK` with `{"message": "Account activated successfully"}`.
7.  **CLI**: Receives success response.
    *   **Action**:
        *   Saves `vault.json` (encrypted private key) to `~/.secureshare/vault.json`.
        *   Saves `public_key.pem` to `~/.secureshare/public_key.pem`.
    *   **Output**: "Ativação concluída com sucesso."

---

## 4. User Login
**Goal**: User logs in to access the system.

### Flow
1.  **CLI**: User runs `secureshare auth login`.
2.  **CLI**: Prompts for `username` and `password`.
3.  **CLI**: Sends login request.
    *   **Request**: `POST /auth/login`
    *   **Body**: `{"username": "newuser", "password": "new_secure_password"}`
4.  **Backend**: Authenticates user.
    *   **Logic**:
        *   Verifies `username` and `password`.
        *   Checks `is_active` is True.
        *   Generates JWT (no admin scope).
    *   **Response**: `200 OK` with access token.
5.  **CLI**: Saves token to `~/.secureshare/session.json`.

---

## 5. User Logout
**Goal**: Terminate the session.

### Flow
1.  **CLI**: User runs `secureshare auth logout`.
2.  **CLI**: Reads the local token.
3.  **CLI**: Sends logout notification to backend.
    *   **Function**: `api_logout(token)` in `cli/core/api.py`
    *   **Request**: `POST /auth/logout`
    *   **Headers**: `Authorization: Bearer <token>`
4.  **Backend**: Receives request.
    *   **Function**: `logout(current_user)`
    *   **Logic**: Validates the token (ensure it's not expired/invalid). Since JWTs are stateless, no database change is strictly required for basic logout, but the endpoint confirms the request.
    *   **Response**: `200 OK` with `{"message": "Logged out successfully"}`.
5.  **CLI**: Clears the local token file `~/.secureshare/session.json`.
    *   **Output**: "Sessão local terminada."
