# SecureShare

SecureShare is a single-tenant secure file transfer web application designed to ensure end-to-end encryption and strict access control.

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

## Detailed Login Process

The login process ensures that the server authenticates the user *without* ever accessing their private key.

1.  **User Input**: The user enters their `username` and `password` in the client application.
2.  **Authentication Request**: The client sends a `POST /auth/login` request with the credentials.
3.  **Server Verification**: The server verifies the credentials (e.g., checking the password hash).
4.  **Token Issuance**: If valid, the server returns an authentication token (JWT or session cookie).
5.  **Vault Retrieval**: The client sends a `GET /users/me/vault` request (authenticated with the token) to retrieve the user's **Encrypted Private Key Blob**.
6.  **Local Decryption**: The client uses the user's `password` (which is still in memory or re-entered) to decrypt the Private Key Blob using a strong KDF (e.g., Argon2/PBKDF2).
7.  **Session Ready**: The plaintext Private Key is stored in the client's memory *only* for the duration of the session, allowing the user to decrypt file keys.

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
