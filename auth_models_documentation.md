# Authentication Data Models

This document defines the data structures used for authentication, including Database Models, API Request/Response Schemas, and the JWT Token structure.

## 1. Database Models (SQLAlchemy)

### User Table
Represents a registered user in the system.

| Column Name | Type | Required | Unique | Description |
| :--- | :--- | :--- | :--- | :--- |
| `id` | `Integer` | Yes | Yes | Primary Key. Auto-incrementing ID. |
| `username` | `String` | Yes | Yes | Unique username (used for login). |
| `hashed_password` | `String` | Yes | No | Bcrypt/Argon2 hash of the user's password. |
| `full_name` | `String` | No | No | User's full real name. |
| `email` | `String` | No | Yes | Optional email address. |
| `is_active` | `Boolean` | Yes | - | `True` if account is active, `False` if pending activation. |
| `is_admin` | `Boolean` | Yes | - | `True` if user has administrative privileges. |
| `otp_hash` | `String` | No | - | Hash of the One-Time Password (used for activation). |
| `public_key` | `String` | No | - | User's RSA Public Key (PEM format). |
| `encrypted_private_key` | `String` | No | - | **The Vault**. User's Private Key encrypted with their password. |

---

## 2. API Schemas (Pydantic)

These models define the JSON structure for API requests and responses.

### A. User Creation (Admin)
**Endpoint:** `POST /users`

**Request (`UserCreate`)**
```json
{
  "username": "alice",
  "full_name": "Alice Wonderland",
  "email": "alice@example.com"
}
```

**Response**
```json
{
  "otp": "123456"  // Only returned once!
}
```

### B. Account Activation (User)
**Endpoint:** `POST /auth/activate`

**Request (`UserActivate`)**
```json
{
  "username": "alice",
  "otp": "123456",
  "password": "new_secure_password",
  "public_key": "-----BEGIN PUBLIC KEY...-----",
  "encrypted_private_key": "..." // Encrypted with "new_secure_password"
}
```

**Response**
```json
{
  "message": "Account activated successfully"
}
```

### C. Login
**Endpoint:** `POST /auth/login`

**Request (`OAuth2PasswordRequestForm`)**
*   Content-Type: `application/x-www-form-urlencoded`
*   Body: `username=alice&password=new_secure_password`

**Response (`Token`)**
```json
{
  "access_token": "eyJhbGciOiJIUzI1Ni...",
  "token_type": "bearer"
}
```

### D. Get Vault (Private Key)
**Endpoint:** `GET /users/me/vault`

**Request**
*   Headers: `Authorization: Bearer <access_token>`

**Response (`VaultContent`)**
```json
{
  "encrypted_private_key": "..." // The blob stored during activation
}
```

---

## 3. JWT Token Structure

The JSON Web Token (JWT) is signed by the server and contains the user's identity.
[Follows standard security practices (RFC 7519)]
**Header**
```json
{
  "alg": "HS256",
  "typ": "JWT"
}
```

**Payload (Claims)**
```json
{
  "sub": "alice",          // Subject (Username)
  "exp": 1715000000,       // Expiration Timestamp (Unix)
  "iat": 1714000000,       // Issued At Timestamp
  "scopes": ["admin"]      // (Optional) Permissions/Roles
}
```
