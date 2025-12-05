import requests
from typing import Optional, List
from .config import BASE_URL, CA_CERT
import json
import os

# Get verify setting - use CA cert if exists, else True (system certs)
def _get_verify():
    if CA_CERT and os.path.exists(CA_CERT):
        return CA_CERT
    return True  # Use system default

def api_login(username: str, password: str) -> Optional[str]:
    """
    Logs in to the backend and returns the access_token.
    """
    url = f"{BASE_URL}/auth/login"
    data = {"username": username, "password": password}
    
    try:
        resp = requests.post(url, json=data, verify=_get_verify(), timeout=5)
        if resp.status_code != 200:
            return None
        return resp.json().get("access_token")
    except Exception:
        return None

def api_logout(token: str) -> bool:
    """
    Logs out from the backend.
    """
    url = f"{BASE_URL}/auth/logout"
    headers = {"Authorization": f"Bearer {token}"}
    
    try:
        resp = requests.post(url, headers=headers, verify=_get_verify(), timeout=5)
        return resp.status_code == 200
    except Exception:
        return False

def api_activate(activation_data: dict) -> bool:
    """
    Activates the account on the backend.
    """
    url = f"{BASE_URL}/auth/activate"
    try:
        resp = requests.post(url, json=activation_data, verify=_get_verify(), timeout=10)
        return resp.status_code == 200
    except Exception:
        return False


def api_get_vault(token: str) -> Optional[str]:
    """
    Gets the vault (encrypted_private_key) from the server.
    Returns the vault JSON string or None if failed.
    """
    url = f"{BASE_URL}/users/me/vault"
    headers = {"Authorization": f"Bearer {token}"}
    try:
        resp = requests.get(url, headers=headers, verify=_get_verify(), timeout=10)
        if resp.status_code != 200:
            return None
        data = resp.json()
        return data.get("encrypted_private_key")
    except Exception:
        return None


def api_update_vault(token: str, encrypted_private_key: str) -> bool:
    """
    Updates the vault (encrypted_private_key) on the server.
    Used when changing password to re-encrypt the private key.
    """
    url = f"{BASE_URL}/users/me/vault"
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    try:
        resp = requests.put(url, json={"encrypted_private_key": encrypted_private_key}, headers=headers, verify=_get_verify(), timeout=10)
        return resp.status_code in (200, 204)
    except Exception:
        return False


def api_create_user(token: str, user_data: dict) -> bool:
    """
    Creates a new user on the backend (Admin only).
    """
    url = f"{BASE_URL}/users"
    headers = {"Authorization": f"Bearer {token}"}
    
    try:
        resp = requests.post(url, json=user_data, headers=headers, verify=_get_verify(), timeout=10)
        return resp.status_code == 201
    except Exception:
        return False


def api_delete_user(token: str, user_id: int) -> bool:
    """
    Deletes a user by ID (Admin only).
    """
    url = f"{BASE_URL}/users/{user_id}"
    headers = {"Authorization": f"Bearer {token}"}
    
    try:
        resp = requests.delete(url, headers=headers, verify=_get_verify(), timeout=10)
        return resp.status_code in (200, 204)
    except Exception:
        return False

def api_get_all_users(token: str, rbac_token: Optional[str] = None) -> Optional[List[dict]]:
    """
    Gets the list of all users (Admin or Security Officer).
    """
    url = f"{BASE_URL}/users"
    headers = {"Authorization": f"Bearer {token}"}
    if rbac_token:
        headers["X-Role-Token"] = rbac_token
    try:
        resp = requests.get(url, headers=headers, verify=_get_verify(), timeout=10)
        if resp.status_code != 200:
            return None
        return resp.json()
    except Exception:
        return None


def api_get_user_by_username(token: str, username: str, rbac_token: Optional[str] = None) -> Optional[dict]:
    """
    Gets the user by username.
    First tries via /users/lookup (any authenticated user).
    If that fails, tries via list (Admin/SO).
    """
    # Fallback: try via list (Admin/SO only)
    users = api_get_all_users(token, rbac_token)
    if not users:
        return None
    for u in users:
        if u.get("username") == username:
            return u
    return None


def api_revoke_token(token: str, user_id: int, token_id: str, revocation_data: dict, rbac_token: str) -> bool:
    """
    Revokes a token for a user (Security Officer only).
    """
    url = f"{BASE_URL}/users/{user_id}/revoke/{token_id}"
    headers = {
        "Authorization": f"Bearer {token}",
        "X-Role-Token": rbac_token,
        "Content-Type": "application/json"
    }
    try:
        resp = requests.put(url, json=revocation_data, headers=headers, verify=_get_verify(), timeout=10)
        return resp.status_code in (200, 204)
    except Exception:
        return False


def api_get_user_public_key(token: str, user_id: int) -> Optional[str]:
    """
    Gets the public key of a user by ID.
    """
    url = f"{BASE_URL}/users/{user_id}/key"
    headers = {"Authorization": f"Bearer {token}"}
    try:
        resp = requests.get(url, headers=headers, verify=_get_verify(), timeout=5)
        if resp.status_code != 200:
            return None
        data = resp.json()
        return data.get("public_key")
    except Exception:
        return None

def api_get_user_clearances(token: str, user_id: int, rbac_token: Optional[str] = None) -> Optional[dict]:
    """
    Gets clearances and roles of the user.
    Returns dict with mls_tokens and rbac_tokens.
    """
    url = f"{BASE_URL}/users/{user_id}/clearance"
    headers = {"Authorization": f"Bearer {token}"}
    if rbac_token:
        headers["X-Role-Token"] = rbac_token
    try:
        resp = requests.get(url, headers=headers, verify=_get_verify(), timeout=10)
        if resp.status_code != 200:
            return None
        return resp.json()
    except Exception:
        return None

def api_get_my_info(token: str) -> Optional[dict]:
    """
    Gets information of the authenticated user.
    """
    url = f"{BASE_URL}/user/me/info"
    headers = {"Authorization": f"Bearer {token}"}
    try:
        resp = requests.get(url, headers=headers, verify=_get_verify(), timeout=5)
        if resp.status_code != 200:
            return None
        return resp.json()
    except Exception:
        return None


def api_update_my_info(token: str, update_data: dict) -> bool:
    """
    Updates information of the authenticated user (password, email, name).
    """
    url = f"{BASE_URL}/user/me/info"
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    try:
        resp = requests.post(url, json=update_data, headers=headers, verify=_get_verify(), timeout=10)
        return resp.status_code == 200
    except Exception:
        return False

def api_upload_transfer(
    token: str,
    file_path: str,
    classification: str,
    departments: List[str],
    recipient_keys: List[dict],
    expires_in_days: int = 7,
    mls_token: Optional[str] = None,
    is_public: bool = False,
    rbac_token: Optional[str] = None,
    justification: Optional[str] = None
) -> Optional[str]:
    """
    Uploads an E2EE transfer using multipart form.
    Returns the transfer_id if successful, or None if error.
    
    Args:
        file_path: Path to the encrypted file.
        classification: Classification level (TOP_SECRET, SECRET, etc.)
        departments: List of departments.
        recipient_keys: List of [{recipient_id: int, encrypted_key: str}].
        expires_in_days: Days until expiration.
        mls_token: MLS token (optional).
        is_public: Whether it's a public share.
        rbac_token: RBAC token (for Trusted Officer).
        justification: Justification for MLS bypass (Trusted Officer).
    """
    url = f"{BASE_URL}/transfers"
    headers = {"Authorization": f"Bearer {token}"}
    if mls_token:
        headers["X-MLS-Token"] = mls_token
    if rbac_token:
        headers["X-Role-Token"] = rbac_token
    if justification:
        headers["X-Justification"] = justification

    try:
        with open(file_path, "rb") as f:
            files = {"file": f}
            data = {
                "classification": classification,
                "departments": json.dumps(departments),
                "recipient_keys": json.dumps(recipient_keys),
                "expires_in_days": expires_in_days,
                "is_public": "true" if is_public else "false"
            }
            resp = requests.post(url, headers=headers, files=files, data=data, verify=_get_verify(), timeout=60)
        
        if resp.status_code in (200, 201):
            try:
                result = resp.json()
                return str(result.get("transfer_id"))
            except:
                return None
        print(f"DEBUG: Upload failed: {resp.status_code} - {resp.text}")
        return None
    except Exception as e:
        print(f"DEBUG: Upload exception: {e}")
        return None

def api_get_transfer(
    token: str, 
    transfer_id: str, 
    mls_token: Optional[str] = None,
    rbac_token: Optional[str] = None,
    justification: Optional[str] = None
) -> Optional[dict]:
    """
    Gets transfer metadata.
    """
    url = f"{BASE_URL}/transfers/{transfer_id}"
    headers = {"Authorization": f"Bearer {token}"}
    if mls_token:
        headers["X-MLS-Token"] = mls_token
    if rbac_token:
        headers["X-Role-Token"] = rbac_token
    if justification:
        headers["X-Justification"] = justification
    try:
        resp = requests.get(url, headers=headers, verify=_get_verify(), timeout=10)
        if resp.status_code != 200:
            print(f"DEBUG: Transfer GET failed: {resp.status_code} - {resp.text}")
            return None
        return resp.json()
    except Exception as e:
        print(f"DEBUG: Transfer GET exception: {e}")
        return None

def api_download_encrypted_file(
    token: str, 
    transfer_id: str, 
    mls_token: Optional[str] = None,
    rbac_token: Optional[str] = None,
    justification: Optional[str] = None
) -> Optional[bytes]:
    """
    Gets the raw encrypted file.
    Endpoint: GET /transfers/download/{transfer_id}
    """
    url = f"{BASE_URL}/transfers/download/{transfer_id}"
    headers = {"Authorization": f"Bearer {token}"}
    if mls_token:
        headers["X-MLS-Token"] = mls_token
    if rbac_token:
        headers["X-Role-Token"] = rbac_token
    if justification:
        headers["X-Justification"] = justification
    try:
        resp = requests.get(url, headers=headers, verify=_get_verify(), timeout=30)
        if resp.status_code != 200:
            return None
        return resp.content
    except Exception:
        return None

def api_list_transfers(token: str, mls_token: Optional[str] = None) -> Optional[List[dict]]:
    """
    Lists transfers created by the current user.
    """
    url = f"{BASE_URL}/transfers"
    headers = {"Authorization": f"Bearer {token}"}
    if mls_token:
        headers["X-MLS-Token"] = mls_token
    try:
        resp = requests.get(url, headers=headers, verify=_get_verify(), timeout=10)
        if resp.status_code != 200:
            return None
        return resp.json()
    except Exception:
        return None

def api_delete_transfer(token: str, transfer_id: str, mls_token: Optional[str] = None) -> bool:
    """
    Deletes a transfer (metadata + file) from the server.
    """
    url = f"{BASE_URL}/transfers/{transfer_id}"
    headers = {"Authorization": f"Bearer {token}"}
    if mls_token:
        headers["X-MLS-Token"] = mls_token
    try:
        resp = requests.delete(url, headers=headers, verify=_get_verify(), timeout=10)
        return resp.status_code in (200, 204)
    except Exception:
        return False


def api_assign_role(
    token: str,
    user_id: int,
    signed_jwt: str,
    rbac_token: Optional[str] = None
) -> bool:
    """
    Assigns a role to a user (Admin or SO).
    PUT /users/{user_id}/role
    
    Args:
        token: Auth token
        user_id: Target user ID
        signed_jwt: The signed RBAC JWT to assign
        rbac_token: Caller's RBAC token (for SO)
    """
    url = f"{BASE_URL}/users/{user_id}/role"
    headers = {"Authorization": f"Bearer {token}"}
    if rbac_token:
        headers["X-Role-Token"] = rbac_token
    
    try:
        # Backend expects {"signed_jwt": "<jwt_string>"}
        resp = requests.put(url, verify=_get_verify(), json={"signed_jwt": signed_jwt}, headers=headers, timeout=10)
        return resp.status_code == 204
    except Exception:
        return False


def api_assign_clearance(
    token: str,
    user_id: int,
    signed_jwt: str,
    rbac_token: str
) -> bool:
    """
    Assigns a clearance (MLS Token) to a user (SO only).
    PUT /users/{user_id}/clearance
    
    Args:
        token: Auth token
        user_id: Target user ID
        signed_jwt: The signed MLS JWT to assign
        rbac_token: Caller's RBAC token (SO)
    """
    url = f"{BASE_URL}/users/{user_id}/clearance"
    headers = {
        "Authorization": f"Bearer {token}",
        "X-Role-Token": rbac_token
    }
    
    try:
        resp = requests.put(url, verify=_get_verify(), json={"signed_jwt": signed_jwt}, headers=headers, timeout=10)
        return resp.status_code == 204
    except Exception:
        return False


def api_revoke_token(
    token: str,
    user_id: int,
    token_id: str,
    revocation_token: dict,
    rbac_token: str
) -> bool:
    """
    Revokes a token (SO only).
    PUT /users/{user_id}/revoke/{token_id}
    
    Args:
        token: Auth token
        user_id: User whose token is being revoked
        token_id: JTI of the token to revoke
        revocation_token: The revocation object
        rbac_token: Caller's SO RBAC token
    """
    url = f"{BASE_URL}/users/{user_id}/revoke/{token_id}"
    headers = {
        "Authorization": f"Bearer {token}",
        "X-Role-Token": rbac_token
    }
    
    try:
        resp = requests.put(url, verify=_get_verify(), json=revocation_token, headers=headers, timeout=10)
        return resp.status_code == 204
    except Exception:
        return False


def api_list_departments(token: str) -> Optional[List[dict]]:
    """
    Lists all departments (Admin only).
    """
    url = f"{BASE_URL}/departments"
    headers = {"Authorization": f"Bearer {token}"}
    try:
        resp = requests.get(url, headers=headers, verify=_get_verify(), timeout=10)
        if resp.status_code != 200:
            return None
        return resp.json()
    except Exception:
        return None


def api_create_department(token: str, name: str) -> bool:
    """
    Creates a new department (Admin only).
    """
    url = f"{BASE_URL}/departments"
    headers = {"Authorization": f"Bearer {token}"}
    try:
        resp = requests.post(url, json={"name": name}, headers=headers, verify=_get_verify(), timeout=10)
        return resp.status_code == 201
    except Exception:
        return False


def api_delete_department(token: str, dept_id: int) -> bool:
    """
    Deletes a department (Admin only).
    """
    url = f"{BASE_URL}/departments/{dept_id}"
    headers = {"Authorization": f"Bearer {token}"}
    try:
        resp = requests.delete(url, headers=headers, verify=_get_verify(), timeout=10)
        return resp.status_code == 204
    except Exception:
    except Exception:
        return False


def api_get_audit_logs(token: str, rbac_token: str) -> Optional[List[dict]]:
    """
    Gets the audit logs (Auditor only).
    GET /audit/log
    """
    url = f"{BASE_URL}/audit/log"
    headers = {
        "Authorization": f"Bearer {token}",
        "X-Role-Token": rbac_token
    }
    try:
        resp = requests.get(url, headers=headers, verify=_get_verify(), timeout=10)
        if resp.status_code != 200:
            return None
        return resp.json()
    except Exception:
        return None


def api_validate_audit_log(
    token: str,
    log_id: int,
    signature: str,
    rbac_token: str
) -> Optional[dict]:
    """
    Validates an audit log entry (Auditor only).
    PUT /audit/validate
    """
    url = f"{BASE_URL}/audit/validate"
    headers = {
        "Authorization": f"Bearer {token}",
        "X-Role-Token": rbac_token
    }
    data = {
        "log_id": log_id,
        "signature": signature
    }
    try:
        resp = requests.put(url, json=data, headers=headers, verify=_get_verify(), timeout=10)
        if resp.status_code != 200:
            return None
        return resp.json()
    except Exception:
        return None