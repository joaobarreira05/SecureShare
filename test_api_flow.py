import requests
import json
import sys
import os
import time
from datetime import datetime, timedelta
from jose import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

BASE_URL = "https://127.0.0.1:8000"
ADMIN_USER = "admin"
ADMIN_PASS = "adminadmin"
CA_CERT = os.path.abspath("certs/ca.crt")
os.environ["REQUESTS_CA_BUNDLE"] = CA_CERT
print(f"DEBUG: CA_CERT path: {CA_CERT}")
print(f"DEBUG: CA_CERT exists: {os.path.exists(CA_CERT)}")

def print_header(msg):
    print(f"\n{'='*60}\n{msg}\n{'='*60}")

def print_step(msg):
    print(f"\n[STEP] {msg}")

def print_success(msg):
    print(f"[SUCCESS] {msg}")

def print_fail(msg):
    print(f"[FAILURE] {msg}")

def generate_rsa_key_pair():
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    private_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_pem = key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return private_pem.decode('utf-8'), public_pem.decode('utf-8')

def test_flow():
    session = requests.Session()
    
    # ==========================================
    # 1. AUTHENTICATION & USER MANAGEMENT
    # ==========================================
    print_header("TESTING AUTHENTICATION & USER MANAGEMENT")

    # [SUCCESS] Login as Admin
    print_step("Logging in as Admin")
    resp = session.post(f"{BASE_URL}/auth/login", json={"username": ADMIN_USER, "password": ADMIN_PASS})
    if resp.status_code == 200:
        admin_token = resp.json()["access_token"]
        session.headers.update({"Authorization": f"Bearer {admin_token}"})
        print_success("Admin logged in successfully")
    else:
        print_fail(f"Admin login failed: {resp.text}")
        sys.exit(1)

    # Generate unique suffix
    suffix = int(time.time())
    std_username = f"standard_user_{suffix}"
    sec_username = f"sec_officer_{suffix}"

    # [SUCCESS] Create New User
    print_step("Creating a new Standard User")
    new_user = {
        "username": std_username,
        "email": f"user_{suffix}@example.com",
        "full_name": "Standard User",
        "password": "password123",
        "otp": "123456"
    }
    resp = session.post(f"{BASE_URL}/users", json=new_user)
    if resp.status_code == 201:
        print_success("User created successfully")
    elif resp.status_code == 400 and "already registered" in resp.text:
        print_success("User already exists")
    else:
        print_fail(f"User creation failed: {resp.text}")

    # [SUCCESS] Activate User
    print_step("Activating Standard User")
    # Generate keys for standard user (mocking client side)
    st_priv, st_pub = generate_rsa_key_pair()
    activation_data = {
        "username": std_username,
        "otp": "123456",
        "password": "password123",
        "public_key": st_pub,
        "encrypted_private_key": "encrypted_priv_key_blob"
    }
    resp = session.post(f"{BASE_URL}/auth/activate", json=activation_data)
    if resp.status_code == 200:
        print_success("User activated successfully")
    elif resp.status_code == 400 and "already active" in resp.text:
        print_success("User already active")
    else:
        # It might fail if already active, which is fine
        pass

    # [SUCCESS] Create Trusted Officer (Acting as Security Officer for this test context)
    # We will use this user to sign MLS tokens.
    print_step("Creating Security Officer User")
    sec_user = {
        "username": sec_username,
        "email": f"sec_{suffix}@example.com",
        "full_name": "Security Officer",
        "password": "password123",
        "otp": "123456"
    }
    session.post(f"{BASE_URL}/users", json=sec_user)
    
    # [SUCCESS] Activate Security Officer with REAL KEYS
    print_step("Activating Security Officer with Real Keys")
    so_priv, so_pub = generate_rsa_key_pair()
    activation_data = {
        "username": sec_username,
        "otp": "123456",
        "password": "password123",
        "public_key": so_pub,
        "encrypted_private_key": "encrypted_priv_key_blob"
    }
    resp = session.post(f"{BASE_URL}/auth/activate", json=activation_data)
    if resp.status_code == 200:
        print_success("Security Officer activated successfully")
    elif resp.status_code == 400 and "already active" in resp.text:
        print_success("Security Officer already active")
    else:
        pass

    # GET USER IDs
    print_step("Fetching User IDs")
    resp = session.get(f"{BASE_URL}/users")
    users = resp.json()
    std_user_id = next((u["id"] for u in users if u["username"] == std_username), None)
    sec_user_id = next((u["id"] for u in users if u["username"] == sec_username), None)
    
    if not std_user_id or not sec_user_id:
        print_fail("Could not find user IDs")
        sys.exit(1)
    print_success(f"Found IDs: Standard={std_user_id}, SecurityOfficer={sec_user_id}")

    # ==========================================
    # 2. DEPARTMENTS
    # ==========================================
    print_header("TESTING DEPARTMENTS")
    print_step("Creating 'Engineering' Department")
    resp = session.post(f"{BASE_URL}/departments", json={"name": "Engineering", "description": "Eng Dept"})
    if resp.status_code in [201, 400]:
        print_success("Department created/exists")
    else:
        print_fail(f"Department creation failed: {resp.text}")

    # ==========================================
    # 3. TRANSFERS (MLS & RBAC)
    # ==========================================
    print_header("TESTING TRANSFERS (MLS & RBAC)")

    # Login as Standard User
    print_step("Logging in as Standard User")
    resp = requests.post(f"{BASE_URL}/auth/login", json={"username": std_username, "password": "password123"}, verify=CA_CERT)
    if resp.status_code == 200:
        user_token = resp.json()["access_token"]
        user_headers = {"Authorization": f"Bearer {user_token}"}
        print_success("Standard User logged in")
    else:
        print_fail("Standard User login failed")
        sys.exit(1)

    # [FAILURE] Upload without MLS Token
    print_step("Attempting upload without MLS Token (Security Check)")
    files = {'file': ('test.txt', b'Secret Content')}
    data = {
        'classification': 'SECRET',
        'departments': json.dumps(['Engineering']),
        'recipient_keys': json.dumps([]),
        'expires_in_days': 7
    }
    resp = requests.post(f"{BASE_URL}/transfers", headers=user_headers, files=files, data=data, verify=CA_CERT)
    if resp.status_code == 403:
        print_success(f"Upload failed/rejected as expected: {resp.status_code}")
    else:
        print_fail(f"Upload should have failed but got {resp.status_code}")

    # [SUCCESS] Upload with VALID MLS Token
    print_step("Attempting upload with VALID MLS Token")
    
    # Generate MLS Token signed by Security Officer
    mls_payload = {
        "iss": str(sec_user_id),
        "sub": str(std_user_id),
        "exp": datetime.utcnow() + timedelta(hours=1),
        "jti": "unique_token_id_" + str(time.time()),
        "clearance": "SECRET",
        "departments": ["Engineering"]
    }
    mls_token = jwt.encode(mls_payload, so_priv, algorithm="RS256")
    
    user_headers["X-MLS-Token"] = mls_token
    
    # We also need recipient keys. For now, let's say we send to ourselves.
    # We need to encrypt the file key with our public key.
    # Mocking this:
    recipient_keys = [
        {
            "recipient_id": std_user_id,
            "encrypted_key": "mock_encrypted_aes_key" 
        }
    ]
    data['recipient_keys'] = json.dumps(recipient_keys)
    
    # Reset file cursor or create new tuple
    files = {'file': ('secret_doc.txt', b'This is a TOP SECRET document.')}
    
    resp = requests.post(f"{BASE_URL}/transfers", headers=user_headers, files=files, data=data, verify=CA_CERT)
    if resp.status_code == 201:
        transfer_id = resp.json()["transfer_id"]
        print_success(f"Upload succeeded! Transfer ID: {transfer_id}")
    else:
        print_fail(f"Upload failed: {resp.text}")
        sys.exit(1)

    # [SUCCESS] Download File
    print_step("Attempting download of the uploaded file")
    resp = requests.get(f"{BASE_URL}/transfers/download/{transfer_id}", headers=user_headers, verify=CA_CERT)
    if resp.status_code == 200:
        content = resp.content
        if content == b'This is a TOP SECRET document.':
             print_success("Download succeeded and content matches!")
        else:
             print_fail(f"Download succeeded but content mismatch: {content}")
    else:
        print_fail(f"Download failed: {resp.text}")

    # [SUCCESS] List Transfers
    print_step("Listing user transfers")
    resp = requests.get(f"{BASE_URL}/transfers", headers=user_headers, verify=CA_CERT)
    if resp.status_code == 200:
        transfers = resp.json()
        if len(transfers) > 0:
            print_success(f"List succeeded. Found {len(transfers)} transfers.")
        else:
            print_fail("List succeeded but found 0 transfers (expected at least 1)")
    else:
        print_fail(f"List failed: {resp.text}")

    # [SUCCESS] Delete Transfer
    print_step("Deleting transfer")
    resp = requests.delete(f"{BASE_URL}/transfers/{transfer_id}", headers=user_headers, verify=CA_CERT)
    if resp.status_code == 200:
        print_success("Delete succeeded")
    else:
        print_fail(f"Delete failed: {resp.text}")

    print_header("TESTING COMPLETED")

if __name__ == "__main__":
    test_flow()
