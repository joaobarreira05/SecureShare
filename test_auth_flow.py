import requests
import time

BASE_URL = "http://localhost:8000"

# 1. Login as Admin
print("\n--- 1. Logging in as Admin ---")
admin_login_data = {
    "username": "admin",
    "password": "admin"
}
response = requests.post(f"{BASE_URL}/auth/login", json=admin_login_data)
if response.status_code != 200:
    print(f"Admin login failed: {response.text}")
    exit(1)
admin_token = response.json()["access_token"]
print(f"Admin Token: {admin_token[:20]}...")

# 2. Create New User (Admin Only)
print("\n--- 2. Creating New User 'testuser' ---")
new_user_data = {
    "username": "testuser",
    "otp": "secret_otp_123",
    "email": "test@example.com",
    "full_name": "Test User"
}
headers = {"Authorization": f"Bearer {admin_token}"}
response = requests.post(f"{BASE_URL}/users", json=new_user_data, headers=headers)
if response.status_code == 201:
    print("User created successfully.")
elif response.status_code == 400 and "already registered" in response.text:
    print("User already exists, proceeding...")
else:
    print(f"User creation failed: {response.text}")
    exit(1)

# 3. Activate User
print("\n--- 3. Activating 'testuser' ---")
activation_data = {
    "username": "testuser",
    "otp": "secret_otp_123",
    "password": "new_secure_password",
    "public_key": "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQD...",
    "encrypted_private_key": "encrypted_blob_..."
}
response = requests.post(f"{BASE_URL}/auth/activate", json=activation_data)
if response.status_code == 200:
    print("User activated successfully.")
elif response.status_code == 400 and "already active" in response.text:
    print("User already active, proceeding...")
else:
    print(f"Activation failed: {response.text}")
    # Don't exit here, maybe we can still login if it was already active

# 4. Login as New User
print("\n--- 4. Logging in as 'testuser' ---")
user_login_data = {
    "username": "testuser",
    "password": "new_secure_password"
}
response = requests.post(f"{BASE_URL}/auth/login", json=user_login_data)
if response.status_code != 200:
    print(f"User login failed: {response.text}")
    exit(1)
user_token_1 = response.json()["access_token"]
print(f"User Token 1: {user_token_1[:20]}...")

# 5. Test Token Reuse
print("\n--- 5. Testing Token Reuse ---")
response = requests.post(f"{BASE_URL}/auth/login", json=user_login_data)
user_token_2 = response.json()["access_token"]
print(f"User Token 2: {user_token_2[:20]}...")

if user_token_1 == user_token_2:
    print("SUCCESS: Token was reused!")
else:
    print("FAILURE: Token was NOT reused.")

print("\n--- Test Complete ---")
