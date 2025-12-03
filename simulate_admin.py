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