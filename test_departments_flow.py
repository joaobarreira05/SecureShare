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
headers = {"Authorization": f"Bearer {admin_token}"}

# 2. Create Department
print("\n--- 2. Creating Department 'Engineering' ---")
dept_data = {
    "name": "Engineering",
    "description": "Software Development"
}
response = requests.post(f"{BASE_URL}/departments", json=dept_data, headers=headers)
if response.status_code == 201:
    print("Department created successfully.")
    dept_id = response.json()["id"]
elif response.status_code == 400 and "already exists" in response.text:
    print("Department already exists, fetching ID...")
    # Fetch all and find it
    response = requests.get(f"{BASE_URL}/departments", headers=headers)
    for d in response.json():
        if d["name"] == "Engineering":
            dept_id = d["id"]
            break
else:
    print(f"Department creation failed: {response.text}")
    exit(1)

# 3. List Departments
print("\n--- 3. Listing Departments ---")
response = requests.get(f"{BASE_URL}/departments", headers=headers)
if response.status_code == 200:
    depts = response.json()
    print(f"Found {len(depts)} departments.")
    found = False
    for d in depts:
        print(f"- {d['name']} (ID: {d['id']})")
        if d['id'] == dept_id:
            found = True
    if not found:
        print("ERROR: Created department not found in list!")
        exit(1)
else:
    print(f"Listing failed: {response.text}")
    exit(1)

# 4. Delete Department
print(f"\n--- 4. Deleting Department ID {dept_id} ---")
response = requests.delete(f"{BASE_URL}/departments/{dept_id}", headers=headers)
if response.status_code == 204:
    print("Department deleted successfully.")
else:
    print(f"Deletion failed: {response.text}")
    exit(1)

# 5. Verify Deletion
print("\n--- 5. Verifying Deletion ---")
response = requests.get(f"{BASE_URL}/departments", headers=headers)
found = False
for d in response.json():
    if d['id'] == dept_id:
        found = True
        break
if found:
    print("ERROR: Department still exists after deletion!")
else:
    print("SUCCESS: Department is gone.")

print("\n--- Test Complete ---")
