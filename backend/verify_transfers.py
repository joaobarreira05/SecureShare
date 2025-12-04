import os
import json
from fastapi.testclient import TestClient
from app.main import app
from app.core.database import create_db_and_tables
from app.core.init_db import init_db

# Initialize DB
create_db_and_tables()
init_db()

client = TestClient(app)

def test_transfers():
    print("Starting Transfer Verification...")

    # 1. Upload File
    print("\n[1] Testing Upload...")
    file_content = b"This is a test encrypted file content."
    files = {"file": ("test_enc.bin", file_content, "application/octet-stream")}
    data = {
        "classification": "TOP_SECRET",
        "departments": json.dumps(["HR", "Finance"]),
        "recipient_keys": json.dumps([{"recipient_id": 1, "encrypted_key": "dGVzdF9rZXk="}]), # Base64 "test_key"
        "expires_in_days": 7
    }
    
    # Mock user is ID 1, so we are sending to ourselves
    
    response = client.post("/transfers", files=files, data=data)
    if response.status_code != 201:
        print(f"Upload Failed: {response.status_code} - {response.text}")
        return
    
    transfer_id = response.json()["transfer_id"]
    print(f"Upload Success. Transfer ID: {transfer_id}")

    # 2. Get Metadata
    print("\n[2] Testing Get Metadata...")
    response = client.get(f"/transfers/{transfer_id}")
    if response.status_code != 200:
        print(f"Get Metadata Failed: {response.status_code} - {response.text}")
        return
    
    metadata = response.json()
    print(f"Metadata: {json.dumps(metadata, indent=2)}")
    assert metadata["filename"] == "test_enc.bin"
    assert metadata["classification"] == "TOP_SECRET"

    # 3. Download File
    print("\n[3] Testing Download...")
    response = client.get(f"/transfers/download/{transfer_id}")
    if response.status_code != 200:
        print(f"Download Failed: {response.status_code} - {response.text}")
        return
    
    downloaded_content = response.content
    print(f"Downloaded {len(downloaded_content)} bytes.")
    assert downloaded_content == file_content
    print("Content matches.")

    # 4. List Transfers
    print("\n[4] Testing List Transfers...")
    response = client.get("/transfers")
    if response.status_code != 200:
        print(f"List Failed: {response.status_code} - {response.text}")
        return
    
    transfers = response.json()
    print(f"Found {len(transfers)} transfers.")
    found = False
    for t in transfers:
        if t["id"] == transfer_id:
            found = True
            break
    assert found
    print("Transfer found in list.")

    # 5. Delete Transfer
    print("\n[5] Testing Delete...")
    response = client.delete(f"/transfers/{transfer_id}")
    if response.status_code != 200:
        print(f"Delete Failed: {response.status_code} - {response.text}")
        return
    
    print("Delete Success.")

    # Verify Deletion
    response = client.get(f"/transfers/{transfer_id}")
    assert response.status_code == 404
    print("Verified deletion (404 returned).")

    print("\nVerification Complete: SUCCESS")

if __name__ == "__main__":
    test_transfers()
