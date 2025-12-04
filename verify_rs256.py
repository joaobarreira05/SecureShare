import sys
import os
sys.path.append("backend")

from app.core.settings import settings
from app.auth.service import create_access_token, get_current_user
from sqlmodel import Session, create_engine, select
from app.models.JWTAuthToken import JWTAuthToken
from datetime import timedelta
from jose import jwt

# Mock Session
engine = create_engine("sqlite:///:memory:")
session = Session(engine)
JWTAuthToken.metadata.create_all(engine)

def verify_rs256():
    print("Verifying RS256 Token Generation...")
    
    # 1. Generate Token
    user_id = 1
    data = {"sub": "admin"}
    token = create_access_token(session, user_id, data, timedelta(minutes=15))
    print(f"Generated Token: {token[:20]}...")
    
    # 2. Verify Header
    headers = jwt.get_unverified_header(token)
    print(f"Token Headers: {headers}")
    if headers['alg'] != 'RS256':
        print("FAILURE: Algorithm is not RS256")
        sys.exit(1)
        
    # 3. Verify Signature using Public Key
    try:
        payload = jwt.decode(token, settings.SERVER_PUBLIC_KEY, algorithms=["RS256"])
        print(f"Decoded Payload: {payload}")
        if payload['sub'] != 'admin':
             print("FAILURE: Payload mismatch")
             sys.exit(1)
    except Exception as e:
        print(f"FAILURE: Verification failed: {e}")
        sys.exit(1)

    print("SUCCESS: RS256 Token Verified!")

if __name__ == "__main__":
    verify_rs256()
