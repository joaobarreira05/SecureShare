from fastapi import HTTPException, status
from sqlmodel import Session, select
from ..models.User import User, UserCreate
from ..auth.service import get_password_hash

async def create_user(session: Session, user: UserCreate):
    statement = select(User).where(User.username == user.username)
    db_user = session.exec(statement).first()
    if db_user:
        raise HTTPException(status_code=400, detail="Username already registered")
    
    # Hash the OTP provided by the admin
    hashed_otp = get_password_hash(user.otp)
    
    db_user = User(
        username=user.username,
        email=user.email,
        full_name=user.full_name,
        otp_hash=hashed_otp,
        is_active=False, # User is inactive until they activate with OTP
        is_admin=False
    )
    session.add(db_user)
    session.commit()
    session.refresh(db_user)
    return db_user
