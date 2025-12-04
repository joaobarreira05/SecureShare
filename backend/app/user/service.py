from sqlmodel import Session
from ..models.User import User, UserUpdate
from ..auth.service import get_password_hash

async def update_user_info(session: Session, user: User, update_data: UserUpdate):
    if update_data.full_name is not None:
        user.full_name = update_data.full_name
    
    if update_data.email is not None:
        user.email = update_data.email
        
    if update_data.password is not None:
        user.hashed_password = get_password_hash(update_data.password)
        
    session.add(user)
    session.commit()
    session.refresh(user)
    return user
