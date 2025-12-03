from sqlmodel import Session, select
from .database import engine
from .settings import settings
from ..models.User import User
from ..auth.service import get_custom_hash

def init_db():
    with Session(engine) as session:
        statement = select(User).where(User.username == settings.ADMIN_USERNAME)
        user = session.exec(statement).first()
        
        if not user:
            print(f"Creating initial admin user: {settings.ADMIN_USERNAME}")
            
            # Generate custom hash
            hashed_password = get_custom_hash(
                settings.ADMIN_PASSWORD,
                settings.HASH_SALT,
                settings.HASH_ALGORITHM,
                settings.HASH_ITERATIONS
            )
            
            admin_user = User(
                id=1, # Explicitly set ID to 1 as requested
                username=settings.ADMIN_USERNAME,
                hashed_password=hashed_password,
                full_name="Administrator",
                email="admin@secureshare.local",
                is_active=True,
                is_admin=True,
                public_key=settings.ADMIN_PUBLIC_KEY,
                encrypted_private_key=settings.ADMIN_ENCRYPTED_PRIVATE_KEY
            )
            
            session.add(admin_user)
            session.commit()
            print("Admin user created successfully.")
        else:
            print("Admin user already exists.")
