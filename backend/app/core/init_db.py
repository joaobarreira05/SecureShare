from sqlmodel import Session, select
from .database import engine
from .settings import settings
from ..models.User import User
from ..auth.service import get_password_hash

def init_db():
    with Session(engine) as session:
        statement = select(User).where(User.username == settings.ADMIN_USERNAME)
        user = session.exec(statement).first()
        
        if not user:
            print(f"Creating initial admin user: {settings.ADMIN_USERNAME}")
            
            # Generate custom hash
            hashed_password = get_password_hash(settings.ADMIN_PASSWORD)
            
            # Generate Admin Keys
            print("Generating Admin RSA Keys (4096 bits)...")
            from .crypto import generate_rsa_keypair, encrypt_private_key_with_password
            
            private_pem, public_pem = generate_rsa_keypair()
            encrypted_private_key = encrypt_private_key_with_password(
                private_pem, 
                settings.ADMIN_PASSWORD
            )
            
            admin_user = User(
                id=1, # Explicitly set ID to 1 as requested
                username=settings.ADMIN_USERNAME,
                hashed_password=hashed_password,
                full_name="Administrator",
                email="admin@secureshare.local",
                is_active=True,
                is_admin=True,
                public_key=public_pem.decode("utf-8"),
                encrypted_private_key=encrypted_private_key
            )
            
            session.add(admin_user)
            session.commit()
            print("Admin user created successfully.")
        else:
            print("Admin user already exists.")
