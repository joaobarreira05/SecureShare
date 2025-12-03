from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    PROJECT_NAME: str = "SecureShare"
    DATABASE_URL: str = "sqlite:///./secureshare.db"
    SECRET_KEY: str = "change_this_to_a_secure_random_key"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 15
    
    # Admin Hardcoded Credentials
    ADMIN_USERNAME: str = "admin"
    ADMIN_PASSWORD: str = "admin"
    ADMIN_PUBLIC_KEY: str = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQD..." # Placeholder
    ADMIN_ENCRYPTED_PRIVATE_KEY: str = "..." # Placeholder
    
    # Custom Hashing Config
    HASH_ALGORITHM: str = "sha256"
    HASH_ITERATIONS: int = 10000
    HASH_SALT: str = "hardcoded_salt_for_admin" # For the initial admin seed

    model_config = SettingsConfigDict(env_file=".env")

settings = Settings()
