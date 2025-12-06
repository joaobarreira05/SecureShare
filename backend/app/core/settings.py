from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    PROJECT_NAME: str = "SecureShare"
    DATABASE_URL: str = "sqlite:///./data/secureshare.db"
    
    # Auth Config
    ALGORITHM: str 
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 15
    SERVER_PRIVATE_KEY: str
    SERVER_PUBLIC_KEY: str
    
    # Security
    PASSWORD_PEPPER: str

    # Admin ConfigHardcoded Credentials
    ADMIN_USERNAME: str 
    ADMIN_PASSWORD: str
    
    model_config = SettingsConfigDict(env_file=".env")

settings = Settings()
