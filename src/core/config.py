from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    DATABASE_URL: str = "postgresql+asyncpg://sentinel_app:app_secure_password@localhost:5432/sentinelcore"
    REDIS_URL: str = "redis://localhost:6379/0"
    
    # Asymmetric RS256 + JWKS Configuration
    ALGORITHM: str = "RS256"
    JWKS_URL: str = "http://localhost:8000/.well-known/jwks.json"
    JWKS_COOLDOWN_SECONDS: int = 10
    
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    RATE_LIMIT_PER_MINUTE: int = 60

settings = Settings()
