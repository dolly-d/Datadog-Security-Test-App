from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    app_env: str = "lab"
    database_url: str
    redis_url: str
    danger_mode: bool = False
    weak_auth_mode: bool = True
    log_level: str = "INFO"

settings = Settings()  # reads env vars
