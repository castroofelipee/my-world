from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    APP_NAME: str
    DATABASE_URL: str
    DEBUG: bool = False

    ADMIN_USERNAME: str
    ADMIN_PASSWORD_HASH: str
    SECRET_KEY: str
    AUTH_COOKIE_NAME: str = "session"
    AUTH_COOKIE_MAX_AGE_DAYS: int = 7

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")


settings = Settings()

