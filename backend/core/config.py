from python_settings import BaseConfig, SettingsConfigDict


class Settings(BaseConfig):
    APP_NAME: str
    DATABASE_URL: str
    DEBUG: bool = False

    model_config = SettingsConfigDict(env_prefix=".env", extra="ignore")


settings = Settings()
