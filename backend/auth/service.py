from datetime import timedelta
from fastapi import HTTPException, status
from core.config import settings
from auth.security import verify_password, create_access_token


class AuthService:
    def authenticate(self, username: str, password: str) -> str:
        if not username or not password:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid credentials",
            )

        if username != settings.ADMIN_USERNAME:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid credentials",
            )

        if not verify_password(password, settings.ADMIN_PASSWORD_HASH):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid credentials",
            )

        return username

    def generate_token(self, username: str) -> str:
        expires_delta = timedelta(days=settings.AUTH_COOKIE_MAX_AGE_DAYS)
        return create_access_token(subject=username, expires_delta=expires_delta)
