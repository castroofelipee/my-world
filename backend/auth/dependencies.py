from fastapi import Request, HTTPException, status, Depends
import jwt
from core.config import settings
from auth.security import decode_access_token
from auth.service import AuthService


def get_auth_service() -> AuthService:
    return AuthService()


def get_current_user(request: Request) -> str:
    token = request.cookies.get(settings.AUTH_COOKIE_NAME)
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
        )

    try:
        username = decode_access_token(token)
    except (jwt.ExpiredSignatureError, jwt.InvalidTokenError, Exception):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
        )

    if username != settings.ADMIN_USERNAME:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
        )

    return username
