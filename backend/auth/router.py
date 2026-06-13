from fastapi import APIRouter, Depends, Response
from core.config import settings
from auth.schemas import LoginRequest, UserResponse
from auth.dependencies import get_auth_service, get_current_user
from auth.service import AuthService

router = APIRouter(prefix="/auth", tags=["authentication"])


@router.post("/login")
def login(
    payload: LoginRequest,
    response: Response,
    auth_service: AuthService = Depends(get_auth_service),
):
    username = auth_service.authenticate(payload.username, payload.password)

    token = auth_service.generate_token(username)
    max_age_seconds = settings.AUTH_COOKIE_MAX_AGE_DAYS * 24 * 60 * 60
    secure_cookie = not settings.DEBUG

    response.set_cookie(
        key=settings.AUTH_COOKIE_NAME,
        value=token,
        max_age=max_age_seconds,
        httponly=True,
        secure=secure_cookie,
        samesite="lax",
    )

    return {"message": "Successfully logged in"}


@router.post("/logout")
def logout(response: Response):
    secure_cookie = not settings.DEBUG
    response.delete_cookie(
        key=settings.AUTH_COOKIE_NAME,
        httponly=True,
        secure=secure_cookie,
        samesite="lax",
    )
    return {"message": "Successfully logged out"}


@router.get("/me", response_model=UserResponse)
def get_me(current_user: str = Depends(get_current_user)):
    return UserResponse(username=current_user)
