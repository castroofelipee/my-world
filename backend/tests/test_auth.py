import pytest
from datetime import datetime, timedelta, timezone
from fastapi.testclient import TestClient
import jwt
from main import app
from core.config import settings

client = TestClient(app)


def test_login_happy_path():
    response = client.post(
        "/auth/login", json={"username": "admin", "password": "secret"}
    )
    assert response.status_code == 200
    assert response.json() == {"message": "Successfully logged in"}

    cookie = response.cookies.get(settings.AUTH_COOKIE_NAME)
    assert cookie is not None

    set_cookie_header = response.headers.get("set-cookie")
    assert set_cookie_header is not None
    assert "httponly" in set_cookie_header.lower()
    assert "samesite=lax" in set_cookie_header.lower()

    if not settings.DEBUG:
        assert "secure" in set_cookie_header.lower()

    expected_max_age = str(settings.AUTH_COOKIE_MAX_AGE_DAYS * 24 * 60 * 60)
    assert f"max-age={expected_max_age}" in set_cookie_header.lower()


def test_logout_happy_path():
    login_response = client.post(
        "/auth/login", json={"username": "admin", "password": "secret"}
    )
    assert login_response.status_code == 200

    logout_response = client.post("/auth/logout")
    assert logout_response.status_code == 200
    assert logout_response.json() == {"message": "Successfully logged out"}

    set_cookie_header = logout_response.headers.get("set-cookie")
    assert set_cookie_header is not None
    assert (
        "max-age=0" in set_cookie_header.lower()
        or "expires=" in set_cookie_header.lower()
        or settings.AUTH_COOKIE_NAME not in logout_response.cookies
    )


def test_authenticated_request_happy_path():
    login_response = client.post(
        "/auth/login", json={"username": "admin", "password": "secret"}
    )
    assert login_response.status_code == 200

    response = client.get("/auth/me")
    assert response.status_code == 200
    assert response.json() == {"username": "admin"}


def test_credential_failures_invalid_username():
    response = client.post(
        "/auth/login", json={"username": "wrong_admin", "password": "secret"}
    )
    assert response.status_code == 401
    assert response.json() == {"detail": "Invalid credentials"}


def test_credential_failures_invalid_password():
    response = client.post(
        "/auth/login", json={"username": "admin", "password": "wrong_password"}
    )
    assert response.status_code == 401
    assert response.json() == {"detail": "Invalid credentials"}


def test_credential_failures_empty_username():
    response = client.post(
        "/auth/login", json={"username": "", "password": "secret"}
    )
    assert response.status_code == 401
    assert response.json() == {"detail": "Invalid credentials"}


def test_credential_failures_empty_password():
    response = client.post(
        "/auth/login", json={"username": "admin", "password": ""}
    )
    assert response.status_code == 401
    assert response.json() == {"detail": "Invalid credentials"}


def test_token_failures_missing_cookie():
    clean_client = TestClient(app)
    response = clean_client.get("/auth/me")
    assert response.status_code == 401
    assert response.json() == {"detail": "Invalid credentials"}


def test_token_failures_malformed_token():
    clean_client = TestClient(app)
    clean_client.cookies.set(
        settings.AUTH_COOKIE_NAME, "malformed-jwt-token-value"
    )
    response = clean_client.get("/auth/me")
    assert response.status_code == 401
    assert response.json() == {"detail": "Invalid credentials"}


def test_token_failures_expired_token():
    now = datetime.now(timezone.utc)
    expired_payload = {
        "sub": "admin",
        "exp": now - timedelta(seconds=10),
        "iat": now - timedelta(minutes=10),
    }
    expired_token = jwt.encode(
        expired_payload, settings.SECRET_KEY, algorithm="HS256"
    )

    clean_client = TestClient(app)
    clean_client.cookies.set(settings.AUTH_COOKIE_NAME, expired_token)
    response = clean_client.get("/auth/me")
    assert response.status_code == 401
    assert response.json() == {"detail": "Invalid credentials"}


def test_token_failures_invalid_signature():
    now = datetime.now(timezone.utc)
    payload = {
        "sub": "admin",
        "exp": now + timedelta(days=1),
        "iat": now,
    }
    invalid_token = jwt.encode(
        payload, "wrong_signing_key_12345_longer_than_32_bytes_long", algorithm="HS256"
    )

    clean_client = TestClient(app)
    clean_client.cookies.set(settings.AUTH_COOKIE_NAME, invalid_token)
    response = clean_client.get("/auth/me")
    assert response.status_code == 401
    assert response.json() == {"detail": "Invalid credentials"}


def test_security_leak_prevention():
    response = client.post(
        "/auth/login", json={"username": "admin", "password": "wrong_password"}
    )
    assert response.status_code == 401
    assert response.json() == {"detail": "Invalid credentials"}

    response_text = response.text
    assert settings.SECRET_KEY not in response_text
    assert settings.ADMIN_PASSWORD_HASH not in response_text
    assert "argon" not in response_text.lower()

    valid_response = client.post(
        "/auth/login", json={"username": "admin", "password": "secret"}
    )
    assert valid_response.status_code == 200
    valid_response_text = valid_response.text
    assert settings.SECRET_KEY not in valid_response_text
    assert settings.ADMIN_PASSWORD_HASH not in valid_response_text
    assert "argon" not in valid_response_text.lower()

    me_response = client.get("/auth/me")
    assert me_response.status_code == 200
    me_response_text = me_response.text
    assert settings.SECRET_KEY not in me_response_text
    assert settings.ADMIN_PASSWORD_HASH not in me_response_text
    assert "argon" not in me_response_text.lower()
