"""Regression tests for password-reset credential exposure.

Two defects:

1. After OTP verification the signed reset bearer was placed in the
   redirect query string (``/auth/reset-password?token=...``), so access
   logs, proxies, and browser history retained a live credential.
2. With SMTP unconfigured and ENV not exactly "production", the plaintext
   OTP was written to the INFO application log.
"""

import logging
import re
import uuid

import pytest
from fastapi.testclient import TestClient

from app.db.session import SessionLocal
from app.main import app
from app.models import User
from app.services.security import hash_password, verify_password

_NEW_PASSWORD = "Reset-Pass-1"


@pytest.fixture
def http():
    """Fresh client per test so cookies never leak between cases."""
    with TestClient(app) as c:
        yield c


def _csrf_from(response, held: str | None = None) -> tuple[str, str]:
    """Pull the anonymous CSRF cookie and the matching form token.

    ``held`` is the cookie already stored by the client: a page only sets
    wh_csrf_id when the request arrived without one.
    """
    csrf_id = response.cookies.get("wh_csrf_id") or held
    match = re.search(r'name="csrf_token" value="([^"]+)"', response.text)
    assert csrf_id, "expected wh_csrf_id cookie"
    assert match, "expected csrf_token hidden input"
    return csrf_id, match.group(1)


@pytest.fixture
def reset_user():
    db = SessionLocal()
    uid = uuid.uuid4().hex[:8]
    email = f"reset_{uid}@test.com"
    user = User(email=email, password_hash=hash_password("Old-Password-1"))
    db.add(user)
    db.commit()
    user_id = user.id
    yield {"id": user_id, "email": email}
    db.close()


def test_verified_otp_redirects_without_token_in_url(http, reset_user):
    """A successful OTP check must not put the reset bearer in the URL.

    The redirect target is a clean path. The only credential delivered to
    the browser is an opaque id in a short-lived HttpOnly cookie.
    """
    from app.services.password_reset import create_otp_for_user

    db = SessionLocal()
    try:
        otp = create_otp_for_user(db, reset_user["id"], reset_user["email"])[1]
    finally:
        db.close()

    page = http.get("/auth/forgot-password/verify", params={"email": reset_user["email"]})
    csrf_token = _csrf_from(page)[1]

    response = http.post(
        "/auth/forgot-password/verify",
        data={"email": reset_user["email"], "otp": otp, "csrf_token": csrf_token},
        follow_redirects=False,
    )

    assert response.status_code == 303
    location = response.headers["location"]
    assert location.split("?", 1)[0].rstrip("/") == "/auth/reset-password"
    assert "token=" not in location
    # The signed bearer itself must not appear anywhere in the redirect.
    assert "." not in location.split("?", 1)[-1] if "?" in location else True

    set_cookie = response.headers.get("set-cookie", "")
    assert "wh_reset_session=" in set_cookie
    assert "httponly" in set_cookie.lower()
    assert "samesite=strict" in set_cookie.lower()
    # Cookie value is an opaque session id, not the signed itsdangerous token
    # (those always contain a '.' separator between payload and signature).
    cookie_value = response.cookies.get("wh_reset_session")
    assert cookie_value
    assert "." not in cookie_value


def test_reset_completes_from_cookie_without_form_token(http, reset_user):
    """The password form posts no bearer. The cookie is the only credential,
    and it is single-use: a second submit with the same cookie fails."""
    from app.services.password_reset import create_otp_for_user

    db = SessionLocal()
    try:
        otp = create_otp_for_user(db, reset_user["id"], reset_user["email"])[1]
    finally:
        db.close()

    page = http.get("/auth/forgot-password/verify", params={"email": reset_user["email"]})
    csrf_token = _csrf_from(page)[1]
    verified = http.post(
        "/auth/forgot-password/verify",
        data={"email": reset_user["email"], "otp": otp, "csrf_token": csrf_token},
        follow_redirects=False,
    )
    reset_cookie = verified.cookies.get("wh_reset_session")
    assert reset_cookie

    form = http.get("/auth/reset-password")
    assert form.status_code == 200
    assert 'name="token"' not in form.text
    form_csrf = _csrf_from(form, held=http.cookies.get("wh_csrf_id"))[1]

    done = http.post(
        "/auth/reset-password",
        data={"password": _NEW_PASSWORD, "confirm_password": _NEW_PASSWORD, "csrf_token": form_csrf},
    )
    assert done.status_code == 200
    assert "Password reset successful" in done.text

    db = SessionLocal()
    try:
        user = db.query(User).filter(User.id == reset_user["id"]).first()
        assert verify_password(_NEW_PASSWORD, user.password_hash)
    finally:
        db.close()

    # Cookie was consumed with the reset; replaying it must not reset again.
    # Re-set it explicitly: the successful response deleted it.
    http.cookies.set("wh_reset_session", reset_cookie)
    replay_page = http.get("/auth/forgot-password/verify", params={"email": reset_user["email"]})
    replay_csrf = _csrf_from(replay_page, held=http.cookies.get("wh_csrf_id"))[1]
    replay = http.post(
        "/auth/reset-password",
        data={"password": "Another-Pass-2", "confirm_password": "Another-Pass-2", "csrf_token": replay_csrf},
        follow_redirects=False,
    )
    assert replay.status_code == 400


def test_reset_page_without_cookie_is_rejected(http):
    """A clean URL with no reset cookie is not a usable reset link."""
    response = http.get("/auth/reset-password", follow_redirects=False)
    assert response.status_code == 400
    assert "invalid or has expired" in response.text.lower()


def test_send_otp_email_never_logs_plaintext_otp(caplog, monkeypatch):
    """Unconfigured SMTP must not write the live OTP to application logs,
    regardless of ENV. The dev fallback used to log it at INFO."""
    from app.config import Settings, settings
    from app.services.email import send_otp_email

    assert "PASSWORD_RESET_OTP_CAPTURE" in Settings.model_fields
    monkeypatch.setattr(settings, "SMTP_HOST", "")
    monkeypatch.setattr(settings, "ENV", "development")
    monkeypatch.setattr(settings, "PASSWORD_RESET_OTP_CAPTURE", False)

    otp = "654321"
    with caplog.at_level(logging.DEBUG, logger="webhook.email"):
        assert send_otp_email("person@example.com", otp) is True

    assert otp not in caplog.text
    assert "person@example.com" not in caplog.text


def test_otp_capture_requires_explicit_test_setting(monkeypatch):
    """OTP inspection exists only behind an explicit test-only flag, and
    even then it stays out of the log stream."""
    from app.config import settings
    from app.services import email as email_mod

    monkeypatch.setattr(settings, "SMTP_HOST", "")
    monkeypatch.setattr(settings, "ENV", "development")

    assert "PASSWORD_RESET_OTP_CAPTURE" in type(settings).model_fields
    monkeypatch.setattr(settings, "PASSWORD_RESET_OTP_CAPTURE", False)
    email_mod.clear_captured_otps()
    send = email_mod.send_otp_email
    assert send("hidden@example.com", "111222") is True
    assert email_mod.captured_otps() == []

    monkeypatch.setattr(settings, "PASSWORD_RESET_OTP_CAPTURE", True)
    email_mod.clear_captured_otps()
    assert send("visible@example.com", "333444") is True
    captured = email_mod.captured_otps()
    assert captured == [{"to": "visible@example.com", "otp": "333444"}]
