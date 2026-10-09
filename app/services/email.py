"""Transactional email delivery via SMTP (forgot-password OTP).

Uses only the Python standard library (smtplib + email) so no new
dependencies are required. When SMTP is not configured (no SMTP_HOST),
delivery is skipped. The plaintext OTP is never written to the application
log. Automated tests opt into an in-process capture sink with
PASSWORD_RESET_OTP_CAPTURE; that sink is off unless explicitly enabled.
"""

import html as _html
import logging
import smtplib
import ssl
from email.message import EmailMessage

from app.config import settings

logger = logging.getLogger("webhook.email")

# In-process mail sink. Populated only when PASSWORD_RESET_OTP_CAPTURE is on,
# so tests can read a code without it ever reaching a log line.
_captured_otps: list[dict[str, str]] = []


def captured_otps() -> list[dict[str, str]]:
    """Copies of OTPs held by the test-only capture sink."""
    return [dict(item) for item in _captured_otps]


def clear_captured_otps() -> None:
    _captured_otps.clear()


def _mask_email(email: str) -> str:
    """user@example.com -> u***@example.com. Never log the full recipient."""
    local, _, domain = (email or "").partition("@")
    if not local or not domain:
        return "***"
    return f"{local[0]}***@{domain}"


def is_email_configured() -> bool:
    return bool((settings.SMTP_HOST or "").strip())


def _build_otp_message(to_email: str, otp: str, expire_minutes: int) -> EmailMessage:
    from_name = (settings.SMTP_FROM_NAME or "Relayflow").strip() or "Relayflow"
    from_email = (settings.SMTP_FROM_EMAIL or "noreply@relayflow.local").strip()
    safe_name = _html.escape(from_name, quote=True)
    safe_otp = _html.escape((otp or "").strip(), quote=True)
    msg = EmailMessage()
    # Keep the OTP out of the Subject: subjects are logged by MTAs,
    # shown in push/lock-screen notifications, and are a classic
    # spam-heuristic trigger ("code: 123456" patterns).
    msg["Subject"] = f"{from_name} password reset code"
    msg["From"] = f"{from_name} <{from_email}>"
    msg["To"] = to_email
    msg.set_content(
        f"""Hi,

You requested a password reset for your {from_name} account.

Your verification code is:

    {otp}

This code expires in {expire_minutes} minutes. Enter it on the
password-reset page to choose a new password.

If you did not request this, you can safely ignore this email —
your password will not change.

— The {from_name} team
"""
    )
    msg.add_alternative(
        f"""<html><body style="font-family:Inter,system-ui,sans-serif;color:#111813;">
<p>Hi,</p>
<p>You requested a password reset for your <strong>{safe_name}</strong> account.</p>
<p>Your verification code is:</p>
<p style="font-size:28px;font-weight:800;letter-spacing:6px;background:#f4f6f3;
border:1px solid #e5ebe6;border-radius:12px;padding:12px 18px;display:inline-block;">{safe_otp}</p>
<p style="color:#6b7c70;">This code expires in <strong>{expire_minutes} minutes</strong>.
Enter it on the password-reset page to choose a new password.</p>
<p style="color:#6b7c70;">If you did not request this, you can safely ignore this email.</p>
<p>— The {safe_name} team</p>
</body></html>""",
        subtype="html",
    )
    return msg


def send_otp_email(to_email: str, otp: str, expire_minutes: int | None = None) -> bool:
    """Sends the forgot-password OTP. Returns True if accepted for delivery.

    Never raises: SMTP failures are logged and return False so callers can
    keep the user-facing response generic (no account enumeration, no 500s).
    When SMTP is unconfigured, returns True without logging the OTP so the
    flow stays usable offline. With PASSWORD_RESET_OTP_CAPTURE enabled the
    OTP is held in an in-process sink for tests; it is never logged.
    """
    exp_min = int(expire_minutes if expire_minutes is not None else settings.PASSWORD_RESET_OTP_EXPIRE_MINUTES)
    clean_to = (to_email or "").strip()
    if not clean_to:
        return False

    if not is_email_configured():
        if settings.PASSWORD_RESET_OTP_CAPTURE:
            _captured_otps.append({"to": clean_to, "otp": otp})
        else:
            # No recipient, no code: nothing here is usable as a credential.
            logger.info(
                "SMTP not configured; password-reset email not sent (request expires in %sm)",
                exp_min,
            )
        return True

    msg = _build_otp_message(clean_to, otp, exp_min)
    host = (settings.SMTP_HOST or "").strip()
    port = int(settings.SMTP_PORT or 587)
    username = (settings.SMTP_USERNAME or "").strip()
    password = settings.SMTP_PASSWORD or ""
    timeout = float(settings.SMTP_TIMEOUT_SECONDS or 10.0)

    try:
        if settings.SMTP_USE_SSL:
            context = ssl.create_default_context()
            with smtplib.SMTP_SSL(host, port, timeout=timeout, context=context) as server:
                if username:
                    server.login(username, password)
                server.send_message(msg)
        else:
            with smtplib.SMTP(host, port, timeout=timeout) as server:
                if settings.SMTP_USE_TLS:
                    context = ssl.create_default_context()
                    server.starttls(context=context)
                if username:
                    server.login(username, password)
                server.send_message(msg)
        logger.info("Password-reset email accepted for %s via %s:%s", _mask_email(clean_to), host, port)
        return True
    except Exception as e:
        logger.warning(
            "Failed to send password-reset email to %s via %s:%s: %s", _mask_email(clean_to), host, port, e
        )
        return False
