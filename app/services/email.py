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

# Best-effort in-process email counters (surfaced via /metrics note; full
# Prometheus RED metrics live in metrics.py which queries DB — email has no DB
# table, so we keep process counters here and expose via generate_email_metrics).
_email_sent_total: int = 0
_email_failed_total: int = 0


def email_counters() -> dict[str, int]:
    return {"sent": _email_sent_total, "failed": _email_failed_total}


def generate_email_metrics_text() -> str:
    return (
        "# HELP webhook_email_send_total Transactional emails accepted for delivery\n"
        "# TYPE webhook_email_send_total counter\n"
        f'webhook_email_send_total{{result="sent"}} {_email_sent_total}\n'
        f'webhook_email_send_total{{result="failed"}} {_email_failed_total}\n'
    )


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
    from_name = (settings.SMTP_FROM_NAME or "Hookflow").strip() or "Hookflow"
    from_email = (settings.SMTP_FROM_EMAIL or "noreply@hookflow.local").strip()
    safe_name = _html.escape(from_name, quote=True)
    safe_otp = _html.escape((otp or "").strip(), quote=True)
    msg = EmailMessage()
    # Keep the OTP out of the Subject: subjects are logged by MTAs,
    # shown in push/lock-screen notifications, and are a classic
    # spam-heuristic trigger ("code: 123456" patterns).
    msg["Subject"] = f"{from_name} password reset code"
    msg["From"] = f"{from_name} <{from_email}>"
    msg["To"] = to_email
    msg.set_content(f"""Hi,

You requested a password reset for your {from_name} account.

Your verification code is:

    {otp}

This code expires in {expire_minutes} minutes. Enter it on the
password-reset page to choose a new password.

If you did not request this, you can safely ignore this email —
your password will not change.

— The {from_name} team
""")
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
    When SMTP is unconfigured, returns False (fail-closed) unless the test-only
    PASSWORD_RESET_OTP_CAPTURE sink is enabled — callers show a generic
    "if an account exists" message either way, so dev without SMTP does not
    silently pretend delivery succeeded. The OTP is never logged.
    """
    exp_min = int(expire_minutes if expire_minutes is not None else settings.PASSWORD_RESET_OTP_EXPIRE_MINUTES)
    clean_to = (to_email or "").strip()
    if not clean_to:
        return False

    if not is_email_configured():
        if settings.PASSWORD_RESET_OTP_CAPTURE:
            if len(_captured_otps) < 1000:
                _captured_otps.append({"to": clean_to, "otp": otp})
            return True
        # Fail closed in every ENV: returning True here masked SMTP outages
        # (staging showed "code sent" with nothing delivered while prod failed).
        logger.error("SMTP not configured; refusing to fake a password-reset delivery to %s", _mask_email(clean_to))
        return False

    return _send_message(_build_otp_message(clean_to, otp, exp_min), clean_to)


def _send_message(msg: EmailMessage, to_email: str) -> bool:
    """Delivers one message. Never raises and never logs message contents."""
    global _email_sent_total, _email_failed_total
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
        _email_sent_total += 1
        logger.info("Email accepted for %s via %s:%s", _mask_email(to_email), host, port)
        return True
    except Exception as e:
        _email_failed_total += 1
        logger.warning("Failed to send email to %s via %s:%s: %s", _mask_email(to_email), host, port, e)
        return False


def send_invitation_email(to_email: str, invite_url: str, org_name: str, role: str) -> bool:
    """Emails a one-time invitation link. Returns False when it cannot be delivered.

    The URL contains the raw token. Callers must not persist that token, and
    this function never logs the URL.
    """
    clean_to = (to_email or "").strip()
    if not clean_to or not invite_url:
        return False
    if not is_email_configured():
        try:
            from app.config import is_production_env as _is_prod

            _prod = bool(_is_prod(getattr(settings, "ENV", "")))
        except Exception:
            _prod = False
        if _prod:
            logger.error("SMTP not configured; refusing to fake an invitation delivery")
        else:
            logger.info("SMTP not configured; invitation email not sent to %s", _mask_email(clean_to))
        return False

    from_name = (settings.SMTP_FROM_NAME or "Hookflow").strip() or "Hookflow"
    from_email = (settings.SMTP_FROM_EMAIL or "noreply@hookflow.local").strip()
    safe_name = _html.escape(from_name, quote=True)
    safe_org = _html.escape((org_name or "your organization").strip(), quote=True)
    safe_role = _html.escape((role or "member").strip(), quote=True)
    safe_url = _html.escape(invite_url, quote=True)

    msg = EmailMessage()
    msg["Subject"] = f"You've been invited to {org_name or from_name}"
    msg["From"] = f"{from_name} <{from_email}>"
    msg["To"] = clean_to
    msg.set_content(f"""Hi,

You've been invited to join {org_name or "an organization"} on {from_name} as {role or "member"}.

Open this link to accept (it expires in 7 days):

    {invite_url}

If you did not expect this invitation, you can ignore this email.

— The {from_name} team
""")
    msg.add_alternative(
        f"""<html><body style="font-family:Inter,system-ui,sans-serif;color:#111813;">
<p>Hi,</p>
<p>You've been invited to join <strong>{safe_org}</strong> on {safe_name} as <strong>{safe_role}</strong>.</p>
<p><a href="{safe_url}" style="display:inline-block;padding:10px 16px;background:#1aae5c;color:#fff;
text-decoration:none;border-radius:8px;font-weight:600;">Accept invitation</a></p>
<p style="color:#6b7c70;">This link expires in 7 days. If you did not expect this, ignore this email.</p>
<p>— The {safe_name} team</p>
</body></html>""",
        subtype="html",
    )
    return _send_message(msg, clean_to)
