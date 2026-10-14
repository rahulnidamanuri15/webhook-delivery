import json
import re

from fastapi import APIRouter, Depends, Form, HTTPException, Query, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import func, or_
from sqlalchemy.orm import Session, joinedload

_EMAIL_REGEX = re.compile(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$")

from app.api.deps import get_optional_user
from app.config import settings
from app.db.session import get_db
from app.models import (
    ApiKey,
    Delivery,
    DeliveryAttempt,
    Endpoint,
    EndpointSubscription,
    Event,
    Organization,
    OrganizationMember,
    Project,
    User,
    utc_now,
)
from app.services.delivery_service import replay_delivery
from app.services.event_service import IdempotencyConflictError, ingest_event
from app.services.security import (
    create_session_token,
    decrypt_secret,
    encrypt_secret,
    generate_api_key,
    generate_signing_secret,
    get_client_ip,
    get_csrf_token_for_request,
    hash_password,
    rotate_secret_ciphertext,
    validate_request_csrf,
    verify_password,
)
from app.services.ssrf import validate_webhook_url

# Module-level dummy Argon2 hash for login timing mitigation (lazy init).
_DUMMY_LOGIN_HASH: str | None = None


def is_cookie_secure() -> bool:
    # Production (incl. prod/staging aliases) always uses Secure cookies: the
    # dashboard is served over HTTPS there, and Secure has no downside on TLS.
    # COOKIE_SECURE may only relax this in non-production (local plain-HTTP dev).
    from app.config import is_production_env as _is_prod

    if _is_prod(settings.ENV):
        return True
    if settings.COOKIE_SECURE is not None:
        return settings.COOKIE_SECURE
    return not settings.DEBUG


def assert_csrf(request: Request, csrf_token: str | None = None):
    """Enforces CSRF protection on state-changing dashboard requests."""
    # Allow testing override if explicitly running without csrf in dev testing fixture
    if getattr(request.state, "skip_csrf", False):
        return
    if not validate_request_csrf(request, csrf_token):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Forbidden: Invalid or missing CSRF token. Please refresh the page and try again.",
        )


class CompatibleJinja2Templates(Jinja2Templates):
    """Ensures seamless compatibility across Starlette versions for TemplateResponse and injects CSRF token."""

    def TemplateResponse(self, *args, **kwargs):
        new_cookie = None
        if len(args) >= 2 and isinstance(args[0], str) and isinstance(args[1], dict):
            name, context = args[0], args[1]
            req = context.get("request") or kwargs.pop("request", None)
            if req and "csrf_token" not in context:
                token, new_cookie = get_csrf_token_for_request(req)
                context["csrf_token"] = token
            resp = super().TemplateResponse(request=req, name=name, context=context, **kwargs)
        elif len(args) == 1 and isinstance(args[0], str) and "context" in kwargs:
            name = args[0]
            context = kwargs.pop("context")
            req = context.get("request") or kwargs.pop("request", None)
            if req and "csrf_token" not in context:
                token, new_cookie = get_csrf_token_for_request(req)
                context["csrf_token"] = token
            resp = super().TemplateResponse(request=req, name=name, context=context, **kwargs)
        else:
            resp = super().TemplateResponse(*args, **kwargs)

        if new_cookie:
            resp.set_cookie("wh_csrf_id", new_cookie, httponly=True, samesite="lax", secure=is_cookie_secure())
        return resp


templates = CompatibleJinja2Templates(directory="app/templates")
router = APIRouter()


# IST (UTC+5:30, no DST) for human timelines. Storage, APIs, signatures and
# logs stay UTC — this filter is display-only.
from datetime import timedelta as _td
from datetime import timezone as _tz

_IST = _tz(_td(hours=5, minutes=30))


def _ist_display(value, fmt: str = "%Y-%m-%d %H:%M:%S") -> str:
    """Jinja filter: render a UTC datetime in IST. Empty string for None."""
    if value is None:
        return ""
    try:
        dt = value
        if getattr(dt, "tzinfo", None) is None:
            dt = dt.replace(tzinfo=_tz.utc)
        return dt.astimezone(_IST).strftime(fmt)
    except Exception:
        return ""


_IST_OFFSET = _td(hours=5, minutes=30)


def _utc_naive_to_ist_naive(dt):
    """Shift a UTC naive datetime to IST wall-clock (naive). Storage stays UTC."""
    if dt is None:
        return None
    try:
        naive = dt.replace(tzinfo=None) if getattr(dt, "tzinfo", None) else dt
        return naive + _IST_OFFSET
    except Exception:
        return dt


def _ist_label(dt_utc_naive, fmt: str) -> str:
    """Format a UTC naive datetime as an IST axis label (display-only)."""
    try:
        return _utc_naive_to_ist_naive(dt_utc_naive).strftime(fmt)
    except Exception:
        try:
            return dt_utc_naive.strftime(fmt)
        except Exception:
            return ""


templates.env.filters["ist"] = _ist_display


def get_user_and_project(request: Request, db: Session):
    user = get_optional_user(request, db)
    if not user:
        return None, None, None

    # Check if a specific organization was chosen via cookie
    active_org_id = request.cookies.get("wh_active_org_id")
    membership = None
    if active_org_id:
        membership = (
            db.query(OrganizationMember)
            .filter(OrganizationMember.user_id == user.id, OrganizationMember.organization_id == active_org_id)
            .first()
        )

    # If no active org chosen, check active project's organization
    active_project_id = request.cookies.get("wh_active_project_id")
    if not membership and active_project_id:
        proj = db.query(Project).filter(Project.id == active_project_id).first()
        if proj:
            membership = (
                db.query(OrganizationMember)
                .filter(
                    OrganizationMember.user_id == user.id, OrganizationMember.organization_id == proj.organization_id
                )
                .first()
            )

    # Fallback to user's first membership
    if not membership:
        membership = db.query(OrganizationMember).filter(OrganizationMember.user_id == user.id).first()

    if not membership:
        return user, None, None

    org = membership.organization

    project = None
    if active_project_id:
        project = db.query(Project).filter(Project.id == active_project_id, Project.organization_id == org.id).first()

    if not project:
        project = db.query(Project).filter(Project.organization_id == org.id).first()

    # Sidebar "Issues" badge + navbar bell must be visible on every tab, not
    # just Overview (which is the only view that builds the full `stats`
    # dict). One cheap indexed COUNT here covers all dashboard pages since
    # they all go through this helper. Failures never break the page.
    try:
        request.state.sidebar_dead_count = get_sidebar_dead_count(db, project.id if project else None)
    except Exception:
        pass
    # Same for the superadmin "Approvals" badge (pending registration count).
    try:
        if getattr(user, "is_superadmin", False):
            request.state.sidebar_pending_count = (
                db.query(func.count(User.id)).filter(User.status == "pending").scalar() or 0
            )
        else:
            request.state.sidebar_pending_count = None
    except Exception:
        pass
    # Sidebar Settings (audit trail) is manager-only; hide for plain members.
    try:
        request.state.sidebar_is_manager = bool(membership and membership.role in ("owner", "admin"))
    except Exception:
        request.state.sidebar_is_manager = True

    return user, org, project


def get_sidebar_dead_count(db: Session, project_id: str | None) -> int | None:
    """Dead-delivery count for the sidebar Issues badge and navbar bell.

    Returns None when there is no project context (badge hidden) or the
    query fails (badge hidden rather than showing a wrong 0).
    """
    if not project_id:
        return None
    try:
        return (
            db.query(func.count(Delivery.id))
            .join(Event, Delivery.event_id == Event.id)
            .filter(Event.project_id == project_id, Delivery.status == "DEAD")
            .scalar()
        ) or 0
    except Exception:
        try:
            db.rollback()
        except Exception:
            pass
        return None


def get_membership(db: Session, org_id: str, user_id: str):
    return (
        db.query(OrganizationMember)
        .filter(
            OrganizationMember.organization_id == org_id,
            OrganizationMember.user_id == user_id,
        )
        .first()
    )


def require_manager(db: Session, org, user):
    """Owners and admins may mutate endpoints, keys and replays. Members are read-only."""
    if not org or not user:
        raise HTTPException(status_code=403, detail="Not authorized")
    m = get_membership(db, org.id, user.id)
    if not m or m.role not in ("owner", "admin"):
        raise HTTPException(status_code=403, detail="Requires owner or admin role")
    return m


def require_owner(db: Session, org, user):
    if not org or not user:
        raise HTTPException(status_code=403, detail="Not authorized")
    m = get_membership(db, org.id, user.id)
    if not m or m.role != "owner":
        raise HTTPException(status_code=403, detail="Requires owner role")
    return m


def safe_back_redirect(request: Request, fallback: str = "/dashboard/endpoints") -> str:
    """Same-origin back-redirect (fixes open-redirect via Referer header).

    Allows relative paths or same-host URLs starting with '/dashboard'.
    Falls back to a safe dashboard path otherwise.
    """
    ref = (request.headers.get("referer") or "").strip()
    if not ref:
        return fallback
    try:
        from urllib.parse import urlparse as _up

        p = _up(ref)
        req_host = (request.headers.get("host") or "").lower().split(":")[0]
        ref_host = (p.hostname or "").lower()
        if p.scheme or p.netloc:
            # Reject cross-origin hostnames
            if not req_host or ref_host != req_host:
                return fallback
        path = p.path or ""
        if not path.startswith("/") or path.startswith("//"):
            return fallback
        # Only allow dashboard-internal paths
        if not path.startswith("/dashboard"):
            return fallback
        qs = f"?{p.query}" if p.query else ""
        return (path + qs)[:500]
    except Exception:
        return fallback


# ================= AUTHENTICATION ROUTES =================


@router.get("/", response_class=HTMLResponse)
def root(request: Request, db: Session = Depends(get_db)):
    user, org, prj = get_user_and_project(request, db)
    if user:
        return RedirectResponse(url="/dashboard", status_code=302)
    return templates.TemplateResponse("landing.html", {"request": request, "current_user": None})


@router.get("/auth/login", response_class=HTMLResponse)
def login_page(request: Request):
    return templates.TemplateResponse("auth/login.html", {"request": request, "current_user": None})


@router.post("/auth/login")
def login_post(
    request: Request,
    email: str = Form(...),
    password: str = Form(...),
    csrf_token: str | None = Form(None),
    db: Session = Depends(get_db),
):
    assert_csrf(request, csrf_token)

    # Login rate limiting (5 attempts per minute)
    from app.services.rate_limiter import check_login_rate_limit

    client_ip = get_client_ip(request)
    allowed, wait_sec = check_login_rate_limit(client_ip, email)
    if not allowed:
        return templates.TemplateResponse(
            "auth/login.html",
            {
                "request": request,
                "error": f"Too many login attempts. Please wait {int(wait_sec) + 1}s before trying again.",
                "current_user": None,
            },
            status_code=429,
        )

    # Constant-time enumeration defense: always run Argon2 verify,
    # even when the user does not exist (dummy hash absorbs timing).
    global _DUMMY_LOGIN_HASH
    if _DUMMY_LOGIN_HASH is None:
        try:
            from app.services.security import ph as _ph

            _DUMMY_LOGIN_HASH = _ph.hash("dummy-password-for-timing-mitigation-!23")
        except Exception:
            _DUMMY_LOGIN_HASH = "invalid"
    user = db.query(User).filter(User.email == email.strip().lower()).first()
    # Bound password length before Argon2 (CPU DoS): oversized input fails fast.
    if len(password) > 128:
        password_ok = False
    else:
        password_ok = (
            verify_password(password, user.password_hash)
            if user
            else verify_password(password, _DUMMY_LOGIN_HASH or "invalid")
        )
    if not user or not password_ok:
        return templates.TemplateResponse(
            "auth/login.html",
            {"request": request, "error": "Invalid email or password.", "current_user": None},
            status_code=400,
        )

    # Approval queue: pending/rejected users cannot sign in.
    _login_status = getattr(user, "status", "approved") or "approved"
    if _login_status == "pending":
        return templates.TemplateResponse(
            "auth/login.html",
            {"request": request, "error": "Account awaiting admin approval.", "current_user": None},
            status_code=400,
        )
    if _login_status == "rejected":
        return templates.TemplateResponse(
            "auth/login.html",
            {
                "request": request,
                "error": "Registration was not approved. Contact an administrator.",
                "current_user": None,
            },
            status_code=400,
        )

    membership = db.query(OrganizationMember).filter(OrganizationMember.user_id == user.id).first()
    org_id = membership.organization_id if membership else None

    # Session-fixation defense: invalidate any pre-login token, then issue fresh.
    from app.services.security import invalidate_session_token

    _old = request.cookies.get("wh_session")
    if _old:
        try:
            invalidate_session_token(_old)
        except Exception:
            pass
    token = create_session_token(user.id, org_id=org_id)
    response = RedirectResponse(url="/dashboard", status_code=303)
    response.set_cookie(
        key="wh_session", value=token, httponly=True, max_age=86400 * 7, samesite="lax", secure=is_cookie_secure()
    )
    return response


@router.get("/auth/register", response_class=HTMLResponse)
def register_page(request: Request):
    return templates.TemplateResponse("auth/register.html", {"request": request, "current_user": None})


@router.post("/auth/register")
def register_post(
    request: Request,
    email: str = Form(...),
    password: str = Form(...),
    project_name: str = Form("Default Project"),
    csrf_token: str | None = Form(None),
    db: Session = Depends(get_db),
):
    assert_csrf(request, csrf_token)
    # Registration throttle: 10/hour per IP (anti mass-account DoS)
    from app.services.rate_limiter import check_registration_rate_limit

    _reg_ip = get_client_ip(request)
    _reg_allowed, _reg_wait = check_registration_rate_limit(_reg_ip)

    if not settings.ALLOW_OPEN_REGISTRATION:
        # Approval queue: accept signups as PENDING (no org, no session) when
        # enabled. Safe for production — pending users get zero access.
        if not getattr(settings, "ALLOW_PENDING_REGISTRATION", False):
            raise HTTPException(status_code=403, detail="Open registration is disabled. Contact an administrator.")

    if not _reg_allowed:
        return templates.TemplateResponse(
            "auth/register.html",
            {
                "request": request,
                "error": f"Too many registrations. Try again in {int(_reg_wait) + 1}s.",
                "current_user": None,
            },
            status_code=429,
        )
    email = email.strip().lower()
    if not _EMAIL_REGEX.match(email):
        return templates.TemplateResponse(
            "auth/register.html",
            {"request": request, "error": "Invalid email address format.", "current_user": None},
            status_code=400,
        )
    existing = db.query(User).filter(User.email == email).first()
    if existing:
        _st = getattr(existing, "status", "approved") or "approved"
        if _st == "pending":
            return templates.TemplateResponse(
                "auth/register.html",
                {
                    "request": request,
                    "error": "This email is awaiting admin approval. You will be able to sign in once approved.",
                    "current_user": None,
                },
                status_code=400,
            )
        if _st != "rejected":
            return templates.TemplateResponse(
                "auth/register.html",
                {"request": request, "error": "Email is already registered. Please sign in.", "current_user": None},
                status_code=400,
            )
        # Rejected users may re-apply: reset to pending with the new password.
        existing.password_hash = hash_password(password)
        existing.status = "pending"
        try:
            db.commit()
        except Exception:
            db.rollback()
            raise
        return templates.TemplateResponse(
            "auth/register.html",
            {
                "request": request,
                "success": "Re-application received. An admin will review your account.",
                "current_user": None,
            },
        )

    if len(password) < 8 or len(password) > 128:
        return templates.TemplateResponse(
            "auth/register.html",
            {"request": request, "error": "Password must be 8..128 characters long.", "current_user": None},
            status_code=400,
        )
    # Basic complexity: require 3 of 4 classes (upper/lower/digit/symbol)
    import re as _re

    _classes = sum(
        [
            bool(_re.search(r"[A-Z]", password)),
            bool(_re.search(r"[a-z]", password)),
            bool(_re.search(r"[0-9]", password)),
            bool(_re.search(r"[^A-Za-z0-9]", password)),
        ]
    )
    if _classes < 3:
        return templates.TemplateResponse(
            "auth/register.html",
            {
                "request": request,
                "error": "Password must include 3 of: uppercase, lowercase, digit, symbol.",
                "current_user": None,
            },
            status_code=400,
        )
    # Validate project name length to avoid DB errors
    _proj_name = (project_name or "").strip() or "Default Project"
    if len(_proj_name) > 100:
        return templates.TemplateResponse(
            "auth/register.html",
            {"request": request, "error": "Project name must be ≤100 characters.", "current_user": None},
            status_code=400,
        )

    # Approval-queue mode (open registration off): create a PENDING user with
    # no organization and no session. Superadmin approves/rejects later.
    if not settings.ALLOW_OPEN_REGISTRATION:
        try:
            user = User(email=email, password_hash=hash_password(password), status="pending")
            # is_superadmin defaults False; never settable via signup.
            user.is_superadmin = False
            db.add(user)
            db.commit()
        except Exception as e:
            db.rollback()
            from sqlalchemy.exc import IntegrityError as _IE

            if isinstance(e, _IE) or "UNIQUE" in str(type(e).__name__).upper() or "unique" in str(e).lower():
                return templates.TemplateResponse(
                    "auth/register.html",
                    {
                        "request": request,
                        "error": "This email is awaiting admin approval. You will be able to sign in once approved.",
                        "current_user": None,
                    },
                    status_code=400,
                )
            raise
        return templates.TemplateResponse(
            "auth/register.html",
            {
                "request": request,
                "success": "Application received. An admin will review your account before you can sign in.",
                "current_user": None,
            },
        )

    # Atomically create user, organization, membership, and initial project
    try:
        user = User(email=email, password_hash=hash_password(password), status="approved")
        db.add(user)
        db.flush()

        org_name = email.split("@")[0].capitalize() + "'s Org"
        org = Organization(name=org_name)
        db.add(org)
        db.flush()

        member = OrganizationMember(organization_id=org.id, user_id=user.id, role="owner")
        db.add(member)

        project = Project(organization_id=org.id, name=_proj_name)
        db.add(project)

        db.commit()
    except Exception as e:
        db.rollback()
        from sqlalchemy.exc import IntegrityError as _IE

        if isinstance(e, _IE) or "UNIQUE" in str(type(e).__name__).upper() or "unique" in str(e).lower():
            return templates.TemplateResponse(
                "auth/register.html",
                {"request": request, "error": "Email is already registered. Please sign in.", "current_user": None},
                status_code=400,
            )
        raise

    token = create_session_token(user.id, org_id=org.id, project_id=project.id)
    response = RedirectResponse(url="/dashboard", status_code=303)
    response.set_cookie(
        "wh_session", token, httponly=True, max_age=86400 * 7, samesite="lax", secure=is_cookie_secure()
    )
    # Project selector is HttpOnly: JS never needs to read it; server validates org scope.
    response.set_cookie(
        "wh_active_project_id", project.id, httponly=True, max_age=86400 * 30, samesite="lax", secure=is_cookie_secure()
    )
    return response


@router.post("/auth/logout")
def logout(request: Request, csrf_token: str | None = Form(None)):
    assert_csrf(request, csrf_token)
    from app.services.security import invalidate_session_token

    token = request.cookies.get("wh_session")
    if token:
        invalidate_session_token(token)
    response = RedirectResponse(url="/", status_code=303)
    response.delete_cookie("wh_session")
    response.delete_cookie("wh_active_project_id")
    response.delete_cookie("wh_active_org_id")
    response.delete_cookie("wh_csrf_id")
    return response


# ================= FORGOT PASSWORD (OTP via SMTP) =================


def _forgot_generic_success(request, email: str, resend: bool = False):
    """Generic success response to prevent email enumeration."""
    msg = (
        "If an account exists for this email, a verification code has been sent. Can't find it? Check your spam folder."
    )
    if resend:
        msg = (
            "If an account exists for this email, a new verification code has been sent. "
            "Can't find it? Check your spam folder."
        )
    return templates.TemplateResponse(
        "auth/verify_otp.html",
        {
            "request": request,
            "current_user": None,
            "email": email,
            "message": msg,
            "message_type": "success",
        },
    )


@router.get("/auth/forgot-password", response_class=HTMLResponse)
def forgot_password_page(request: Request):
    return templates.TemplateResponse("auth/forgot_password.html", {"request": request, "current_user": None})


@router.post("/auth/forgot-password")
def forgot_password_post(
    request: Request,
    email: str = Form(...),
    csrf_token: str | None = Form(None),
    db: Session = Depends(get_db),
):
    assert_csrf(request, csrf_token)
    from app.services.rate_limiter import check_password_reset_request_rate_limit

    clean_email = (email or "").strip().lower()[:255]
    client_ip = get_client_ip(request)
    allowed, wait_sec = check_password_reset_request_rate_limit(client_ip, clean_email)
    if not allowed:
        return templates.TemplateResponse(
            "auth/forgot_password.html",
            {
                "request": request,
                "current_user": None,
                "error": f"Too many reset requests. Please wait {int(wait_sec) + 1}s before trying again.",
                "email": clean_email,
            },
            status_code=429,
        )
    if not _EMAIL_REGEX.match(clean_email):
        # Keep response generic-shaped but flag format error (no account leak).
        return templates.TemplateResponse(
            "auth/forgot_password.html",
            {
                "request": request,
                "current_user": None,
                "error": "Please enter a valid email address.",
                "email": clean_email,
            },
            status_code=400,
        )

    user = db.query(User).filter(User.email == clean_email).first()
    if not user:
        # Generic response to prevent user enumeration (same in dev and prod).
        return _forgot_generic_success(request, clean_email)

    from app.services.email import send_otp_email
    from app.services.password_reset import create_otp_for_user

    try:
        _row, plain_otp = create_otp_for_user(db, user.id, user.email)
    except Exception:
        return templates.TemplateResponse(
            "auth/forgot_password.html",
            {
                "request": request,
                "current_user": None,
                "error": "Could not start reset. Please try again.",
                "email": clean_email,
            },
            status_code=500,
        )

    if not send_otp_email(user.email, plain_otp):
        # Never distinguish SMTP failures (would let attackers enumerate
        # registered emails via 500 vs 200). Log internally, show generic success.
        import logging as _logging

        _logging.getLogger("webhook.auth").warning(
            "password-reset email delivery failed for known user (generic response shown)"
        )
    return _forgot_generic_success(request, clean_email)


@router.get("/auth/forgot-password/verify", response_class=HTMLResponse)
def forgot_password_verify_page(request: Request, email: str | None = None):
    return templates.TemplateResponse(
        "auth/verify_otp.html", {"request": request, "current_user": None, "email": (email or "").strip()}
    )


@router.post("/auth/forgot-password/verify")
def forgot_password_verify_post(
    request: Request,
    email: str = Form(...),
    otp: str = Form(...),
    csrf_token: str | None = Form(None),
    db: Session = Depends(get_db),
):
    assert_csrf(request, csrf_token)
    from app.services.rate_limiter import check_password_reset_verify_rate_limit

    clean_email = (email or "").strip().lower()[:255]
    clean_otp = "".join(ch for ch in (otp or "") if ch.isdigit())[:10]
    client_ip = get_client_ip(request)
    allowed, wait_sec = check_password_reset_verify_rate_limit(client_ip, clean_email)
    if not allowed:
        return templates.TemplateResponse(
            "auth/verify_otp.html",
            {
                "request": request,
                "current_user": None,
                "email": clean_email,
                "error": f"Too many verification attempts. Please wait {int(wait_sec) + 1}s.",
            },
            status_code=429,
        )

    user = db.query(User).filter(User.email == clean_email).first()
    if not user:
        return templates.TemplateResponse(
            "auth/verify_otp.html",
            {
                "request": request,
                "current_user": None,
                "email": clean_email,
                "error": "Invalid or expired code. Please request a new one.",
            },
            status_code=400,
        )

    from app.services.password_reset import consume_otp, create_reset_token, verify_otp

    ok, reason, row = verify_otp(db, user.id, clean_otp)
    if not ok:
        messages = {
            "expired": "This code has expired. Please request a new one.",
            "locked": "Too many wrong attempts. Please request a new code.",
            "missing": "Invalid or expired code. Please request a new one.",
        }
        return templates.TemplateResponse(
            "auth/verify_otp.html",
            {
                "request": request,
                "current_user": None,
                "email": clean_email,
                "error": messages.get(reason, "Invalid or expired code."),
            },
            status_code=400,
        )
    # Success: single-use the OTP. The signed bearer stays server-side;
    # the browser receives only an opaque id in a short-lived cookie, and
    # the redirect URL carries no credential for logs or history to keep.
    consume_otp(db, row)
    from app.services.password_reset import issue_reset_session

    token = create_reset_token(user.id, row.id)
    session_id = issue_reset_session(token)
    response = RedirectResponse(url="/auth/reset-password", status_code=303)
    response.set_cookie(
        "wh_reset_session",
        session_id,
        httponly=True,
        max_age=int(settings.PASSWORD_RESET_TOKEN_EXPIRE_MINUTES or 15) * 60,
        samesite="strict",
        secure=is_cookie_secure(),
        path="/auth/reset-password",
    )
    return response


@router.post("/auth/forgot-password/resend")
def forgot_password_resend_post(
    request: Request,
    email: str = Form(...),
    csrf_token: str | None = Form(None),
    db: Session = Depends(get_db),
):
    """Resend a fresh OTP (same throttling as request)."""
    assert_csrf(request, csrf_token)
    from app.services.rate_limiter import check_password_reset_request_rate_limit

    clean_email = (email or "").strip().lower()[:255]
    client_ip = get_client_ip(request)
    allowed, wait_sec = check_password_reset_request_rate_limit(client_ip, clean_email)
    if not allowed:
        return templates.TemplateResponse(
            "auth/verify_otp.html",
            {
                "request": request,
                "current_user": None,
                "email": clean_email,
                "error": f"Too many reset requests. Please wait {int(wait_sec) + 1}s before trying again.",
            },
            status_code=429,
        )
    if not _EMAIL_REGEX.match(clean_email):
        return templates.TemplateResponse(
            "auth/verify_otp.html",
            {"request": request, "current_user": None, "email": clean_email, "error": "Invalid or expired code."},
            status_code=400,
        )
    user = db.query(User).filter(User.email == clean_email).first()
    if not user:
        # Generic response to prevent user enumeration (same in dev and prod).
        return _forgot_generic_success(request, clean_email, resend=True)
    from app.services.email import send_otp_email
    from app.services.password_reset import create_otp_for_user

    try:
        _row, plain_otp = create_otp_for_user(db, user.id, user.email)
    except Exception:
        return templates.TemplateResponse(
            "auth/verify_otp.html",
            {"request": request, "current_user": None, "email": clean_email, "error": "Could not resend. Try again."},
            status_code=500,
        )
    if not send_otp_email(user.email, plain_otp):
        import logging as _logging

        _logging.getLogger("webhook.auth").warning(
            "password-reset resend delivery failed for known user (generic response shown)"
        )
    return _forgot_generic_success(request, clean_email, resend=True)


def _reset_context(request: Request) -> tuple[dict | None, str]:
    """Resolves the reset cookie to its verified token payload.

    Returns (payload, session_id). payload is None when the cookie is
    missing, unknown, or the signed bearer inside it has expired.
    """
    from app.services.password_reset import lookup_reset_session, verify_reset_token

    session_id = request.cookies.get("wh_reset_session") or ""
    token = lookup_reset_session(session_id)
    data = verify_reset_token(token or "")
    if not data:
        return None, session_id
    return data, session_id


def _reject_reset(request: Request, message: str, status_code: int = 400):
    response = templates.TemplateResponse(
        "auth/forgot_password.html",
        {"request": request, "current_user": None, "error": message},
        status_code=status_code,
    )
    response.delete_cookie("wh_reset_session", path="/auth/reset-password")
    return response


@router.get("/auth/reset-password", response_class=HTMLResponse)
def reset_password_page(request: Request, db: Session = Depends(get_db)):
    data, _session_id = _reset_context(request)
    if not data:
        return _reject_reset(request, "This reset link is invalid or has expired. Please request a new code.")
    # The link is only usable after OTP verification and before any newer OTP.
    from app.models.password_reset import PasswordResetOTP

    otp_row = db.query(PasswordResetOTP).filter(PasswordResetOTP.id == data["otp_id"]).first()
    if not otp_row or otp_row.user_id != data["user_id"] or not otp_row.used:
        return _reject_reset(request, "This reset link is invalid or has expired. Please request a new code.")
    latest = (
        db.query(PasswordResetOTP)
        .filter(PasswordResetOTP.user_id == data["user_id"])
        .order_by(PasswordResetOTP.created_at.desc())
        .first()
    )
    if not latest or latest.id != otp_row.id:
        return _reject_reset(request, "A newer verification code was requested. Please use the latest link.")
    return templates.TemplateResponse("auth/reset_password.html", {"request": request, "current_user": None})


@router.post("/auth/reset-password")
def reset_password_post(
    request: Request,
    password: str = Form(...),
    confirm_password: str = Form(...),
    csrf_token: str | None = Form(None),
    db: Session = Depends(get_db),
):
    assert_csrf(request, csrf_token)
    from app.services.password_reset import consume_reset_session, validate_new_password

    data, session_id = _reset_context(request)
    if not data:
        return _reject_reset(request, "This reset link is invalid or has expired. Please request a new code.")
    if password != confirm_password:
        return templates.TemplateResponse(
            "auth/reset_password.html",
            {"request": request, "current_user": None, "error": "Passwords do not match."},
            status_code=400,
        )
    pw_error = validate_new_password(password)
    if pw_error:
        return templates.TemplateResponse(
            "auth/reset_password.html",
            {"request": request, "current_user": None, "error": pw_error},
            status_code=400,
        )

    user = db.query(User).filter(User.id == data["user_id"]).first()
    if not user:
        return _reject_reset(request, "Account no longer exists.")
    # Ensure the OTP backing this token was actually consumed (verified).
    # Also requires it to be the latest OTP for the user so that requesting
    # a newer code invalidates older reset links.
    from app.models.password_reset import PasswordResetOTP

    otp_row = db.query(PasswordResetOTP).filter(PasswordResetOTP.id == data["otp_id"]).first()
    if not otp_row or otp_row.user_id != user.id or not otp_row.used:
        return _reject_reset(request, "This reset link is invalid or has expired. Please request a new code.")
    latest = (
        db.query(PasswordResetOTP)
        .filter(PasswordResetOTP.user_id == user.id)
        .order_by(PasswordResetOTP.created_at.desc())
        .first()
    )
    if not latest or latest.id != otp_row.id:
        return _reject_reset(request, "A newer verification code was requested. Please use the latest link.")

    user.password_hash = hash_password(password)
    user.password_changed_at = utc_now()

    # Invalidate all existing sessions across all browsers/devices for this user
    from app.services.security import invalidate_all_user_sessions

    invalidate_all_user_sessions(user.id)

    # Single-use reset link: remove all OTP rows for this user so the
    # signed token cannot be replayed after a successful reset.
    try:
        db.query(PasswordResetOTP).filter(PasswordResetOTP.user_id == user.id).delete(synchronize_session=False)
    except Exception:
        pass
    db.commit()

    # Best-effort audit on the user's first org (non-blocking for password reset).
    try:
        membership = db.query(OrganizationMember).filter(OrganizationMember.user_id == user.id).first()
        if membership:
            from app.services.audit import log_audit_event

            log_audit_event(
                db=db,
                organization_id=membership.organization_id,
                user_id=user.id,
                action="auth.password_reset",
                resource_type="user",
                resource_id=user.id,
                ip_address=get_client_ip(request),
                details={"email": user.email},
            )
    except Exception:
        pass

    response = templates.TemplateResponse(
        "auth/login.html",
        {
            "request": request,
            "current_user": None,
            "message": "Password reset successful. Please sign in with your new password.",
        },
    )
    # The signed bearer is forgotten with the session, so the cookie cannot
    # be replayed even if the browser still holds it.
    consume_reset_session(session_id)
    response.delete_cookie("wh_session")
    response.delete_cookie("wh_reset_session", path="/auth/reset-password")
    return response


# ================= DASHBOARD CORE =================


@router.get("/dashboard", response_class=HTMLResponse)
def dashboard_overview(request: Request, db: Session = Depends(get_db)):
    user, org, project = get_user_and_project(request, db)
    if not user:
        return RedirectResponse(url="/auth/login", status_code=302)
    if not project:
        return RedirectResponse(url="/dashboard/projects", status_code=302)

    # Gather metrics
    total_events = db.query(func.count(Event.id)).filter(Event.project_id == project.id).scalar() or 0

    delivery_base = db.query(Delivery).join(Event, Delivery.event_id == Event.id).filter(Event.project_id == project.id)
    succeeded_deliveries = delivery_base.filter(Delivery.status == "SUCCEEDED").count()
    pending_deliveries = delivery_base.filter(Delivery.status.in_(["PENDING", "IN_FLIGHT", "RETRY_SCHEDULED"])).count()

    now = utc_now()
    deliveries_due = delivery_base.filter(
        Delivery.status.in_(["PENDING", "RETRY_SCHEDULED"]), Delivery.next_attempt_at <= now
    ).count()

    dead_deliveries = delivery_base.filter(Delivery.status == "DEAD").count()
    total_deliveries = succeeded_deliveries + pending_deliveries + dead_deliveries

    # Attempt stats
    attempts_query = (
        db.query(DeliveryAttempt)
        .join(Delivery, DeliveryAttempt.delivery_id == Delivery.id)
        .join(Event, Delivery.event_id == Event.id)
        .filter(Event.project_id == project.id)
    )
    total_attempts = attempts_query.count()
    successful_attempts = attempts_query.filter(DeliveryAttempt.outcome == "SUCCESS").count()
    avg_latency = attempts_query.with_entities(func.avg(DeliveryAttempt.duration_ms)).scalar() or 0

    delivery_success_rate = round((succeeded_deliveries / total_deliveries * 100), 1) if total_deliveries > 0 else 0.0
    attempt_success_rate = round((successful_attempts / total_attempts * 100), 1) if total_attempts > 0 else 0.0

    # End-to-end time from acceptance to successful delivery
    completed_records = (
        db.query(Delivery.completed_at, Event.created_at)
        .join(Event, Delivery.event_id == Event.id)
        .filter(Event.project_id == project.id, Delivery.status == "SUCCEEDED", Delivery.completed_at.is_not(None))
        .limit(100)
        .all()
    )
    e2e_durations = []
    for comp_at, created_at in completed_records:
        if comp_at and created_at:
            diff_ms = (comp_at - created_at).total_seconds() * 1000.0
            if diff_ms >= 0:
                e2e_durations.append(diff_ms)
    avg_e2e_duration_ms = round(sum(e2e_durations) / len(e2e_durations), 1) if e2e_durations else 0.0

    recent_events = (
        db.query(Event).filter(Event.project_id == project.id).order_by(Event.created_at.desc()).limit(10).all()
    )

    recent_deliveries = (
        delivery_base.options(joinedload(Delivery.event), joinedload(Delivery.endpoint))
        .order_by(Delivery.created_at.desc())
        .limit(15)
        .all()
    )

    stats = {
        "total_events": total_events,
        "total_deliveries": total_deliveries,
        "succeeded_deliveries": succeeded_deliveries,
        "pending_deliveries": pending_deliveries,
        "deliveries_due": deliveries_due,
        "dead_deliveries": dead_deliveries,
        "total_attempts": total_attempts,
        "delivery_success_rate": delivery_success_rate,
        "attempt_success_rate": attempt_success_rate,
        "avg_latency_ms": round(avg_latency, 1),
        "avg_e2e_duration_ms": avg_e2e_duration_ms,
    }

    # 24h activity series (default landing view) — bounded to last 1 day only.
    # Labels are IST wall-clock (display-only); storage/bucketing stays UTC.
    from datetime import timedelta as _td

    def _to_naive_overview(dt):
        if dt is None:
            return None
        return dt.replace(tzinfo=None) if getattr(dt, "tzinfo", None) else dt

    _now_utc = _to_naive_overview(utc_now())
    _labels: list[str] = []
    _events_per_day: list[int] = []
    _succeeded_per_day: list[int] = []
    _dead_per_day: list[int] = []
    _day_ago = utc_now() - _td(days=1)
    try:
        _all_events = (
            db.query(Event.created_at)
            .filter(Event.project_id == project.id, Event.created_at >= _day_ago)
            .limit(5000)
            .all()
        )
    except Exception:
        _all_events = []
    try:
        _all_dlv = (
            db.query(Delivery.created_at, Delivery.status)
            .join(Event, Delivery.event_id == Event.id)
            .filter(Event.project_id == project.id, Delivery.created_at >= _day_ago)
            .limit(5000)
            .all()
        )
    except Exception:
        _all_dlv = []
    try:
        _ev_utc = [_to_naive_overview(c) for (c,) in _all_events if c is not None]
    except Exception:
        _ev_utc = []
    try:
        _dlv_utc = [(_to_naive_overview(c), s) for c, s in _all_dlv if c is not None]
    except Exception:
        _dlv_utc = []
    _retrying_per_day: list[int] = []
    for _i in range(5, -1, -1):
        _t_start = _now_utc - _td(hours=(_i + 1) * 4)
        _t_end = _now_utc - _td(hours=_i * 4)
        _labels.append(_ist_label(_t_end, "%H:00"))
        _e = sum(1 for c in _ev_utc if c is not None and _t_start <= c <= _t_end)
        _events_per_day.append(_e)
        _s = sum(1 for c, s in _dlv_utc if c is not None and _t_start <= c <= _t_end and s == "SUCCEEDED")
        _r = sum(
            1
            for c, s in _dlv_utc
            if c is not None and _t_start <= c <= _t_end and s in ("RETRY_SCHEDULED", "PENDING", "IN_FLIGHT")
        )
        _d = sum(1 for c, s in _dlv_utc if c is not None and _t_start <= c <= _t_end and s == "DEAD")
        _succeeded_per_day.append(_s)
        _retrying_per_day.append(_r)
        _dead_per_day.append(_d)
    chart = {
        "labels": _labels,
        "events": _events_per_day,
        "succeeded": _succeeded_per_day,
        "retrying": _retrying_per_day,
        "dead": _dead_per_day,
        "range": "24h",
    }

    return templates.TemplateResponse(
        "dashboard/index.html",
        {
            "request": request,
            "current_user": user,
            "current_project": project,
            "stats": stats,
            "recent_events": recent_events,
            "deliveries": recent_deliveries,
            "chart": chart,
        },
    )


@router.get("/dashboard/deliveries/table", response_class=HTMLResponse)
def deliveries_table_fragment(
    request: Request,
    status: str | None = None,
    q: str | None = None,
    page: int = 1,
    per_page: int = 15,
    event_id: str | None = None,
    db: Session = Depends(get_db),
):
    """HTMX partial fragment endpoint with search and status filtering."""
    from app.services.security import get_csrf_token_for_request

    user, org, project = get_user_and_project(request, db)
    if not user or not project:
        return HTMLResponse("<p class='text-xs text-rose-500 p-4'>Not authorized</p>", status_code=401)

    # Clamp client-controlled pagination (deep-offset + huge-limit DoS).
    try:
        page = min(max(1, int(page)), 1000)
    except Exception:
        page = 1
    try:
        per_page = min(max(1, int(per_page)), 50)
    except Exception:
        per_page = 15

    query = db.query(Delivery).join(Event, Delivery.event_id == Event.id).filter(Event.project_id == project.id)
    if event_id and event_id.strip():
        # Scoped to one event (event-detail live view). Still project-scoped
        # via the join above; length-bounded to avoid pathological scans.
        _eid = event_id.strip()[:64]
        query = query.filter(Delivery.event_id == _eid)
    if status and status.strip():
        # Allowlist statuses to avoid arbitrary filter scans.
        _st = status.strip().upper()
        if _st in ("PENDING", "IN_FLIGHT", "RETRY_SCHEDULED", "SUCCEEDED", "DEAD"):
            query = query.filter(Delivery.status == _st)
    if q and q.strip():
        # Escape LIKE wildcards (%, _, \) to prevent wildcard-injection scans.
        _raw = q.strip()[:100]
        _esc = _raw.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        search_term = f"%{_esc}%"
        query = query.filter(
            or_(
                Delivery.id.ilike(search_term, escape="\\"),
                Event.id.ilike(search_term, escape="\\"),
                Event.event_type.ilike(search_term, escape="\\"),
                Event.idempotency_key.ilike(search_term, escape="\\"),
                Delivery.target_url_snapshot.ilike(search_term, escape="\\"),
            )
        )

    page = min(max(1, page), 1000)
    total_count = query.count()
    total_pages = max(1, (total_count + per_page - 1) // per_page)
    deliveries = query.order_by(Delivery.created_at.desc()).offset((page - 1) * per_page).limit(per_page).all()

    csrf_token, _ = get_csrf_token_for_request(request)
    return templates.TemplateResponse(
        "deliveries/_table.html",
        {
            "request": request,
            "deliveries": deliveries,
            "csrf_token": csrf_token,
            "page": page,
            "per_page": per_page,
            "total_pages": total_pages,
            "total_count": total_count,
            "status_filter": status,
            "current_user": user,
            "current_project": project,
        },
    )


@router.get("/dashboard/deliveries/{delivery_id}/drawer", response_class=HTMLResponse)
def delivery_drawer_fragment(delivery_id: str, request: Request, db: Session = Depends(get_db)):
    """HTMX slide-over drawer log inspector for Svix/Stripe debugging experience."""
    from app.services.security import get_csrf_token_for_request

    user, org, project = get_user_and_project(request, db)
    if not user or not project:
        return HTMLResponse("<div class='p-6 text-sm text-rose-500'>Unauthorized</div>", status_code=401)

    delivery = (
        db.query(Delivery)
        .join(Event, Delivery.event_id == Event.id)
        .filter(Delivery.id == delivery_id, Event.project_id == project.id)
        .first()
    )
    if not delivery:
        return HTMLResponse("<div class='p-6 text-sm text-slate-500'>Delivery not found</div>", status_code=404)

    formatted_payload = delivery.event.payload_json
    try:
        parsed = json.loads(delivery.event.payload_json)
        formatted_payload = json.dumps(parsed, indent=2)
    except Exception:
        pass

    csrf_token, _ = get_csrf_token_for_request(request)
    return templates.TemplateResponse(
        "components/drawer.html",
        {
            "request": request,
            "delivery": delivery,
            "formatted_payload": formatted_payload,
            "csrf_token": csrf_token,
            "current_user": user,
            "current_project": project,
        },
    )


@router.get("/dashboard/metrics/chart", response_class=HTMLResponse)
def dashboard_metrics_chart_fragment(
    request: Request, time_range: str = Query(default="24h", alias="range"), db: Session = Depends(get_db)
):
    """HTMX partial endpoint to dynamically switch chart time ranges (1h, 24h, 7d, 30d)."""
    user, org, project = get_user_and_project(request, db)
    if not user or not project:
        return HTMLResponse("", status_code=401)

    from datetime import timedelta as _td

    def _to_naive(dt):
        if dt is None:
            return None
        return dt.replace(tzinfo=None) if getattr(dt, "tzinfo", None) else dt

    now = _to_naive(utc_now())
    labels = []
    events_per_bucket = []
    succeeded_per_bucket = []
    dead_per_bucket = []

    # Bounded: only fetch window needed for requested range (was full-table scan).
    _range_days = {"1h": 1, "24h": 1, "7d": 7, "30d": 30}.get(time_range, 1)
    _window_start = utc_now() - _td(days=_range_days)
    try:
        raw_events = (
            db.query(Event.created_at)
            .filter(Event.project_id == project.id, Event.created_at >= _window_start)
            .limit(5000)
            .all()
        )
        raw_dlv = (
            db.query(Delivery.created_at, Delivery.status)
            .join(Event, Delivery.event_id == Event.id)
            .filter(Event.project_id == project.id, Delivery.created_at >= _window_start)
            .limit(5000)
            .all()
        )
        all_events = [_to_naive(c) for (c,) in raw_events if c is not None]
        all_dlv = [(_to_naive(c), s) for c, s in raw_dlv if c is not None]
    except Exception:
        all_events = []
        all_dlv = []

    retrying_per_bucket = []

    # IST wall-clock for display + daily grouping (storage stays UTC).
    now_ist = _utc_naive_to_ist_naive(now)

    if time_range == "1h":
        for i in range(5, -1, -1):
            t_start = now - _td(minutes=(i + 1) * 10)
            t_end = now - _td(minutes=i * 10)
            labels.append(_ist_label(t_end, "%H:%M"))
            events_per_bucket.append(sum(1 for c in all_events if t_start <= c <= t_end))
            succeeded_per_bucket.append(sum(1 for c, s in all_dlv if t_start <= c <= t_end and s == "SUCCEEDED"))
            retrying_per_bucket.append(
                sum(1 for c, s in all_dlv if t_start <= c <= t_end and s in ("RETRY_SCHEDULED", "PENDING", "IN_FLIGHT"))
            )
            dead_per_bucket.append(sum(1 for c, s in all_dlv if t_start <= c <= t_end and s == "DEAD"))
    elif time_range == "7d":
        for i in range(6, -1, -1):
            day = (now_ist - _td(days=i)).date()
            labels.append(day.strftime("%m-%d"))
            events_per_bucket.append(
                sum(1 for c in all_events if _utc_naive_to_ist_naive(c).date() == day)
            )
            succeeded_per_bucket.append(
                sum(1 for c, s in all_dlv if _utc_naive_to_ist_naive(c).date() == day and s == "SUCCEEDED")
            )
            retrying_per_bucket.append(
                sum(
                    1
                    for c, s in all_dlv
                    if _utc_naive_to_ist_naive(c).date() == day
                    and s in ("RETRY_SCHEDULED", "PENDING", "IN_FLIGHT")
                )
            )
            dead_per_bucket.append(
                sum(1 for c, s in all_dlv if _utc_naive_to_ist_naive(c).date() == day and s == "DEAD")
            )
    elif time_range == "30d":
        for i in range(29, -1, -5):
            day = (now_ist - _td(days=i)).date()
            labels.append(day.strftime("%m-%d"))
            _win_start = day - _td(days=4)
            events_per_bucket.append(
                sum(
                    1
                    for c in all_events
                    if _win_start <= _utc_naive_to_ist_naive(c).date() <= day
                )
            )
            succeeded_per_bucket.append(
                sum(
                    1
                    for c, s in all_dlv
                    if _win_start <= _utc_naive_to_ist_naive(c).date() <= day and s == "SUCCEEDED"
                )
            )
            retrying_per_bucket.append(
                sum(
                    1
                    for c, s in all_dlv
                    if _win_start <= _utc_naive_to_ist_naive(c).date() <= day
                    and s in ("RETRY_SCHEDULED", "PENDING", "IN_FLIGHT")
                )
            )
            dead_per_bucket.append(
                sum(
                    1
                    for c, s in all_dlv
                    if _win_start <= _utc_naive_to_ist_naive(c).date() <= day and s == "DEAD"
                )
            )
    else:  # 24h default
        for i in range(5, -1, -1):
            t_start = now - _td(hours=(i + 1) * 4)
            t_end = now - _td(hours=i * 4)
            labels.append(_ist_label(t_end, "%H:00"))
            events_per_bucket.append(sum(1 for c in all_events if t_start <= c <= t_end))
            succeeded_per_bucket.append(sum(1 for c, s in all_dlv if t_start <= c <= t_end and s == "SUCCEEDED"))
            retrying_per_bucket.append(
                sum(1 for c, s in all_dlv if t_start <= c <= t_end and s in ("RETRY_SCHEDULED", "PENDING", "IN_FLIGHT"))
            )
            dead_per_bucket.append(sum(1 for c, s in all_dlv if t_start <= c <= t_end and s == "DEAD"))

    # Compute overall stats
    delivery_base = db.query(Delivery).join(Event, Delivery.event_id == Event.id).filter(Event.project_id == project.id)
    succeeded_del = delivery_base.filter(Delivery.status == "SUCCEEDED").count()
    pending_del = delivery_base.filter(Delivery.status.in_(["PENDING", "IN_FLIGHT", "RETRY_SCHEDULED"])).count()
    dead_del = delivery_base.filter(Delivery.status == "DEAD").count()
    total_del = succeeded_del + pending_del + dead_del
    delivery_success_rate = round((succeeded_del / total_del * 100), 1) if total_del > 0 else 0.0

    attempts_query = (
        db.query(DeliveryAttempt)
        .join(Delivery, DeliveryAttempt.delivery_id == Delivery.id)
        .join(Event, Delivery.event_id == Event.id)
        .filter(Event.project_id == project.id)
    )
    avg_latency = attempts_query.with_entities(func.avg(DeliveryAttempt.duration_ms)).scalar() or 0

    stats = {
        "succeeded_deliveries": succeeded_del,
        "pending_deliveries": pending_del,
        "dead_deliveries": dead_del,
        "total_deliveries": total_del,
        "delivery_success_rate": delivery_success_rate,
        "avg_latency_ms": round(avg_latency, 1),
        "avg_e2e_duration_ms": 0.0,
    }

    chart = {
        "labels": labels,
        "events": events_per_bucket,
        "succeeded": succeeded_per_bucket,
        "retrying": retrying_per_bucket,
        "dead": dead_per_bucket,
        "range": time_range,
    }

    return templates.TemplateResponse(
        "dashboard/_charts.html",
        {
            "request": request,
            "chart": chart,
            "stats": stats,
            "current_user": user,
            "current_project": project,
        },
    )


# ================= PROJECTS =================


@router.get("/dashboard/projects", response_class=HTMLResponse)
def list_projects(request: Request, db: Session = Depends(get_db)):
    user, org, project = get_user_and_project(request, db)
    if not user:
        return RedirectResponse(url="/auth/login", status_code=302)
    if not org:
        return templates.TemplateResponse(
            "projects/index.html",
            {
                "request": request,
                "current_user": user,
                "current_project": None,
                "current_org": None,
                "projects": [],
                "orgs": [],
            },
        )

    projects = db.query(Project).filter(Project.organization_id == org.id).order_by(Project.created_at.desc()).all()
    # All orgs this login belongs to (invited members hold several) so they
    # can switch workspaces — project switching alone stays within one org.
    memberships = db.query(OrganizationMember).filter(OrganizationMember.user_id == user.id).all()
    org_ids = [m.organization_id for m in memberships]
    orgs = db.query(Organization).filter(Organization.id.in_(org_ids)).all() if org_ids else []
    return templates.TemplateResponse(
        "projects/index.html",
        {
            "request": request,
            "current_user": user,
            "current_project": project,
            "current_org": org,
            "projects": projects,
            "orgs": orgs,
        },
    )


@router.post("/dashboard/projects")
def create_project(
    request: Request, name: str = Form(...), csrf_token: str | None = Form(None), db: Session = Depends(get_db)
):
    assert_csrf(request, csrf_token)
    user, org, _ = get_user_and_project(request, db)
    if not user:
        return RedirectResponse(url="/auth/login", status_code=302)
    if not org:
        raise HTTPException(status_code=400, detail="No active organization")
    require_manager(db, org, user)

    clean_name = (name or "").strip()
    if not (1 <= len(clean_name) <= 100):
        raise HTTPException(status_code=400, detail="Project name must be between 1 and 100 characters")

    new_project = Project(organization_id=org.id, name=clean_name)
    db.add(new_project)
    db.commit()

    # Rotate session so embedded project_id stays in sync with the selector cookie.
    from app.services.security import invalidate_session_token as _inv

    _old = request.cookies.get("wh_session")
    if _old:
        try:
            _inv(_old)
        except Exception:
            pass
    _new_token = create_session_token(user.id, org_id=org.id, project_id=new_project.id)
    response = RedirectResponse(url="/dashboard/projects", status_code=303)
    response.set_cookie(
        "wh_session", _new_token, httponly=True, max_age=86400 * 7, samesite="lax", secure=is_cookie_secure()
    )
    response.set_cookie(
        "wh_active_project_id",
        new_project.id,
        httponly=True,
        max_age=86400 * 30,
        samesite="lax",
        secure=is_cookie_secure(),
    )
    return response


@router.post("/dashboard/projects/switch")
def switch_project(
    request: Request, project_id: str = Form(...), csrf_token: str | None = Form(None), db: Session = Depends(get_db)
):
    assert_csrf(request, csrf_token)
    user, org, _ = get_user_and_project(request, db)
    if not user or not org:
        return RedirectResponse(url="/auth/login", status_code=302)

    project = db.query(Project).filter(Project.id == project_id, Project.organization_id == org.id).first()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    # Rotate session on privilege-context change (project switch).
    from app.services.security import invalidate_session_token as _inv2

    _old2 = request.cookies.get("wh_session")
    if _old2:
        try:
            _inv2(_old2)
        except Exception:
            pass
    _new_token2 = create_session_token(user.id, org_id=org.id, project_id=project.id)
    response = RedirectResponse(url="/dashboard", status_code=303)
    response.set_cookie(
        "wh_session", _new_token2, httponly=True, max_age=86400 * 7, samesite="lax", secure=is_cookie_secure()
    )
    response.set_cookie(
        "wh_active_project_id", project.id, httponly=True, max_age=86400 * 30, samesite="lax", secure=is_cookie_secure()
    )
    return response


@router.post("/dashboard/orgs/switch")
def switch_organization(
    request: Request,
    organization_id: str = Form(...),
    csrf_token: str | None = Form(None),
    db: Session = Depends(get_db),
):
    """Switch workspace between organizations this login is a member of."""
    assert_csrf(request, csrf_token)
    user, _, _ = get_user_and_project(request, db)
    if not user:
        return RedirectResponse(url="/auth/login", status_code=302)

    membership = (
        db.query(OrganizationMember)
        .filter(OrganizationMember.user_id == user.id, OrganizationMember.organization_id == organization_id)
        .first()
    )
    if not membership:
        raise HTTPException(status_code=404, detail="Organization not found")

    project = (
        db.query(Project).filter(Project.organization_id == organization_id).order_by(Project.created_at.desc()).first()
    )

    from app.services.security import invalidate_session_token as _inv3

    _old3 = request.cookies.get("wh_session")
    if _old3:
        try:
            _inv3(_old3)
        except Exception:
            pass
    _new_token3 = create_session_token(user.id, org_id=organization_id, project_id=project.id if project else None)
    response = RedirectResponse(url="/dashboard", status_code=303)
    response.set_cookie(
        "wh_session", _new_token3, httponly=True, max_age=86400 * 7, samesite="lax", secure=is_cookie_secure()
    )
    response.set_cookie(
        "wh_active_org_id",
        organization_id,
        httponly=True,
        max_age=86400 * 30,
        samesite="lax",
        secure=is_cookie_secure(),
    )
    if project:
        response.set_cookie(
            "wh_active_project_id",
            project.id,
            httponly=True,
            max_age=86400 * 30,
            samesite="lax",
            secure=is_cookie_secure(),
        )
    else:
        response.delete_cookie("wh_active_project_id")
    return response


# ================= ENDPOINTS =================


@router.get("/dashboard/endpoints", response_class=HTMLResponse)
def list_endpoints(request: Request, db: Session = Depends(get_db)):
    user, org, project = get_user_and_project(request, db)
    if not user or not project:
        return RedirectResponse(url="/auth/login", status_code=302)

    endpoints = db.query(Endpoint).filter(Endpoint.project_id == project.id).order_by(Endpoint.created_at.desc()).all()
    return templates.TemplateResponse(
        "endpoints/index.html",
        {"request": request, "current_user": user, "current_project": project, "endpoints": endpoints},
    )


@router.post("/dashboard/endpoints")
def create_endpoint_post(
    request: Request,
    url: str = Form(...),
    description: str | None = Form(None),
    event_types: str = Form("*"),
    rate_limit_per_second: int = Form(10),
    csrf_token: str | None = Form(None),
    db: Session = Depends(get_db),
):
    assert_csrf(request, csrf_token)
    user, org, project = get_user_and_project(request, db)
    if not user or not project:
        return RedirectResponse(url="/auth/login", status_code=302)
    require_manager(db, org, user)

    # Enforce maximum endpoints per project limit
    cur_ep_count = db.query(func.count(Endpoint.id)).filter(Endpoint.project_id == project.id).scalar() or 0
    if cur_ep_count >= settings.MAX_ENDPOINTS_PER_PROJECT:
        endpoints = db.query(Endpoint).filter(Endpoint.project_id == project.id).all()
        return templates.TemplateResponse(
            "endpoints/index.html",
            {
                "request": request,
                "current_user": user,
                "current_project": project,
                "endpoints": endpoints,
                "message": f"Project limit reached. Maximum {settings.MAX_ENDPOINTS_PER_PROJECT} endpoints allowed per project.",
                "message_type": "error",
            },
            status_code=400,
        )

    url = url.strip()
    is_valid, err = validate_webhook_url(url)
    if not is_valid:
        endpoints = db.query(Endpoint).filter(Endpoint.project_id == project.id).all()
        return templates.TemplateResponse(
            "endpoints/index.html",
            {
                "request": request,
                "current_user": user,
                "current_project": project,
                "endpoints": endpoints,
                "message": f"URL validation failed: {err}",
                "message_type": "error",
            },
            status_code=400,
        )

    # Validate subscription patterns (prevent DB errors / wildcard abuse)
    import re as _re

    def _valid_sub(p: str) -> bool:
        if not p or len(p) > 255:
            return False
        if p == "*":
            return True
        if not _re.match(r"^[A-Za-z0-9._*-]+$", p):
            return False
        # '*' only allowed as full wildcard or trailing '.*'
        if "*" in p and not (p == "*" or p.endswith(".*")):
            return False
        return True

    # Generate and encrypt endpoint HMAC signing secret
    plain_secret = generate_signing_secret()
    encrypted_secret = encrypt_secret(plain_secret)

    # Clamp rate limit to schema bounds (1..100)
    try:
        _rl = max(1, min(100, int(rate_limit_per_second or 10)))
    except Exception:
        _rl = 10
    endpoint = Endpoint(
        project_id=project.id,
        url=url[:2048],
        description=(description.strip()[:500] if description else None),
        encrypted_signing_secret=encrypted_secret,
        enabled=True,
        rate_limit_per_second=_rl,
    )
    db.add(endpoint)
    db.flush()

    # Parse subscribed event types
    raw_types = [t.strip() for t in event_types.split(",") if t.strip()]
    if not raw_types:
        raw_types = ["*"]
    if len(raw_types) > 50:
        db.rollback()
        endpoints = db.query(Endpoint).filter(Endpoint.project_id == project.id).all()
        return templates.TemplateResponse(
            "endpoints/index.html",
            {
                "request": request,
                "current_user": user,
                "current_project": project,
                "endpoints": endpoints,
                "message": "Too many subscriptions (max 50).",
                "message_type": "error",
            },
            status_code=400,
        )
    for et in raw_types:
        if not _valid_sub(et):
            db.rollback()
            endpoints = db.query(Endpoint).filter(Endpoint.project_id == project.id).all()
            return templates.TemplateResponse(
                "endpoints/index.html",
                {
                    "request": request,
                    "current_user": user,
                    "current_project": project,
                    "endpoints": endpoints,
                    "message": f"Invalid subscription pattern: {et}",
                    "message_type": "error",
                },
                status_code=400,
            )

    for et in set(raw_types):
        sub = EndpointSubscription(endpoint_id=endpoint.id, event_type=et[:255])
        db.add(sub)

    db.commit()

    # Audit log
    from app.services.audit import log_audit_event

    client_ip = get_client_ip(request)
    log_audit_event(
        db=db,
        organization_id=org.id,
        user_id=user.id,
        action="endpoint.create",
        resource_type="endpoint",
        resource_id=endpoint.id,
        ip_address=client_ip,
        details={"url": endpoint.url, "subscriptions": raw_types},
    )

    return RedirectResponse(url=f"/dashboard/endpoints/{endpoint.id}", status_code=303)


@router.get("/dashboard/endpoints/{endpoint_id}", response_class=HTMLResponse)
def endpoint_detail(endpoint_id: str, request: Request, db: Session = Depends(get_db)):
    user, org, project = get_user_and_project(request, db)
    if not user or not project:
        return RedirectResponse(url="/auth/login", status_code=302)

    endpoint = db.query(Endpoint).filter(Endpoint.id == endpoint_id, Endpoint.project_id == project.id).first()
    if not endpoint:
        raise HTTPException(status_code=404, detail="Endpoint not found")

    membership = get_membership(db, org.id, user.id)
    is_mgr = bool(membership and membership.role in ("owner", "admin"))
    decrypted_secret = None
    decryption_failed = False
    if is_mgr:
        try:
            decrypted_secret = decrypt_secret(endpoint.encrypted_signing_secret)
            # Opportunistic rotation: upgrade ciphertext to primary key in DB
            try:
                rotated_ct, was_rotated = rotate_secret_ciphertext(endpoint.encrypted_signing_secret)
                if was_rotated:
                    endpoint.encrypted_signing_secret = rotated_ct
                    db.commit()
            except Exception:
                pass
        except Exception:
            decryption_failed = True

    recent_deliveries = (
        db.query(Delivery)
        .options(joinedload(Delivery.event))
        .filter(Delivery.endpoint_id == endpoint.id)
        .order_by(Delivery.created_at.desc())
        .limit(20)
        .all()
    )

    return templates.TemplateResponse(
        "endpoints/detail.html",
        {
            "request": request,
            "current_user": user,
            "current_project": project,
            "endpoint": endpoint,
            "decrypted_secret": decrypted_secret,
            "decryption_failed": decryption_failed,
            "is_mgr": is_mgr,
            "endpoint_deliveries": recent_deliveries,
        },
    )


@router.post("/dashboard/endpoints/{endpoint_id}/toggle")
def toggle_endpoint(
    endpoint_id: str, request: Request, csrf_token: str | None = Form(None), db: Session = Depends(get_db)
):
    assert_csrf(request, csrf_token)
    user, org, project = get_user_and_project(request, db)
    if not user or not project:
        return RedirectResponse(url="/auth/login", status_code=302)
    require_manager(db, org, user)

    endpoint = db.query(Endpoint).filter(Endpoint.id == endpoint_id, Endpoint.project_id == project.id).first()
    if endpoint:
        endpoint.enabled = not endpoint.enabled
        db.commit()

        from app.services.audit import log_audit_event

        client_ip = get_client_ip(request)
        log_audit_event(
            db=db,
            organization_id=org.id,
            user_id=user.id,
            action="endpoint.toggle",
            resource_type="endpoint",
            resource_id=endpoint.id,
            ip_address=client_ip,
            details={"enabled": endpoint.enabled},
        )

    return RedirectResponse(url=safe_back_redirect(request, "/dashboard/endpoints"), status_code=303)


@router.post("/dashboard/endpoints/{endpoint_id}/disable")
def disable_endpoint(
    endpoint_id: str, request: Request, csrf_token: str | None = Form(None), db: Session = Depends(get_db)
):
    assert_csrf(request, csrf_token)
    user, org, project = get_user_and_project(request, db)
    if not user or not project:
        return RedirectResponse(url="/auth/login", status_code=302)
    require_manager(db, org, user)

    endpoint = db.query(Endpoint).filter(Endpoint.id == endpoint_id, Endpoint.project_id == project.id).first()
    if endpoint:
        endpoint.enabled = False
        db.commit()

        from app.services.audit import log_audit_event

        client_ip = get_client_ip(request)
        log_audit_event(
            db=db,
            organization_id=org.id,
            user_id=user.id,
            action="endpoint.disable",
            resource_type="endpoint",
            resource_id=endpoint.id,
            ip_address=client_ip,
            details={"enabled": False},
        )

    return RedirectResponse(url=safe_back_redirect(request, "/dashboard/endpoints"), status_code=303)


@router.post("/dashboard/endpoints/{endpoint_id}/rotate-secret")
def rotate_endpoint_secret(
    endpoint_id: str, request: Request, csrf_token: str | None = Form(None), db: Session = Depends(get_db)
):
    assert_csrf(request, csrf_token)
    user, org, project = get_user_and_project(request, db)
    if not user or not project:
        return RedirectResponse(url="/auth/login", status_code=302)
    require_manager(db, org, user)

    endpoint = db.query(Endpoint).filter(Endpoint.id == endpoint_id, Endpoint.project_id == project.id).first()
    if not endpoint:
        raise HTTPException(status_code=404, detail="Endpoint not found")

    new_secret = generate_signing_secret()
    endpoint.encrypted_signing_secret = encrypt_secret(new_secret)
    db.commit()

    from app.services.audit import log_audit_event

    client_ip = get_client_ip(request)
    log_audit_event(
        db=db,
        organization_id=org.id,
        user_id=user.id,
        action="endpoint.rotate_secret",
        resource_type="endpoint",
        resource_id=endpoint.id,
        ip_address=client_ip,
        details={"status": "rotated"},
    )

    return RedirectResponse(url=f"/dashboard/endpoints/{endpoint.id}", status_code=303)


@router.post("/dashboard/endpoints/{endpoint_id}/edit")
def edit_endpoint_post(
    endpoint_id: str,
    request: Request,
    url: str = Form(...),
    description: str | None = Form(None),
    event_types: str = Form("*"),
    rate_limit_per_second: int = Form(10),
    csrf_token: str | None = Form(None),
    db: Session = Depends(get_db),
):
    """Full endpoint CRUD: update URL, description, rate limit and subscriptions."""
    assert_csrf(request, csrf_token)
    user, org, project = get_user_and_project(request, db)
    if not user or not project:
        return RedirectResponse(url="/auth/login", status_code=302)
    require_manager(db, org, user)

    endpoint = db.query(Endpoint).filter(Endpoint.id == endpoint_id, Endpoint.project_id == project.id).first()
    if not endpoint:
        raise HTTPException(status_code=404, detail="Endpoint not found")

    new_url = (url or "").strip()[:2048]
    is_valid, err = validate_webhook_url(new_url)
    if not is_valid:
        raise HTTPException(status_code=400, detail=f"URL validation failed: {err}")

    import re as _re2

    raw_types = [t.strip() for t in (event_types or "*").split(",") if t.strip()] or ["*"]
    if len(raw_types) > 50:
        raise HTTPException(status_code=400, detail="Too many subscriptions (max 50).")
    for et in raw_types:
        if (
            not et
            or len(et) > 255
            or not _re2.match(r"^[A-Za-z0-9._*-]+$", et)
            or ("*" in et and not (et == "*" or et.endswith(".*")))
        ):
            raise HTTPException(status_code=400, detail=f"Invalid subscription pattern: {et}")

    endpoint.url = new_url
    endpoint.description = description.strip()[:500] if description else None
    try:
        endpoint.rate_limit_per_second = max(1, min(100, int(rate_limit_per_second or 10)))
    except Exception:
        endpoint.rate_limit_per_second = 10

    # Replace subscriptions atomically
    db.query(EndpointSubscription).filter(EndpointSubscription.endpoint_id == endpoint.id).delete()
    for et in set(raw_types):
        db.add(EndpointSubscription(endpoint_id=endpoint.id, event_type=et[:255]))
    db.commit()

    from app.services.audit import log_audit_event

    log_audit_event(
        db=db,
        organization_id=org.id,
        user_id=user.id,
        action="endpoint.update",
        resource_type="endpoint",
        resource_id=endpoint.id,
        ip_address=get_client_ip(request),
        details={"url": endpoint.url, "subscriptions": raw_types},
    )
    return RedirectResponse(url=f"/dashboard/endpoints/{endpoint.id}", status_code=303)


@router.post("/dashboard/endpoints/{endpoint_id}/delete")
def delete_endpoint_post(
    endpoint_id: str, request: Request, csrf_token: str | None = Form(None), db: Session = Depends(get_db)
):
    """Full endpoint CRUD: delete endpoint and its subscriptions.

    Existing deliveries keep their `target_url_snapshot` for audit history;
    only future events stop fanning out to this endpoint.
    """
    assert_csrf(request, csrf_token)
    user, org, project = get_user_and_project(request, db)
    if not user or not project:
        return RedirectResponse(url="/auth/login", status_code=302)
    require_manager(db, org, user)

    endpoint = db.query(Endpoint).filter(Endpoint.id == endpoint_id, Endpoint.project_id == project.id).first()
    if not endpoint:
        raise HTTPException(status_code=404, detail="Endpoint not found")
    ep_id = endpoint.id
    ep_url = endpoint.url
    db.delete(endpoint)
    db.commit()

    from app.services.audit import log_audit_event

    log_audit_event(
        db=db,
        organization_id=org.id,
        user_id=user.id,
        action="endpoint.delete",
        resource_type="endpoint",
        resource_id=ep_id,
        ip_address=get_client_ip(request),
        details={"url": ep_url},
    )
    return RedirectResponse(url="/dashboard/endpoints", status_code=303)


@router.post("/dashboard/endpoints/{endpoint_id}/ping")
def ping_endpoint(
    endpoint_id: str, request: Request, csrf_token: str | None = Form(None), db: Session = Depends(get_db)
):
    assert_csrf(request, csrf_token)
    user, org, project = get_user_and_project(request, db)
    if not user or not project:
        return RedirectResponse(url="/auth/login", status_code=302)
    require_manager(db, org, user)

    endpoint = db.query(Endpoint).filter(Endpoint.id == endpoint_id, Endpoint.project_id == project.id).first()
    if not endpoint:
        raise HTTPException(status_code=404, detail="Endpoint not found")

    # Throttle dashboard ingest the same as the public API (prevents member/CSRF fan-out).
    from app.services.rate_limiter import check_ingestion_rate_limit

    _allowed, _wait = check_ingestion_rate_limit(
        project.id, max_per_second=float(settings.INGESTION_RATE_LIMIT_PER_SECOND)
    )
    if not _allowed:
        raise HTTPException(status_code=429, detail="Ingestion rate limit exceeded. Try again shortly.")

    # Ingest a ping event
    ping_payload = {"ping": True, "timestamp": utc_now().isoformat(), "message": "Webhook platform test ping"}
    # Enforce payload-size limit consistently with public API (defense in depth;
    # ping body is tiny but keeps behavior uniform if template changes).
    import json as _json

    if len(_json.dumps(ping_payload, ensure_ascii=False).encode("utf-8")) > settings.MAX_PAYLOAD_SIZE_BYTES:
        raise HTTPException(status_code=413, detail="Ping payload exceeds maximum size.")
    event, _, _ = ingest_event(db, project.id, "endpoint.ping", ping_payload)

    # Ensure this specific endpoint receives the delivery even if its subscriptions do not match 'endpoint.ping'
    target_dlv = db.query(Delivery).filter(Delivery.event_id == event.id, Delivery.endpoint_id == endpoint.id).first()
    if not target_dlv:
        now = utc_now()
        ping_delivery = Delivery(
            event_id=event.id,
            endpoint_id=endpoint.id,
            target_url_snapshot=endpoint.url,
            status="PENDING",
            attempt_count=0,
            next_attempt_at=now,
            created_at=now,
        )
        db.add(ping_delivery)
        db.commit()

    return RedirectResponse(url=f"/dashboard/events/{event.id}", status_code=303)


# ================= EVENTS =================


@router.get("/dashboard/events", response_class=HTMLResponse)
def list_events(request: Request, type: str | None = None, page: int = 1, db: Session = Depends(get_db)):
    user, org, project = get_user_and_project(request, db)
    if not user or not project:
        return RedirectResponse(url="/auth/login", status_code=302)

    query = db.query(Event).filter(Event.project_id == project.id)
    if type and type.strip():
        query = query.filter(Event.event_type == type.strip())

    page = min(max(1, page), 1000)
    per_page = 20
    total_count = query.count()
    total_pages = max(1, (total_count + per_page - 1) // per_page)
    events = query.order_by(Event.created_at.desc()).offset((page - 1) * per_page).limit(per_page).all()

    return templates.TemplateResponse(
        "events/index.html",
        {
            "request": request,
            "current_user": user,
            "current_project": project,
            "events": events,
            "event_type_filter": type,
            "page": page,
            "per_page": per_page,
            "total_pages": total_pages,
            "total_count": total_count,
        },
    )


@router.get("/dashboard/events/send-test", response_class=HTMLResponse)
def send_test_event_page(request: Request, db: Session = Depends(get_db)):
    user, org, project = get_user_and_project(request, db)
    if not user or not project:
        return RedirectResponse(url="/auth/login", status_code=302)

    return templates.TemplateResponse(
        "events/send_test.html",
        {
            "request": request,
            "current_user": user,
            "current_project": project,
            **_send_test_endpoints_ctx(db, project.id),
        },
    )


def _send_test_endpoints_ctx(db: Session, project_id: str) -> dict:
    """Enabled endpoints + subscription labels for the publish target picker."""
    try:
        endpoints = (
            db.query(Endpoint)
            .filter(Endpoint.project_id == project_id, Endpoint.enabled == True)
            .order_by(Endpoint.url.asc())
            .all()
        )
    except Exception:
        endpoints = []
    subs: dict[str, list[str]] = {}
    try:
        if endpoints:
            from collections import defaultdict as _dd

            rows = (
                db.query(EndpointSubscription.endpoint_id, EndpointSubscription.event_type)
                .filter(EndpointSubscription.endpoint_id.in_([e.id for e in endpoints]))
                .all()
            )
            _map: dict[str, list[str]] = _dd(list)
            for _eid, _etype in rows:
                _map[_eid].append(_etype)
            subs = dict(_map)
    except Exception:
        subs = {}
    return {"endpoints": endpoints, "ep_subs": subs}


@router.post("/dashboard/events/send-test")
def send_test_event_post(
    request: Request,
    event_type: str = Form(...),
    idempotency_key: str | None = Form(None),
    payload_data: str = Form(...),
    target_mode: str = Form("all"),
    endpoint_ids: list[str] = Form(default=[]),
    csrf_token: str | None = Form(None),
    db: Session = Depends(get_db),
):
    assert_csrf(request, csrf_token)
    user, org, project = get_user_and_project(request, db)
    if not user or not project:
        return RedirectResponse(url="/auth/login", status_code=302)
    require_manager(db, org, user)

    _ep_ctx = _send_test_endpoints_ctx(db, project.id)
    # Targeted fan-out: "selected" restricts to checked endpoints (validated
    # against this project in ingest_event); anything else means all matches.
    _targets = endpoint_ids if (target_mode or "").strip().lower() == "selected" else None

    # Same throttle as public ingest + idempotency-key bound (DB column is 255).
    _idem = idempotency_key.strip() if idempotency_key and idempotency_key.strip() else None
    if _idem and len(_idem) > 255:
        return templates.TemplateResponse(
            "events/send_test.html",
            {
                "request": request,
                "current_user": user,
                "current_project": project,
                **_ep_ctx,
                "message": "Idempotency-Key must be ≤255 characters.",
                "message_type": "error",
            },
            status_code=400,
        )
    from app.services.rate_limiter import check_ingestion_rate_limit as _check_ingest

    _ok, _wait = _check_ingest(project.id, max_per_second=float(settings.INGESTION_RATE_LIMIT_PER_SECOND))
    if not _ok:
        return templates.TemplateResponse(
            "events/send_test.html",
            {
                "request": request,
                "current_user": user,
                "current_project": project,
                **_ep_ctx,
                "message": "Ingestion rate limit exceeded. Try again shortly.",
                "message_type": "error",
            },
            status_code=429,
        )

    try:
        parsed_data = json.loads(payload_data)
        if not isinstance(parsed_data, dict):
            raise ValueError("Payload must be a JSON object.")
    except Exception:
        return templates.TemplateResponse(
            "events/send_test.html",
            {
                "request": request,
                "current_user": user,
                "current_project": project,
                **_ep_ctx,
                "message": "Invalid JSON payload: please provide a valid JSON object.",
                "message_type": "error",
            },
            status_code=400,
        )

    # Enforce the same payload-size limit as POST /api/v1/events (413).
    if len(json.dumps(parsed_data, ensure_ascii=False).encode("utf-8")) > settings.MAX_PAYLOAD_SIZE_BYTES:
        return templates.TemplateResponse(
            "events/send_test.html",
            {
                "request": request,
                "current_user": user,
                "current_project": project,
                **_ep_ctx,
                "message": f"Payload exceeds maximum allowed size of {settings.MAX_PAYLOAD_SIZE_BYTES} bytes.",
                "message_type": "error",
            },
            status_code=413,
        )

    try:
        event, is_dup, count = ingest_event(
            db=db,
            project_id=project.id,
            event_type=event_type.strip(),
            payload_data=parsed_data,
            idempotency_key=_idem,
            endpoint_ids=_targets,
        )
    except IdempotencyConflictError as e:
        return templates.TemplateResponse(
            "events/send_test.html",
            {
                "request": request,
                "current_user": user,
                "current_project": project,
                **_ep_ctx,
                "message": f"Idempotency conflict: {e} Use a new key or resend the exact same event type and payload.",
                "message_type": "error",
            },
            status_code=409,
        )
    except ValueError as e:
        _raw = str(e) or ""
        safe_msg = (
            _raw
            if _raw.lower().startswith(("event", "payload", "idempotency", "select", "unknown", "too many"))
            else "Invalid event data."
        )
        return templates.TemplateResponse(
            "events/send_test.html",
            {
                "request": request,
                "current_user": user,
                "current_project": project,
                **_ep_ctx,
                "message": f"Event ingestion error: {safe_msg}",
                "message_type": "error",
            },
            status_code=400,
        )
    except Exception as e:
        import logging as _logging

        _logging.getLogger("webhook.dashboard").exception("send-test ingest failed")
        try:
            from sqlalchemy.exc import OperationalError as _OperationalError

            _is_db_error = isinstance(e, _OperationalError)
        except Exception:
            _is_db_error = False
        _req_id = getattr(getattr(request, "state", None), "request_id", None) or "-"
        if _is_db_error:
            _msg = (
                "Database temporarily unavailable. Your payload was not saved. "
                f"Please try again in a moment. (Reference: {_req_id})"
            )
            _status = 503
        else:
            _msg = f"Event ingestion failed ({type(e).__name__}). Please try again. (Reference: {_req_id})"
            _status = 400
        return templates.TemplateResponse(
            "events/send_test.html",
            {
                "request": request,
                "current_user": user,
                "current_project": project,
                **_ep_ctx,
                "message": _msg,
                "message_type": "error",
            },
            status_code=_status,
        )

    return RedirectResponse(url=f"/dashboard/events/{event.id}", status_code=303)


@router.get("/dashboard/events/{event_id}", response_class=HTMLResponse)
def event_detail_view(event_id: str, request: Request, page: int = 1, db: Session = Depends(get_db)):
    user, org, project = get_user_and_project(request, db)
    if not user or not project:
        return RedirectResponse(url="/auth/login", status_code=302)

    event = db.query(Event).filter(Event.id == event_id, Event.project_id == project.id).first()
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")

    try:
        parsed_payload = json.loads(event.payload_json)
        formatted_payload = json.dumps(parsed_payload, indent=2)
    except Exception:
        formatted_payload = event.payload_json

    # Paginate deliveries for this event (previously unpaginated full list).
    page = min(max(1, page), 1000)
    per_page = 20
    _dq = db.query(Delivery).filter(Delivery.event_id == event.id).order_by(Delivery.created_at.desc())
    _total = _dq.count()
    _total_pages = max(1, (_total + per_page - 1) // per_page)
    if page > _total_pages:
        page = _total_pages
    _deliveries = _dq.options(joinedload(Delivery.endpoint)).offset((page - 1) * per_page).limit(per_page).all()

    return templates.TemplateResponse(
        "events/detail.html",
        {
            "request": request,
            "current_user": user,
            "current_project": project,
            "event": event,
            "formatted_payload": formatted_payload,
            "deliveries": _deliveries,
            "page": page,
            "per_page": per_page,
            "total_pages": _total_pages,
            "total_count": _total,
        },
    )


# ================= DELIVERIES & DEAD LETTERS =================


@router.get("/dashboard/deliveries", response_class=HTMLResponse)
def list_deliveries(request: Request, status: str | None = None, page: int = 1, db: Session = Depends(get_db)):
    user, org, project = get_user_and_project(request, db)
    if not user or not project:
        return RedirectResponse(url="/auth/login", status_code=302)

    query = db.query(Delivery).join(Event, Delivery.event_id == Event.id).filter(Event.project_id == project.id)
    if status and status.strip():
        query = query.filter(Delivery.status == status.strip().upper())

    page = min(max(1, page), 1000)
    per_page = 20
    total_count = query.count()
    total_pages = max(1, (total_count + per_page - 1) // per_page)
    deliveries = (
        query.options(joinedload(Delivery.event), joinedload(Delivery.endpoint))
        .order_by(Delivery.created_at.desc())
        .offset((page - 1) * per_page)
        .limit(per_page)
        .all()
    )
    dead_count = (
        db.query(Delivery)
        .join(Event, Delivery.event_id == Event.id)
        .filter(Event.project_id == project.id, Delivery.status == "DEAD")
        .count()
    )

    return templates.TemplateResponse(
        "deliveries/index.html",
        {
            "request": request,
            "current_user": user,
            "current_project": project,
            "deliveries": deliveries,
            "status_filter": status,
            "dead_count": dead_count,
            "page": page,
            "per_page": per_page,
            "total_pages": total_pages,
            "total_count": total_count,
        },
    )


@router.get("/dashboard/deliveries/{delivery_id}", response_class=HTMLResponse)
def delivery_detail_view(delivery_id: str, request: Request, db: Session = Depends(get_db)):
    user, org, project = get_user_and_project(request, db)
    if not user or not project:
        return RedirectResponse(url="/auth/login", status_code=302)

    delivery = (
        db.query(Delivery)
        .join(Event, Delivery.event_id == Event.id)
        .filter(Delivery.id == delivery_id, Event.project_id == project.id)
        .first()
    )
    if not delivery:
        raise HTTPException(status_code=404, detail="Delivery not found")

    return templates.TemplateResponse(
        "deliveries/detail.html",
        {"request": request, "current_user": user, "current_project": project, "delivery": delivery},
    )


@router.get("/dashboard/deliveries/{delivery_id}/live", response_class=HTMLResponse)
def delivery_live_fragment(delivery_id: str, request: Request, db: Session = Depends(get_db)):
    """HTMX partial for the delivery detail live region (status + timeline)."""
    user, org, project = get_user_and_project(request, db)
    if not user or not project:
        return HTMLResponse("<p class='text-xs text-rose-500 p-4'>Not authorized</p>", status_code=401)

    delivery = (
        db.query(Delivery)
        .join(Event, Delivery.event_id == Event.id)
        .filter(Delivery.id == delivery_id, Event.project_id == project.id)
        .first()
    )
    if not delivery:
        return HTMLResponse("<p class='text-xs text-rose-500 p-4'>Delivery not found</p>", status_code=404)

    return templates.TemplateResponse(
        "deliveries/_live.html",
        {"request": request, "current_user": user, "current_project": project, "delivery": delivery},
    )


@router.get("/dashboard/deliveries/{delivery_id}/replay", response_class=HTMLResponse)
def replay_delivery_page(delivery_id: str, request: Request, db: Session = Depends(get_db)):
    user, org, project = get_user_and_project(request, db)
    if not user or not project:
        return RedirectResponse(url="/auth/login", status_code=302)
    require_manager(db, org, user)

    delivery = (
        db.query(Delivery)
        .join(Event, Delivery.event_id == Event.id)
        .filter(Delivery.id == delivery_id, Event.project_id == project.id)
        .first()
    )
    if not delivery:
        raise HTTPException(status_code=404, detail="Delivery not found in project")
    if delivery.status != "DEAD":
        raise HTTPException(status_code=400, detail="Only DEAD deliveries can be replayed.")

    endpoints = db.query(Endpoint).filter(Endpoint.project_id == project.id).order_by(Endpoint.url.asc()).all()
    # The original endpoint is already offered as "Same endpoint" above —
    # don't list it twice (nothing to dedupe when it was deleted).
    try:
        endpoints = [e for e in endpoints if e.id != delivery.endpoint_id]
    except Exception:
        pass
    subs: dict[str, list[str]] = {}
    try:
        if endpoints:
            from collections import defaultdict as _dd

            rows = (
                db.query(EndpointSubscription.endpoint_id, EndpointSubscription.event_type)
                .filter(EndpointSubscription.endpoint_id.in_([e.id for e in endpoints]))
                .all()
            )
            _map: dict[str, list[str]] = _dd(list)
            for _eid, _etype in rows:
                _map[_eid].append(_etype)
            subs = dict(_map)
    except Exception:
        subs = {}
    return templates.TemplateResponse(
        "deliveries/replay.html",
        {
            "request": request,
            "current_user": user,
            "current_project": project,
            "delivery": delivery,
            "endpoints": endpoints,
            "ep_subs": subs,
        },
    )


@router.post("/dashboard/deliveries/{delivery_id}/replay")
def replay_delivery_post(
    delivery_id: str,
    request: Request,
    endpoint_id: str | None = Form(None),
    csrf_token: str | None = Form(None),
    db: Session = Depends(get_db),
):
    assert_csrf(request, csrf_token)
    user, org, project = get_user_and_project(request, db)
    if not user or not project:
        return RedirectResponse(url="/auth/login", status_code=302)
    require_manager(db, org, user)

    # Enforce multi-tenant project authorization
    delivery = (
        db.query(Delivery)
        .join(Event, Delivery.event_id == Event.id)
        .filter(Delivery.id == delivery_id, Event.project_id == project.id)
        .first()
    )
    if not delivery:
        raise HTTPException(status_code=404, detail="Delivery not found in project")

    try:
        new_delivery = replay_delivery(db, delivery.id, new_endpoint_id=endpoint_id)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e) or "Invalid endpoint selected.")
    if not new_delivery:
        # Either missing or not a DEAD dead-letter (replay policy: DEAD only).
        raise HTTPException(status_code=400, detail="Only DEAD deliveries can be replayed.")

    return RedirectResponse(url=f"/dashboard/deliveries/{new_delivery.id}", status_code=303)


@router.get("/dashboard/dead-letters", response_class=HTMLResponse)
def list_dead_letters(request: Request, page: int = 1, db: Session = Depends(get_db)):
    user, org, project = get_user_and_project(request, db)
    if not user or not project:
        return RedirectResponse(url="/auth/login", status_code=302)

    query = (
        db.query(Delivery)
        .join(Event, Delivery.event_id == Event.id)
        .filter(Event.project_id == project.id, Delivery.status == "DEAD")
        .order_by(Delivery.created_at.desc())
    )

    page = min(max(1, page), 1000)
    per_page = 20
    total_count = query.count()
    total_pages = max(1, (total_count + per_page - 1) // per_page)
    dead_deliveries = query.offset((page - 1) * per_page).limit(per_page).all()

    return templates.TemplateResponse(
        "deliveries/dead_letters.html",
        {
            "request": request,
            "current_user": user,
            "current_project": project,
            "deliveries": dead_deliveries,
            "page": page,
            "per_page": per_page,
            "total_pages": total_pages,
            "total_count": total_count,
        },
    )


@router.post("/dashboard/dead-letters/replay-all")
def replay_all_dead_letters(request: Request, csrf_token: str | None = Form(None), db: Session = Depends(get_db)):
    assert_csrf(request, csrf_token)
    user, org, project = get_user_and_project(request, db)
    if not user or not project:
        return RedirectResponse(url="/auth/login", status_code=302)
    require_manager(db, org, user)

    # Bounded replay-all: cap at 100 per request to avoid thundering herd / timeouts.
    REPLAY_ALL_LIMIT = 100
    dead_ids = [
        r[0]
        for r in db.query(Delivery.id)
        .join(Event, Delivery.event_id == Event.id)
        .filter(Event.project_id == project.id, Delivery.status == "DEAD")
        .limit(REPLAY_ALL_LIMIT + 1)
        .all()
    ]
    capped = len(dead_ids) > REPLAY_ALL_LIMIT
    replayed = 0
    for dlv_id in dead_ids[:REPLAY_ALL_LIMIT]:
        try:
            if replay_delivery(db, dlv_id):
                replayed += 1
        except Exception:
            continue

    from app.services.audit import log_audit_event

    client_ip = get_client_ip(request)
    log_audit_event(
        db=db,
        organization_id=org.id,
        user_id=user.id,
        action="delivery.replay_all",
        resource_type="delivery",
        ip_address=client_ip,
        details={"replayed_count": replayed, "capped": capped, "limit": REPLAY_ALL_LIMIT},
    )

    return RedirectResponse(url="/dashboard/deliveries", status_code=303)


# ================= API KEYS =================


# One-time raw-key display tokens (POST-Redirect-GET for key creation so a
# browser reload can never re-POST and mint a duplicate). Random 24-byte
# tokens, single-use, 5-minute TTL, bound to (user, project). The raw key
# itself never appears in URLs or logs — only the token does.
import secrets as _secrets
import time as _time

_api_key_display: dict[str, tuple[str, str, str, float]] = {}
_API_KEY_DISPLAY_TTL_SECONDS = 300.0


def _issue_key_display_token(raw_key: str, user_id: str, project_id: str) -> str:
    now = _time.monotonic()
    for _tok in [t for t, (_, _, _, exp) in _api_key_display.items() if exp <= now]:
        _api_key_display.pop(_tok, None)
    token = _secrets.token_urlsafe(24)
    _api_key_display[token] = (raw_key, user_id, project_id, now + _API_KEY_DISPLAY_TTL_SECONDS)
    return token


def _consume_key_display_token(token: str | None, user_id: str, project_id: str) -> str | None:
    if not token:
        return None
    entry = _api_key_display.pop(token.strip(), None)
    if not entry:
        return None
    raw_key, uid, pid, exp = entry
    if uid != user_id or pid != project_id or exp <= _time.monotonic():
        return None
    return raw_key


def _render_api_keys(request: Request, db: Session, new_key: str | None = None, display_token: str | None = None):
    user, org, project = get_user_and_project(request, db)
    if not user or not project:
        return RedirectResponse(url="/auth/login", status_code=302)

    if display_token:
        new_key = _consume_key_display_token(display_token, user.id, project.id)

    keys = db.query(ApiKey).filter(ApiKey.project_id == project.id).order_by(ApiKey.created_at.desc()).all()
    return templates.TemplateResponse(
        "api_keys/index.html",
        {"request": request, "current_user": user, "current_project": project, "api_keys": keys, "new_key": new_key},
    )


@router.get("/dashboard/api-keys", response_class=HTMLResponse)
def list_api_keys(request: Request, new_key: str | None = None, db: Session = Depends(get_db)):
    return _render_api_keys(request, db, display_token=new_key)


@router.post("/dashboard/api-keys")
def create_api_key_post(
    request: Request, name: str = Form(...), csrf_token: str | None = Form(None), db: Session = Depends(get_db)
):
    assert_csrf(request, csrf_token)
    user, org, project = get_user_and_project(request, db)
    if not user or not project:
        return RedirectResponse(url="/auth/login", status_code=302)
    require_manager(db, org, user)
    clean_name = (name or "").strip()
    if not (1 <= len(clean_name) <= 100):
        keys = db.query(ApiKey).filter(ApiKey.project_id == project.id).order_by(ApiKey.created_at.desc()).all()
        return templates.TemplateResponse(
            "api_keys/index.html",
            {
                "request": request,
                "current_user": user,
                "current_project": project,
                "api_keys": keys,
                "new_key": None,
                "message": "API key name must be between 1 and 100 characters.",
                "message_type": "error",
            },
            status_code=400,
        )

    full_key, key_prefix, key_hash = generate_api_key()
    api_key_obj = ApiKey(project_id=project.id, name=clean_name, key_prefix=key_prefix, key_hash=key_hash)
    db.add(api_key_obj)
    db.commit()

    from app.services.audit import log_audit_event

    client_ip = get_client_ip(request)
    log_audit_event(
        db=db,
        organization_id=org.id,
        user_id=user.id,
        action="api_key.create",
        resource_type="api_key",
        resource_id=api_key_obj.id,
        ip_address=client_ip,
        details={"name": api_key_obj.name, "prefix": key_prefix},
    )

    # POST-Redirect-GET via one-time display token: reloading the landing
    # page can never re-POST and mint a same-name duplicate.
    _display = _issue_key_display_token(full_key, user.id, project.id)
    return RedirectResponse(url=f"/dashboard/api-keys?new_key={_display}", status_code=303)


@router.post("/dashboard/api-keys/{key_id}/revoke")
def revoke_api_key_post(
    key_id: str, request: Request, csrf_token: str | None = Form(None), db: Session = Depends(get_db)
):
    assert_csrf(request, csrf_token)
    user, org, project = get_user_and_project(request, db)
    if not user or not project:
        return RedirectResponse(url="/auth/login", status_code=302)
    require_manager(db, org, user)

    key = db.query(ApiKey).filter(ApiKey.id == key_id, ApiKey.project_id == project.id).first()
    if key and key.is_active:
        key.revoked_at = utc_now()
        db.commit()

        from app.services.audit import log_audit_event

        client_ip = get_client_ip(request)
        log_audit_event(
            db=db,
            organization_id=org.id,
            user_id=user.id,
            action="api_key.revoke",
            resource_type="api_key",
            resource_id=key.id,
            ip_address=client_ip,
            details={"name": key.name, "prefix": key.key_prefix},
        )

    return RedirectResponse(url="/dashboard/api-keys", status_code=303)


# ================= AUDIT LOGS =================


@router.get("/dashboard/audit-logs", response_class=HTMLResponse)
def list_audit_logs(request: Request, page: int = 1, db: Session = Depends(get_db)):
    user, org, project = get_user_and_project(request, db)
    if not user or not project:
        return RedirectResponse(url="/auth/login", status_code=302)
    # Security trail is manager-only: members must not see admin actions.
    require_manager(db, org, user)

    from app.models.audit_log import AuditLog

    query = db.query(AuditLog).filter(AuditLog.organization_id == org.id).order_by(AuditLog.created_at.desc())

    page = min(max(1, page), 1000)
    per_page = 20
    total_count = query.count()
    total_pages = max(1, (total_count + per_page - 1) // per_page)
    logs = query.offset((page - 1) * per_page).limit(per_page).all()

    # Actor role pills: membership role in this org, Superadmin flag wins.
    actor_roles: dict[str, str] = {}
    try:
        _uids = {entry.user_id for entry in logs if entry.user_id}
        if _uids:
            _mems = (
                db.query(OrganizationMember)
                .filter(OrganizationMember.organization_id == org.id, OrganizationMember.user_id.in_(list(_uids)))
                .all()
            )
            _role_by_uid = {m.user_id: (m.role or "member") for m in _mems}
            _users = db.query(User).filter(User.id.in_(list(_uids))).all()
            for u in _users:
                if getattr(u, "is_superadmin", False):
                    actor_roles[u.id] = "superadmin"
                elif u.id in _role_by_uid:
                    actor_roles[u.id] = _role_by_uid[u.id]
    except Exception:
        actor_roles = {}

    return templates.TemplateResponse(
        "audit_logs/index.html",
        {
            "request": request,
            "current_user": user,
            "current_project": project,
            "audit_logs": logs,
            "actor_roles": actor_roles,
            "page": page,
            "per_page": per_page,
            "total_pages": total_pages,
            "total_count": total_count,
        },
    )


# ================= SUPERADMIN APPROVAL QUEUE =================


def require_superadmin(user):
    """Global admins who approve/reject queued registrations."""
    if not user or not getattr(user, "is_superadmin", False):
        raise HTTPException(status_code=403, detail="Requires superadmin")
    return user


@router.get("/dashboard/admin/pending", response_class=HTMLResponse)
def list_pending_approvals(
    request: Request, db: Session = Depends(get_db), notice: str | None = None, notice_type: str | None = None
):
    user, org, project = get_user_and_project(request, db)
    if not user:
        return RedirectResponse(url="/auth/login", status_code=302)
    require_superadmin(user)
    pending = db.query(User).filter(User.status == "pending").order_by(User.created_at.asc()).limit(200).all()
    return templates.TemplateResponse(
        "team/pending.html",
        {
            "request": request,
            "current_user": user,
            "current_project": project,
            "pending_users": pending,
            "pending_count": len(pending),
            "message": (notice or "").strip()[:500] or None,
            "message_type": "error" if notice_type == "error" else "success",
        },
    )


@router.post("/dashboard/admin/approve")
def approve_pending_user(
    request: Request,
    user_id: str = Form(...),
    csrf_token: str | None = Form(None),
    db: Session = Depends(get_db),
):
    assert_csrf(request, csrf_token)
    actor, actor_org, _ = get_user_and_project(request, db)
    if not actor:
        return RedirectResponse(url="/auth/login", status_code=302)
    require_superadmin(actor)
    target = db.query(User).filter(User.id == user_id).first()
    if not target or (getattr(target, "status", None) or "approved") != "pending":
        return RedirectResponse(
            url="/dashboard/admin/pending?notice=User+not+pending&notice_type=error", status_code=303
        )
    try:
        org_name = (target.email.split("@")[0].capitalize() or "User") + "'s Org"
        org = Organization(name=org_name[:255])
        db.add(org)
        db.flush()
        db.add(OrganizationMember(organization_id=org.id, user_id=target.id, role="owner"))
        db.add(Project(organization_id=org.id, name="Default Project"))
        target.status = "approved"
        db.flush()
        from app.services.audit import log_audit_event

        log_audit_event(
            db,
            organization_id=org.id,
            user_id=actor.id,
            action="user.approved",
            resource_type="user",
            resource_id=target.id,
            ip_address=get_client_ip(request),
            details={"email": target.email},
            commit=False,
        )
        db.commit()
    except Exception:
        db.rollback()
        return RedirectResponse(url="/dashboard/admin/pending?notice=Approve+failed&notice_type=error", status_code=303)
    return RedirectResponse(url="/dashboard/admin/pending?notice=User+approved&notice_type=success", status_code=303)


@router.post("/dashboard/admin/reject")
def reject_pending_user(
    request: Request,
    user_id: str = Form(...),
    csrf_token: str | None = Form(None),
    db: Session = Depends(get_db),
):
    assert_csrf(request, csrf_token)
    actor, actor_org, _ = get_user_and_project(request, db)
    if not actor:
        return RedirectResponse(url="/auth/login", status_code=302)
    require_superadmin(actor)
    target = db.query(User).filter(User.id == user_id).first()
    if not target or (getattr(target, "status", None) or "approved") != "pending":
        return RedirectResponse(
            url="/dashboard/admin/pending?notice=User+not+pending&notice_type=error", status_code=303
        )
    try:
        target.status = "rejected"
        if actor_org is not None:
            from app.services.audit import log_audit_event

            log_audit_event(
                db,
                organization_id=actor_org.id,
                user_id=actor.id,
                action="user.rejected",
                resource_type="user",
                resource_id=target.id,
                ip_address=get_client_ip(request),
                details={"email": target.email},
                commit=False,
            )
        db.commit()
    except Exception:
        db.rollback()
        return RedirectResponse(url="/dashboard/admin/pending?notice=Reject+failed&notice_type=error", status_code=303)
    return RedirectResponse(url="/dashboard/admin/pending?notice=User+rejected&notice_type=success", status_code=303)


# ================= TEAM & INVITATIONS =================


@router.get("/dashboard/team", response_class=HTMLResponse)
def list_team(
    request: Request, db: Session = Depends(get_db), notice: str | None = None, notice_type: str | None = None
):
    user, org, project = get_user_and_project(request, db)
    if not user or not org:
        return RedirectResponse(url="/auth/login", status_code=302)

    membership = get_membership(db, org.id, user.id)
    is_mgr = bool(membership and membership.role in ("owner", "admin"))

    from app.models.invitation import OrganizationInvitation

    members = (
        db.query(OrganizationMember)
        .options(joinedload(OrganizationMember.user))
        .filter(OrganizationMember.organization_id == org.id)
        .all()
    )
    invitations = (
        db.query(OrganizationInvitation)
        .filter(OrganizationInvitation.organization_id == org.id)
        .order_by(OrganizationInvitation.created_at.desc())
        .all()
    )

    if not is_mgr:
        for inv in invitations:
            inv.token = None

    return templates.TemplateResponse(
        "team/index.html",
        {
            "request": request,
            "current_user": user,
            "current_project": project,
            "current_org": org,
            "members": members,
            "invitations": invitations,
            "is_manager": is_mgr,
            "actor_role": membership.role if membership else None,
            "message": (notice or "").strip()[:500] or None,
            "message_type": "error" if notice_type == "error" else "success",
        },
    )


@router.post("/dashboard/team/invite")
def invite_team_member(
    request: Request,
    email: str = Form(...),
    role: str = Form("member"),
    csrf_token: str | None = Form(None),
    db: Session = Depends(get_db),
):
    assert_csrf(request, csrf_token)
    user, org, project = get_user_and_project(request, db)
    if not user or not org:
        return RedirectResponse(url="/auth/login", status_code=302)

    # Enforce role hierarchy: only owner or admin can invite
    cur_membership = (
        db.query(OrganizationMember)
        .filter(OrganizationMember.organization_id == org.id, OrganizationMember.user_id == user.id)
        .first()
    )

    if not cur_membership or cur_membership.role not in ("owner", "admin"):
        raise HTTPException(status_code=403, detail="Only organization owners and admins can invite team members.")

    email_clean = email.strip().lower()
    if not _EMAIL_REGEX.match(email_clean) or len(email_clean) > 255:
        raise HTTPException(status_code=400, detail="Invalid email address.")
    # Invite throttle + dedup: prevent spam / mass-invite DoS
    from app.services.rate_limiter import check_invite_rate_limit

    _inv_allowed, _inv_wait = check_invite_rate_limit(org.id)
    if not _inv_allowed:
        raise HTTPException(status_code=429, detail=f"Too many invites. Try again in {int(_inv_wait) + 1}s.")
    from app.models.invitation import OrganizationInvitation
    from app.services.security import hash_invitation_token
    import secrets as _sec_inv

    # Invalidate previous pending invitations for the same organization and email
    db.query(OrganizationInvitation).filter(
        OrganizationInvitation.organization_id == org.id,
        OrganizationInvitation.email == email_clean,
        OrganizationInvitation.status == "PENDING",
    ).update({"status": "REVOKED"}, synchronize_session=False)

    raw_token = _sec_inv.token_urlsafe(32)
    invitation = OrganizationInvitation(
        organization_id=org.id,
        email=email_clean,
        role=role if role in ("admin", "member") else "member",
        token=hash_invitation_token(raw_token),
        invited_by_user_id=user.id,
    )
    db.add(invitation)
    db.commit()

    from urllib.parse import quote

    from app.services.email import send_invitation_email

    base = (settings.PUBLIC_BASE_URL or "").strip().rstrip("/")
    if not base:
        # Fail closed in production: deriving links from Host: header allows
        # Host-header poisoning (attacker Host -> emailed credential link).
        # PUBLIC_BASE_URL is required in prod compose + config validator.
        try:
            from app.config import is_production_env as _is_prod_env

            _is_prod = bool(_is_prod_env(getattr(settings, "ENV", "")))
        except Exception:
            _is_prod = False
        if _is_prod:
            raise HTTPException(
                status_code=500,
                detail="PUBLIC_BASE_URL is not configured. Set PUBLIC_BASE_URL=https://hooks.example.com.",
            )
        base = str(request.base_url).rstrip("/")
    invite_url = f"{base}/auth/invitations/{raw_token}"
    sent = send_invitation_email(email_clean, invite_url, org.name, invitation.role)
    # Never place the raw token in the redirect Location (browser history,
    # nginx/uvicorn access logs, aggregators). On SMTP failure render the link
    # once in the response BODY so the inviter can copy it; the URL stays clean.
    if not sent:
        from app.services.audit import log_audit_event as _log_invite_fail

        client_ip = get_client_ip(request)
        _log_invite_fail(
            db=db,
            organization_id=org.id,
            user_id=user.id,
            action="team.invite",
            resource_type="invitation",
            resource_id=invitation.id,
            ip_address=client_ip,
            details={"invitee_email": email_clean, "role": invitation.role, "emailed": False},
        )
        return templates.TemplateResponse(
            "team/index.html",
            {
                "request": request,
                "current_user": user,
                "current_project": project,
                "current_org": org,
                "members": db.query(OrganizationMember)
                .options(joinedload(OrganizationMember.user))
                .filter(OrganizationMember.organization_id == org.id)
                .all(),
                "invitations": db.query(OrganizationInvitation)
                .filter(OrganizationInvitation.organization_id == org.id)
                .order_by(OrganizationInvitation.created_at.desc())
                .all(),
                "is_manager": True,
                "actor_role": cur_membership.role if cur_membership else None,
                "message": None,
                "message_type": "success",
                "invite_link": invite_url,
                "invite_email": email_clean,
                "error": "Email could not be sent. Copy this invite link now — it will not be shown again.",
            },
            status_code=200,
        )
    else:
        notice = quote(f"Invitation emailed to {email_clean}. If not visible, Check your spam folder too!", safe="")

    from app.services.audit import log_audit_event

    client_ip = get_client_ip(request)
    log_audit_event(
        db=db,
        organization_id=org.id,
        user_id=user.id,
        action="team.invite",
        resource_type="invitation",
        resource_id=invitation.id,
        ip_address=client_ip,
        details={"invitee_email": email_clean, "role": invitation.role, "emailed": sent},
    )

    return RedirectResponse(
        url=f"/dashboard/team?notice={notice}&notice_type={'success' if sent else 'error'}", status_code=303
    )


@router.post("/dashboard/team/invitations/{inv_id}/revoke")
def revoke_invitation(
    inv_id: str, request: Request, csrf_token: str | None = Form(None), db: Session = Depends(get_db)
):
    assert_csrf(request, csrf_token)
    user, org, _ = get_user_and_project(request, db)
    if not user or not org:
        return RedirectResponse(url="/auth/login", status_code=302)
    require_manager(db, org, user)

    from app.models.invitation import OrganizationInvitation

    invitation = (
        db.query(OrganizationInvitation)
        .filter(OrganizationInvitation.id == inv_id, OrganizationInvitation.organization_id == org.id)
        .first()
    )

    if invitation and invitation.status == "PENDING":
        invitation.status = "REVOKED"
        db.commit()

        from app.services.audit import log_audit_event

        client_ip = get_client_ip(request)
        log_audit_event(
            db=db,
            organization_id=org.id,
            user_id=user.id,
            action="team.revoke_invitation",
            resource_type="invitation",
            resource_id=invitation.id,
            ip_address=client_ip,
            details={"invitee_email": invitation.email},
        )

    return RedirectResponse(url="/dashboard/team", status_code=303)


@router.post("/dashboard/team/members/{member_id}/role")
def update_member_role(
    member_id: str,
    request: Request,
    role: str = Form(...),
    csrf_token: str | None = Form(None),
    db: Session = Depends(get_db),
):
    """Change a member's role. Owners can assign any role; admins can only manage members."""
    assert_csrf(request, csrf_token)
    user, org, _ = get_user_and_project(request, db)
    if not user or not org:
        return RedirectResponse(url="/auth/login", status_code=302)
    actor = require_manager(db, org, user)
    from urllib.parse import quote as _quote

    def _deny(msg: str):
        return RedirectResponse(
            url=f"/dashboard/team?notice={_quote(msg, safe='')}&notice_type=error",
            status_code=303,
        )

    target = (
        db.query(OrganizationMember)
        .filter(
            OrganizationMember.id == member_id,
            OrganizationMember.organization_id == org.id,
        )
        .first()
    )
    if not target:
        return _deny("Member not found.")
    if target.user_id == user.id:
        return _deny("You cannot change your own role.")
    new_role = (role or "").strip().lower()
    if new_role not in ("admin", "member"):
        return _deny("Role must be admin or member.")
    # Only owners may promote to admin or demote admins; admins manage members only.
    if actor.role != "owner" and (target.role in ("owner", "admin") or new_role == "admin"):
        return _deny("Only owners can manage admin roles.")
    if target.role == "owner":
        return _deny("Owner role cannot be changed; transfer ownership manually.")
    target.role = new_role
    db.commit()

    from app.services.audit import log_audit_event

    log_audit_event(
        db=db,
        organization_id=org.id,
        user_id=user.id,
        action="team.change_role",
        resource_type="membership",
        resource_id=target.id,
        ip_address=get_client_ip(request),
        details={"email": target.user.email if target.user else None, "new_role": new_role},
    )
    return RedirectResponse(
        url=f"/dashboard/team?notice={_quote(f'Role updated to {new_role}.', safe='')}&notice_type=success",
        status_code=303,
    )


@router.post("/dashboard/team/members/{member_id}/remove")
def remove_member(member_id: str, request: Request, csrf_token: str | None = Form(None), db: Session = Depends(get_db)):
    """Remove a member. Owners cannot be removed while they are the last owner."""
    assert_csrf(request, csrf_token)
    user, org, _ = get_user_and_project(request, db)
    if not user or not org:
        return RedirectResponse(url="/auth/login", status_code=302)
    actor = require_manager(db, org, user)
    from urllib.parse import quote as _quote

    def _deny(msg: str):
        return RedirectResponse(
            url=f"/dashboard/team?notice={_quote(msg, safe='')}&notice_type=error",
            status_code=303,
        )

    target = (
        db.query(OrganizationMember)
        .filter(
            OrganizationMember.id == member_id,
            OrganizationMember.organization_id == org.id,
        )
        .first()
    )
    if not target:
        return _deny("Member not found.")
    if target.user_id == user.id:
        return _deny("You cannot remove yourself.")
    if target.role == "owner":
        owners = (
            db.query(OrganizationMember)
            .filter(
                OrganizationMember.organization_id == org.id,
                OrganizationMember.role == "owner",
            )
            .count()
        )
        if owners <= 1:
            return _deny("Cannot remove the last owner.")
        if actor.role != "owner":
            return _deny("Only owners can remove an owner.")
    db.delete(target)
    db.commit()

    from app.services.audit import log_audit_event

    log_audit_event(
        db=db,
        organization_id=org.id,
        user_id=user.id,
        action="team.remove_member",
        resource_type="membership",
        resource_id=member_id,
        ip_address=get_client_ip(request),
        details={"removed_user_id": target.user_id},
    )
    return RedirectResponse(
        url=f"/dashboard/team?notice={_quote('Member removed successfully.', safe='')}&notice_type=success",
        status_code=303,
    )


@router.get("/auth/invitations/{token}", response_class=HTMLResponse)
def accept_invitation_page(token: str, request: Request, db: Session = Depends(get_db)):
    from app.models.invitation import OrganizationInvitation
    from app.services.security import get_client_ip, hash_invitation_token_candidates

    # Throttle the GET oracle too (POST alone is not enough — valid/invalid
    # pages differ, so unthrottled GET is a token oracle).
    from app.services.rate_limiter import check_invitation_accept_rate_limit

    _allowed, _wait = check_invitation_accept_rate_limit(get_client_ip(request))
    if not _allowed:
        return HTMLResponse(
            "<p style='padding:40px;text-align:center;font-family:sans-serif;'>Too many attempts. Please try again later.</p>",
            status_code=429,
        )
    candidates = hash_invitation_token_candidates(token)
    invitation = db.query(OrganizationInvitation).filter(OrganizationInvitation.token.in_(candidates)).first()
    if not invitation or not invitation.is_valid:
        return HTMLResponse(
            "<p style='padding:40px;text-align:center;font-family:sans-serif;'>This invitation link is invalid or has expired.</p>",
            status_code=400,
        )

    user = get_optional_user(request, db)
    existing_account = db.query(User).filter(User.email == invitation.email.lower()).first() if not user else None
    return templates.TemplateResponse(
        "team/accept_invitation.html",
        {
            "request": request,
            "invitation": invitation,
            "token": token,
            "current_user": user,
            "existing_account": existing_account is not None,
        },
    )


@router.post("/auth/invitations/{token}/accept")
def accept_invitation_post(
    token: str,
    request: Request,
    password: str | None = Form(None),
    csrf_token: str | None = Form(None),
    db: Session = Depends(get_db),
):
    assert_csrf(request, csrf_token)
    from app.services.rate_limiter import check_invitation_accept_rate_limit

    client_ip = get_client_ip(request)
    allowed, wait_sec = check_invitation_accept_rate_limit(client_ip)
    if not allowed:
        raise HTTPException(status_code=429, detail=f"Too many invitation attempts. Please wait {int(wait_sec) + 1}s.")

    from app.models.invitation import OrganizationInvitation
    from app.services.security import hash_invitation_token_candidates

    candidates = hash_invitation_token_candidates(token)
    invitation = db.query(OrganizationInvitation).filter(OrganizationInvitation.token.in_(candidates)).first()
    if not invitation or not invitation.is_valid:
        return HTMLResponse("<p>This invitation link is invalid or has expired.</p>", status_code=400)

    user = get_optional_user(request, db)
    # Enforce email match for logged-in users: a different account cannot
    # claim an invitation addressed to another email (invite-token guessing).
    if user and user.email.lower() != invitation.email.lower():
        return HTMLResponse(
            "<p style='padding:40px;text-align:center;font-family:sans-serif;'>This invitation was sent to a different email. Please log out and accept with the invited address.</p>",
            status_code=403,
        )

    # If not logged in, find user by email or register new user
    if not user:
        existing_user = db.query(User).filter(User.email == invitation.email.lower()).first()
        if existing_user:
            # Prevent Account Takeover: Require existing user password verification
            if not password or not verify_password(password, existing_user.password_hash):
                return templates.TemplateResponse(
                    "team/accept_invitation.html",
                    {
                        "request": request,
                        "invitation": invitation,
                        "current_user": None,
                        "existing_account": True,
                        "error": "An account with this email already exists. Please enter your existing password to accept.",
                    },
                    status_code=400,
                )
            user = existing_user
        else:
            import re as _re_inv

            _pw = password or ""
            _cls = sum(
                [
                    bool(_re_inv.search(r"[A-Z]", _pw)),
                    bool(_re_inv.search(r"[a-z]", _pw)),
                    bool(_re_inv.search(r"[0-9]", _pw)),
                    bool(_re_inv.search(r"[^A-Za-z0-9]", _pw)),
                ]
            )
            if len(_pw) < 8 or len(_pw) > 128 or _cls < 3:
                return templates.TemplateResponse(
                    "team/accept_invitation.html",
                    {
                        "request": request,
                        "invitation": invitation,
                        "current_user": None,
                        "existing_account": False,
                        "error": "Password must be 8..128 chars with 3 of: uppercase, lowercase, digit, symbol.",
                    },
                    status_code=400,
                )
            user = User(email=invitation.email.lower(), password_hash=hash_password(_pw))
            db.add(user)
            db.flush()

    # Add organization membership
    existing_mem = (
        db.query(OrganizationMember)
        .filter(OrganizationMember.organization_id == invitation.organization_id, OrganizationMember.user_id == user.id)
        .first()
    )

    if not existing_mem:
        new_mem = OrganizationMember(organization_id=invitation.organization_id, user_id=user.id, role=invitation.role)
        db.add(new_mem)

    # Mark invitation as accepted
    invitation.status = "ACCEPTED"
    db.commit()

    # Log audit event
    from app.services.audit import log_audit_event

    client_ip = get_client_ip(request)
    log_audit_event(
        db=db,
        organization_id=invitation.organization_id,
        user_id=user.id,
        action="team.accept_invitation",
        resource_type="invitation",
        resource_id=invitation.id,
        ip_address=client_ip,
        details={"email": user.email, "role": invitation.role},
    )

    # Set session cookie and redirect
    # Rotate: invalidate any pre-accept token (privilege change).
    from app.services.security import invalidate_session_token as _invA

    _oldA = request.cookies.get("wh_session")
    if _oldA:
        try:
            _invA(_oldA)
        except Exception:
            pass
    session_token = create_session_token(user.id, org_id=invitation.organization_id)
    response = RedirectResponse(url="/dashboard", status_code=303)
    response.set_cookie(
        "wh_session", session_token, httponly=True, max_age=86400 * 7, samesite="lax", secure=is_cookie_secure()
    )
    # Clear stale project selector; get_user_and_project will default to first project in new org.
    response.delete_cookie("wh_active_project_id")
    return response
