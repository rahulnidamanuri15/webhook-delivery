import json
from typing import Optional
from fastapi import APIRouter, Depends, Request, Form, Response, HTTPException, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from sqlalchemy import func

from app.db.session import get_db
from app.api.deps import get_optional_user
from app.models import (
    User, Organization, OrganizationMember, Project, ApiKey,
    Endpoint, EndpointSubscription, Event, Delivery, DeliveryAttempt, utc_now
)
from app.services.security import (
    hash_password, verify_password, create_session_token,
    generate_signing_secret, encrypt_secret, decrypt_secret, generate_api_key
)
from app.services.event_service import ingest_event
from app.services.delivery_service import replay_delivery
from app.services.ssrf import validate_webhook_url
from app.config import settings

class CompatibleJinja2Templates(Jinja2Templates):
    """Ensures seamless compatibility across Starlette versions for TemplateResponse."""
    def TemplateResponse(self, *args, **kwargs):
        if len(args) >= 2 and isinstance(args[0], str) and isinstance(args[1], dict):
            name, context = args[0], args[1]
            req = context.get("request") or kwargs.pop("request", None)
            return super().TemplateResponse(request=req, name=name, context=context, **kwargs)
        elif len(args) == 1 and isinstance(args[0], str) and "context" in kwargs:
            name = args[0]
            context = kwargs.pop("context")
            req = context.get("request") or kwargs.pop("request", None)
            return super().TemplateResponse(request=req, name=name, context=context, **kwargs)
        return super().TemplateResponse(*args, **kwargs)

templates = CompatibleJinja2Templates(directory="app/templates")
router = APIRouter()

def get_user_and_project(request: Request, db: Session):
    user = get_optional_user(request, db)
    if not user:
        return None, None, None
    
    # Active organization
    membership = db.query(OrganizationMember).filter(OrganizationMember.user_id == user.id).first()
    if not membership:
        return user, None, None
    
    org = membership.organization
    
    # Active project from cookie or default
    active_project_id = request.cookies.get("wh_active_project_id")
    project = None
    if active_project_id:
        project = db.query(Project).filter(Project.id == active_project_id, Project.organization_id == org.id).first()
    
    if not project:
        project = db.query(Project).filter(Project.organization_id == org.id).first()
        
    return user, org, project

# ================= AUTHENTICATION ROUTES =================

@router.get("/", response_class=HTMLResponse)
def root(request: Request, db: Session = Depends(get_db)):
    user, org, prj = get_user_and_project(request, db)
    if user:
        return RedirectResponse(url="/dashboard", status_code=302)
    return RedirectResponse(url="/auth/login", status_code=302)

@router.get("/auth/login", response_class=HTMLResponse)
def login_page(request: Request):
    return templates.TemplateResponse("auth/login.html", {"request": request, "current_user": None})

@router.post("/auth/login")
def login_post(
    request: Request,
    email: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db)
):
    user = db.query(User).filter(User.email == email.strip().lower()).first()
    if not user or not verify_password(password, user.password_hash):
        return templates.TemplateResponse(
            "auth/login.html",
            {"request": request, "error": "Invalid email or password.", "current_user": None},
            status_code=400
        )
    
    membership = db.query(OrganizationMember).filter(OrganizationMember.user_id == user.id).first()
    org_id = membership.organization_id if membership else None
    
    token = create_session_token(user.id, org_id=org_id)
    response = RedirectResponse(url="/dashboard", status_code=303)
    response.set_cookie(
        key="wh_session",
        value=token,
        httponly=True,
        max_age=86400 * 7,
        samesite="lax"
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
    db: Session = Depends(get_db)
):
    email = email.strip().lower()
    existing = db.query(User).filter(User.email == email).first()
    if existing:
        return templates.TemplateResponse(
            "auth/register.html",
            {"request": request, "error": "Email is already registered. Please sign in.", "current_user": None},
            status_code=400
        )
    
    if len(password) < 8:
        return templates.TemplateResponse(
            "auth/register.html",
            {"request": request, "error": "Password must be at least 8 characters long.", "current_user": None},
            status_code=400
        )

    # Atomically create user, organization, membership, and initial project
    user = User(email=email, password_hash=hash_password(password))
    db.add(user)
    db.flush()

    org_name = email.split("@")[0].capitalize() + "'s Org"
    org = Organization(name=org_name)
    db.add(org)
    db.flush()

    member = OrganizationMember(organization_id=org.id, user_id=user.id, role="owner")
    db.add(member)

    project = Project(organization_id=org.id, name=project_name.strip() or "Default Project")
    db.add(project)
    
    db.commit()

    token = create_session_token(user.id, org_id=org.id, project_id=project.id)
    response = RedirectResponse(url="/dashboard", status_code=303)
    response.set_cookie("wh_session", token, httponly=True, max_age=86400 * 7, samesite="lax")
    response.set_cookie("wh_active_project_id", project.id, httponly=False, max_age=86400 * 30, samesite="lax")
    return response

@router.get("/auth/logout")
def logout():
    response = RedirectResponse(url="/auth/login", status_code=303)
    response.delete_cookie("wh_session")
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
    dead_deliveries = delivery_base.filter(Delivery.status == "DEAD").count()
    total_deliveries = succeeded_deliveries + pending_deliveries + dead_deliveries

    # Attempt stats
    attempts_query = db.query(DeliveryAttempt).join(Delivery, DeliveryAttempt.delivery_id == Delivery.id).join(Event, Delivery.event_id == Event.id).filter(Event.project_id == project.id)
    total_attempts = attempts_query.count()
    successful_attempts = attempts_query.filter(DeliveryAttempt.outcome == "SUCCESS").count()
    avg_latency = attempts_query.with_entities(func.avg(DeliveryAttempt.duration_ms)).scalar() or 0

    delivery_success_rate = round((succeeded_deliveries / total_deliveries * 100), 1) if total_deliveries > 0 else 100.0
    attempt_success_rate = round((successful_attempts / total_attempts * 100), 1) if total_attempts > 0 else 100.0

    recent_events = (
        db.query(Event)
        .filter(Event.project_id == project.id)
        .order_by(Event.created_at.desc())
        .limit(10)
        .all()
    )

    recent_deliveries = (
        delivery_base
        .order_by(Delivery.created_at.desc())
        .limit(15)
        .all()
    )

    stats = {
        "total_events": total_events,
        "succeeded_deliveries": succeeded_deliveries,
        "pending_deliveries": pending_deliveries,
        "dead_deliveries": dead_deliveries,
        "total_attempts": total_attempts,
        "delivery_success_rate": delivery_success_rate,
        "attempt_success_rate": attempt_success_rate,
        "avg_latency_ms": round(avg_latency, 1)
    }

    return templates.TemplateResponse("dashboard/index.html", {
        "request": request,
        "current_user": user,
        "current_project": project,
        "stats": stats,
        "recent_events": recent_events,
        "deliveries": recent_deliveries
    })

@router.get("/dashboard/deliveries/table", response_class=HTMLResponse)
def deliveries_table_fragment(request: Request, db: Session = Depends(get_db)):
    """HTMX partial fragment endpoint."""
    user, org, project = get_user_and_project(request, db)
    if not user or not project:
        return HTMLResponse("<p>Not authorized</p>", status_code=401)

    deliveries = (
        db.query(Delivery)
        .join(Event, Delivery.event_id == Event.id)
        .filter(Event.project_id == project.id)
        .order_by(Delivery.created_at.desc())
        .limit(15)
        .all()
    )
    return templates.TemplateResponse("deliveries/_table.html", {
        "request": request,
        "deliveries": deliveries
    })

# ================= PROJECTS =================

@router.get("/dashboard/projects", response_class=HTMLResponse)
def list_projects(request: Request, db: Session = Depends(get_db)):
    user, org, project = get_user_and_project(request, db)
    if not user:
        return RedirectResponse(url="/auth/login", status_code=302)

    projects = db.query(Project).filter(Project.organization_id == org.id).order_by(Project.created_at.desc()).all()
    return templates.TemplateResponse("projects/index.html", {
        "request": request,
        "current_user": user,
        "current_project": project,
        "projects": projects
    })

@router.post("/dashboard/projects")
def create_project(
    request: Request,
    name: str = Form(...),
    db: Session = Depends(get_db)
):
    user, org, _ = get_user_and_project(request, db)
    if not user:
        return RedirectResponse(url="/auth/login", status_code=302)

    new_project = Project(organization_id=org.id, name=name.strip())
    db.add(new_project)
    db.commit()

    response = RedirectResponse(url="/dashboard/projects", status_code=303)
    response.set_cookie("wh_active_project_id", new_project.id, max_age=86400 * 30)
    return response

@router.post("/dashboard/projects/switch")
def switch_project(
    request: Request,
    project_id: str = Form(...),
    db: Session = Depends(get_db)
):
    user, org, _ = get_user_and_project(request, db)
    if not user:
        return RedirectResponse(url="/auth/login", status_code=302)

    project = db.query(Project).filter(Project.id == project_id, Project.organization_id == org.id).first()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    response = RedirectResponse(url="/dashboard", status_code=303)
    response.set_cookie("wh_active_project_id", project.id, max_age=86400 * 30)
    return response

# ================= ENDPOINTS =================

@router.get("/dashboard/endpoints", response_class=HTMLResponse)
def list_endpoints(request: Request, db: Session = Depends(get_db)):
    user, org, project = get_user_and_project(request, db)
    if not user or not project:
        return RedirectResponse(url="/auth/login", status_code=302)

    endpoints = db.query(Endpoint).filter(Endpoint.project_id == project.id).order_by(Endpoint.created_at.desc()).all()
    return templates.TemplateResponse("endpoints/index.html", {
        "request": request,
        "current_user": user,
        "current_project": project,
        "endpoints": endpoints
    })

@router.post("/dashboard/endpoints")
def create_endpoint_post(
    request: Request,
    url: str = Form(...),
    description: Optional[str] = Form(None),
    event_types: str = Form("*"),
    rate_limit_per_second: int = Form(10),
    db: Session = Depends(get_db)
):
    user, org, project = get_user_and_project(request, db)
    if not user or not project:
        return RedirectResponse(url="/auth/login", status_code=302)

    url = url.strip()
    is_valid, err = validate_webhook_url(url)
    if not is_valid:
        endpoints = db.query(Endpoint).filter(Endpoint.project_id == project.id).all()
        return templates.TemplateResponse("endpoints/index.html", {
            "request": request,
            "current_user": user,
            "current_project": project,
            "endpoints": endpoints,
            "message": f"URL validation failed: {err}",
            "message_type": "error"
        }, status_code=400)

    # Generate and encrypt endpoint HMAC signing secret
    plain_secret = generate_signing_secret()
    encrypted_secret = encrypt_secret(plain_secret)

    endpoint = Endpoint(
        project_id=project.id,
        url=url,
        description=description.strip() if description else None,
        encrypted_signing_secret=encrypted_secret,
        enabled=True,
        rate_limit_per_second=rate_limit_per_second
    )
    db.add(endpoint)
    db.flush()

    # Parse subscribed event types
    raw_types = [t.strip() for t in event_types.split(",") if t.strip()]
    if not raw_types:
        raw_types = ["*"]

    for et in set(raw_types):
        sub = EndpointSubscription(endpoint_id=endpoint.id, event_type=et)
        db.add(sub)

    db.commit()

    # Audit log
    from app.services.audit import log_audit_event
    client_ip = request.client.host if request.client else None
    log_audit_event(
        db=db,
        organization_id=org.id,
        user_id=user.id,
        action="endpoint.create",
        resource_type="endpoint",
        resource_id=endpoint.id,
        ip_address=client_ip,
        details={"url": endpoint.url, "subscriptions": raw_types}
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

    decrypted_secret = decrypt_secret(endpoint.encrypted_signing_secret)
    recent_deliveries = (
        db.query(Delivery)
        .filter(Delivery.endpoint_id == endpoint.id)
        .order_by(Delivery.created_at.desc())
        .limit(20)
        .all()
    )

    return templates.TemplateResponse("endpoints/detail.html", {
        "request": request,
        "current_user": user,
        "current_project": project,
        "endpoint": endpoint,
        "decrypted_secret": decrypted_secret,
        "endpoint_deliveries": recent_deliveries
    })

@router.post("/dashboard/endpoints/{endpoint_id}/toggle")
def toggle_endpoint(endpoint_id: str, request: Request, db: Session = Depends(get_db)):
    user, org, project = get_user_and_project(request, db)
    if not user or not project:
        return RedirectResponse(url="/auth/login", status_code=302)

    endpoint = db.query(Endpoint).filter(Endpoint.id == endpoint_id, Endpoint.project_id == project.id).first()
    if endpoint:
        endpoint.enabled = not endpoint.enabled
        db.commit()

        from app.services.audit import log_audit_event
        client_ip = request.client.host if request.client else None
        log_audit_event(
            db=db,
            organization_id=org.id,
            user_id=user.id,
            action="endpoint.toggle",
            resource_type="endpoint",
            resource_id=endpoint.id,
            ip_address=client_ip,
            details={"enabled": endpoint.enabled}
        )

    return RedirectResponse(url=request.headers.get("referer", "/dashboard/endpoints"), status_code=303)

@router.post("/dashboard/endpoints/{endpoint_id}/rotate-secret")
def rotate_endpoint_secret(endpoint_id: str, request: Request, db: Session = Depends(get_db)):
    user, org, project = get_user_and_project(request, db)
    if not user or not project:
        return RedirectResponse(url="/auth/login", status_code=302)

    endpoint = db.query(Endpoint).filter(Endpoint.id == endpoint_id, Endpoint.project_id == project.id).first()
    if not endpoint:
        raise HTTPException(status_code=404, detail="Endpoint not found")

    new_secret = generate_signing_secret()
    endpoint.encrypted_signing_secret = encrypt_secret(new_secret)
    db.commit()

    from app.services.audit import log_audit_event
    client_ip = request.client.host if request.client else None
    log_audit_event(
        db=db,
        organization_id=org.id,
        user_id=user.id,
        action="endpoint.rotate_secret",
        resource_type="endpoint",
        resource_id=endpoint.id,
        ip_address=client_ip,
        details={"status": "rotated"}
    )

    return RedirectResponse(url=f"/dashboard/endpoints/{endpoint.id}", status_code=303)

@router.post("/dashboard/endpoints/{endpoint_id}/ping")
def ping_endpoint(endpoint_id: str, request: Request, db: Session = Depends(get_db)):
    user, org, project = get_user_and_project(request, db)
    if not user or not project:
        return RedirectResponse(url="/auth/login", status_code=302)

    endpoint = db.query(Endpoint).filter(Endpoint.id == endpoint_id, Endpoint.project_id == project.id).first()
    if not endpoint:
        raise HTTPException(status_code=404, detail="Endpoint not found")

    # Ingest a ping event
    ping_payload = {
        "ping": True,
        "timestamp": utc_now().isoformat(),
        "message": "Webhook platform test ping"
    }
    event, _, _ = ingest_event(db, project.id, "endpoint.ping", ping_payload)

    return RedirectResponse(url=f"/dashboard/events/{event.id}", status_code=303)

# ================= EVENTS =================

@router.get("/dashboard/events", response_class=HTMLResponse)
def list_events(request: Request, type: Optional[str] = None, db: Session = Depends(get_db)):
    user, org, project = get_user_and_project(request, db)
    if not user or not project:
        return RedirectResponse(url="/auth/login", status_code=302)

    query = db.query(Event).filter(Event.project_id == project.id)
    if type and type.strip():
        query = query.filter(Event.event_type == type.strip())

    events = query.order_by(Event.created_at.desc()).limit(50).all()
    return templates.TemplateResponse("events/index.html", {
        "request": request,
        "current_user": user,
        "current_project": project,
        "events": events,
        "event_type_filter": type
    })

@router.get("/dashboard/events/send-test", response_class=HTMLResponse)
def send_test_event_page(request: Request, db: Session = Depends(get_db)):
    user, org, project = get_user_and_project(request, db)
    if not user or not project:
        return RedirectResponse(url="/auth/login", status_code=302)

    return templates.TemplateResponse("events/send_test.html", {
        "request": request,
        "current_user": user,
        "current_project": project
    })

@router.post("/dashboard/events/send-test")
def send_test_event_post(
    request: Request,
    event_type: str = Form(...),
    idempotency_key: Optional[str] = Form(None),
    payload_data: str = Form(...),
    db: Session = Depends(get_db)
):
    user, org, project = get_user_and_project(request, db)
    if not user or not project:
        return RedirectResponse(url="/auth/login", status_code=302)

    try:
        parsed_data = json.loads(payload_data)
        if not isinstance(parsed_data, dict):
            raise ValueError("Payload must be a JSON object.")
    except Exception as e:
        return templates.TemplateResponse("events/send_test.html", {
            "request": request,
            "current_user": user,
            "current_project": project,
            "message": f"Invalid JSON payload: {e}",
            "message_type": "error"
        }, status_code=400)

    try:
        event, is_dup, count = ingest_event(
            db=db,
            project_id=project.id,
            event_type=event_type.strip(),
            payload_data=parsed_data,
            idempotency_key=idempotency_key.strip() if idempotency_key else None
        )
    except Exception as e:
        return templates.TemplateResponse("events/send_test.html", {
            "request": request,
            "current_user": user,
            "current_project": project,
            "message": f"Event ingestion error: {e}",
            "message_type": "error"
        }, status_code=400)

    return RedirectResponse(url=f"/dashboard/events/{event.id}", status_code=303)

@router.get("/dashboard/events/{event_id}", response_class=HTMLResponse)
def event_detail_view(event_id: str, request: Request, db: Session = Depends(get_db)):
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

    return templates.TemplateResponse("events/detail.html", {
        "request": request,
        "current_user": user,
        "current_project": project,
        "event": event,
        "formatted_payload": formatted_payload
    })

# ================= DELIVERIES & DEAD LETTERS =================

@router.get("/dashboard/deliveries", response_class=HTMLResponse)
def list_deliveries(request: Request, status: Optional[str] = None, db: Session = Depends(get_db)):
    user, org, project = get_user_and_project(request, db)
    if not user or not project:
        return RedirectResponse(url="/auth/login", status_code=302)

    query = db.query(Delivery).join(Event, Delivery.event_id == Event.id).filter(Event.project_id == project.id)
    if status and status.strip():
        query = query.filter(Delivery.status == status.strip().upper())

    deliveries = query.order_by(Delivery.created_at.desc()).limit(50).all()
    dead_count = db.query(Delivery).join(Event, Delivery.event_id == Event.id).filter(Event.project_id == project.id, Delivery.status == "DEAD").count()

    return templates.TemplateResponse("deliveries/index.html", {
        "request": request,
        "current_user": user,
        "current_project": project,
        "deliveries": deliveries,
        "status_filter": status,
        "dead_count": dead_count
    })

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

    return templates.TemplateResponse("deliveries/detail.html", {
        "request": request,
        "current_user": user,
        "current_project": project,
        "delivery": delivery
    })

@router.post("/dashboard/deliveries/{delivery_id}/replay")
def replay_delivery_post(delivery_id: str, request: Request, db: Session = Depends(get_db)):
    user, org, project = get_user_and_project(request, db)
    if not user or not project:
        return RedirectResponse(url="/auth/login", status_code=302)

    new_delivery = replay_delivery(db, delivery_id)
    if not new_delivery:
        raise HTTPException(status_code=404, detail="Delivery could not be found to replay")

    return RedirectResponse(url=f"/dashboard/deliveries/{new_delivery.id}", status_code=303)

@router.get("/dashboard/dead-letters", response_class=HTMLResponse)
def list_dead_letters(request: Request, db: Session = Depends(get_db)):
    user, org, project = get_user_and_project(request, db)
    if not user or not project:
        return RedirectResponse(url="/auth/login", status_code=302)

    dead_deliveries = (
        db.query(Delivery)
        .join(Event, Delivery.event_id == Event.id)
        .filter(Event.project_id == project.id, Delivery.status == "DEAD")
        .order_by(Delivery.created_at.desc())
        .all()
    )

    return templates.TemplateResponse("deliveries/dead_letters.html", {
        "request": request,
        "current_user": user,
        "current_project": project,
        "deliveries": dead_deliveries
    })

@router.post("/dashboard/dead-letters/replay-all")
def replay_all_dead_letters(request: Request, db: Session = Depends(get_db)):
    user, org, project = get_user_and_project(request, db)
    if not user or not project:
        return RedirectResponse(url="/auth/login", status_code=302)

    dead_deliveries = (
        db.query(Delivery)
        .join(Event, Delivery.event_id == Event.id)
        .filter(Event.project_id == project.id, Delivery.status == "DEAD")
        .all()
    )

    for dlv in dead_deliveries:
        replay_delivery(db, dlv.id)

    from app.services.audit import log_audit_event
    client_ip = request.client.host if request.client else None
    log_audit_event(
        db=db,
        organization_id=org.id,
        user_id=user.id,
        action="delivery.replay_all",
        resource_type="delivery",
        ip_address=client_ip,
        details={"replayed_count": len(dead_deliveries)}
    )

    return RedirectResponse(url="/dashboard/deliveries", status_code=303)

# ================= API KEYS =================

@router.get("/dashboard/api-keys", response_class=HTMLResponse)
def list_api_keys(request: Request, new_key: Optional[str] = None, db: Session = Depends(get_db)):
    user, org, project = get_user_and_project(request, db)
    if not user or not project:
        return RedirectResponse(url="/auth/login", status_code=302)

    keys = db.query(ApiKey).filter(ApiKey.project_id == project.id).order_by(ApiKey.created_at.desc()).all()
    return templates.TemplateResponse("api_keys/index.html", {
        "request": request,
        "current_user": user,
        "current_project": project,
        "api_keys": keys,
        "new_key": new_key
    })

@router.post("/dashboard/api-keys")
def create_api_key_post(
    request: Request,
    name: str = Form(...),
    db: Session = Depends(get_db)
):
    user, org, project = get_user_and_project(request, db)
    if not user or not project:
        return RedirectResponse(url="/auth/login", status_code=302)

    full_key, key_prefix, key_hash = generate_api_key()
    api_key_obj = ApiKey(
        project_id=project.id,
        name=name.strip(),
        key_prefix=key_prefix,
        key_hash=key_hash
    )
    db.add(api_key_obj)
    db.commit()

    from app.services.audit import log_audit_event
    client_ip = request.client.host if request.client else None
    log_audit_event(
        db=db,
        organization_id=org.id,
        user_id=user.id,
        action="api_key.create",
        resource_type="api_key",
        resource_id=api_key_obj.id,
        ip_address=client_ip,
        details={"name": api_key_obj.name, "prefix": key_prefix}
    )

    return list_api_keys(request=request, new_key=full_key, db=db)

@router.post("/dashboard/api-keys/{key_id}/revoke")
def revoke_api_key_post(key_id: str, request: Request, db: Session = Depends(get_db)):
    user, org, project = get_user_and_project(request, db)
    if not user or not project:
        return RedirectResponse(url="/auth/login", status_code=302)

    key = db.query(ApiKey).filter(ApiKey.id == key_id, ApiKey.project_id == project.id).first()
    if key and key.is_active:
        key.revoked_at = utc_now()
        db.commit()

        from app.services.audit import log_audit_event
        client_ip = request.client.host if request.client else None
        log_audit_event(
            db=db,
            organization_id=org.id,
            user_id=user.id,
            action="api_key.revoke",
            resource_type="api_key",
            resource_id=key.id,
            ip_address=client_ip,
            details={"name": key.name, "prefix": key.key_prefix}
        )

    return RedirectResponse(url="/dashboard/api-keys", status_code=303)

# ================= AUDIT LOGS =================

@router.get("/dashboard/audit-logs", response_class=HTMLResponse)
def list_audit_logs(request: Request, db: Session = Depends(get_db)):
    user, org, project = get_user_and_project(request, db)
    if not user or not project:
        return RedirectResponse(url="/auth/login", status_code=302)

    from app.models.audit_log import AuditLog
    logs = (
        db.query(AuditLog)
        .filter(AuditLog.organization_id == org.id)
        .order_by(AuditLog.created_at.desc())
        .limit(100)
        .all()
    )

    return templates.TemplateResponse("audit_logs/index.html", {
        "request": request,
        "current_user": user,
        "current_project": project,
        "audit_logs": logs
    })

# ================= TEAM & INVITATIONS =================

@router.get("/dashboard/team", response_class=HTMLResponse)
def list_team(request: Request, db: Session = Depends(get_db)):
    user, org, project = get_user_and_project(request, db)
    if not user or not org:
        return RedirectResponse(url="/auth/login", status_code=302)

    from app.models.invitation import OrganizationInvitation
    members = db.query(OrganizationMember).filter(OrganizationMember.organization_id == org.id).all()
    invitations = db.query(OrganizationInvitation).filter(OrganizationInvitation.organization_id == org.id).order_by(OrganizationInvitation.created_at.desc()).all()

    return templates.TemplateResponse("team/index.html", {
        "request": request,
        "current_user": user,
        "current_project": project,
        "current_org": org,
        "members": members,
        "invitations": invitations
    })

@router.post("/dashboard/team/invite")
def invite_team_member(
    request: Request,
    email: str = Form(...),
    role: str = Form("member"),
    db: Session = Depends(get_db)
):
    user, org, project = get_user_and_project(request, db)
    if not user or not org:
        return RedirectResponse(url="/auth/login", status_code=302)

    # Enforce role hierarchy: only owner or admin can invite
    cur_membership = db.query(OrganizationMember).filter(
        OrganizationMember.organization_id == org.id,
        OrganizationMember.user_id == user.id
    ).first()

    if not cur_membership or cur_membership.role not in ("owner", "admin"):
        raise HTTPException(status_code=403, detail="Only organization owners and admins can invite team members.")

    email_clean = email.strip().lower()
    from app.models.invitation import OrganizationInvitation
    invitation = OrganizationInvitation(
        organization_id=org.id,
        email=email_clean,
        role=role if role in ("admin", "member") else "member",
        invited_by_user_id=user.id
    )
    db.add(invitation)
    db.commit()

    from app.services.audit import log_audit_event
    client_ip = request.client.host if request.client else None
    log_audit_event(
        db=db,
        organization_id=org.id,
        user_id=user.id,
        action="team.invite",
        resource_type="invitation",
        resource_id=invitation.id,
        ip_address=client_ip,
        details={"invitee_email": email_clean, "role": invitation.role}
    )

    return RedirectResponse(url="/dashboard/team", status_code=303)

@router.post("/dashboard/team/invitations/{inv_id}/revoke")
def revoke_invitation(inv_id: str, request: Request, db: Session = Depends(get_db)):
    user, org, _ = get_user_and_project(request, db)
    if not user or not org:
        return RedirectResponse(url="/auth/login", status_code=302)

    from app.models.invitation import OrganizationInvitation
    invitation = db.query(OrganizationInvitation).filter(
        OrganizationInvitation.id == inv_id,
        OrganizationInvitation.organization_id == org.id
    ).first()

    if invitation and invitation.status == "PENDING":
        invitation.status = "REVOKED"
        db.commit()

        from app.services.audit import log_audit_event
        client_ip = request.client.host if request.client else None
        log_audit_event(
            db=db,
            organization_id=org.id,
            user_id=user.id,
            action="team.revoke_invitation",
            resource_type="invitation",
            resource_id=invitation.id,
            ip_address=client_ip,
            details={"invitee_email": invitation.email}
        )

    return RedirectResponse(url="/dashboard/team", status_code=303)

@router.get("/auth/invitations/{token}", response_class=HTMLResponse)
def accept_invitation_page(token: str, request: Request, db: Session = Depends(get_db)):
    from app.models.invitation import OrganizationInvitation
    invitation = db.query(OrganizationInvitation).filter(OrganizationInvitation.token == token.strip()).first()
    if not invitation or not invitation.is_valid:
        return HTMLResponse("<p style='padding:40px;text-align:center;font-family:sans-serif;'>This invitation link is invalid or has expired.</p>", status_code=400)

    user = get_optional_user(request, db)
    return templates.TemplateResponse("team/accept_invitation.html", {
        "request": request,
        "invitation": invitation,
        "current_user": user
    })

@router.post("/auth/invitations/{token}/accept")
def accept_invitation_post(
    token: str,
    request: Request,
    password: Optional[str] = Form(None),
    db: Session = Depends(get_db)
):
    from app.models.invitation import OrganizationInvitation
    invitation = db.query(OrganizationInvitation).filter(OrganizationInvitation.token == token.strip()).first()
    if not invitation or not invitation.is_valid:
        return HTMLResponse("<p>This invitation link is invalid or has expired.</p>", status_code=400)

    user = get_optional_user(request, db)
    
    # If not logged in, find user by email or register new user
    if not user:
        user = db.query(User).filter(User.email == invitation.email.lower()).first()
        if not user:
            if not password or len(password) < 8:
                return templates.TemplateResponse("team/accept_invitation.html", {
                    "request": request,
                    "invitation": invitation,
                    "current_user": None,
                    "error": "Password must be at least 8 characters long."
                }, status_code=400)
            user = User(email=invitation.email.lower(), password_hash=hash_password(password))
            db.add(user)
            db.flush()

    # Add organization membership
    existing_mem = db.query(OrganizationMember).filter(
        OrganizationMember.organization_id == invitation.organization_id,
        OrganizationMember.user_id == user.id
    ).first()

    if not existing_mem:
        new_mem = OrganizationMember(
            organization_id=invitation.organization_id,
            user_id=user.id,
            role=invitation.role
        )
        db.add(new_mem)

    # Mark invitation as accepted
    invitation.status = "ACCEPTED"
    db.commit()

    # Log audit event
    from app.services.audit import log_audit_event
    client_ip = request.client.host if request.client else None
    log_audit_event(
        db=db,
        organization_id=invitation.organization_id,
        user_id=user.id,
        action="team.accept_invitation",
        resource_type="invitation",
        resource_id=invitation.id,
        ip_address=client_ip,
        details={"email": user.email, "role": invitation.role}
    )

    # Set session cookie and redirect
    session_token = create_session_token(user.id, org_id=invitation.organization_id)
    response = RedirectResponse(url="/dashboard", status_code=303)
    response.set_cookie("wh_session", session_token, httponly=True, max_age=86400 * 7, samesite="lax")
    return response
