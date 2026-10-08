import uuid

import pytest
from fastapi.testclient import TestClient

from app.db.session import SessionLocal
from app.main import app
from app.models import (
    ApiKey,
    Delivery,
    Endpoint,
    EndpointSubscription,
    Organization,
    OrganizationMember,
    Project,
    User,
)
from app.services.event_service import ingest_event
from app.services.security import (
    create_session_token,
    encrypt_secret,
    generate_api_key,
    generate_signing_secret,
    hash_password,
)

client = TestClient(app)


@pytest.fixture
def htmx_test_data():
    db = SessionLocal()
    uid = uuid.uuid4().hex[:8]

    # Organization & Project A
    org_a = Organization(name=f"HTMX Org A {uid}")
    db.add(org_a)
    db.flush()

    user_a = User(email=f"htmx_a_{uid}@test.com", password_hash=hash_password("password123"))
    db.add(user_a)
    db.flush()
    db.add(OrganizationMember(organization_id=org_a.id, user_id=user_a.id, role="owner"))

    proj_a = Project(organization_id=org_a.id, name=f"HTMX Proj A {uid}")
    db.add(proj_a)
    db.flush()

    full_key_a, prefix_a, hash_a = generate_api_key()
    api_key_a = ApiKey(project_id=proj_a.id, name="Key A", key_prefix=prefix_a, key_hash=hash_a)
    db.add(api_key_a)

    ep_a = Endpoint(
        project_id=proj_a.id,
        url=f"http://127.0.0.1:8001/webhook-ui-a-{uid}",
        encrypted_signing_secret=encrypt_secret(generate_signing_secret()),
        enabled=True,
    )
    db.add(ep_a)
    db.flush()
    db.add(EndpointSubscription(endpoint_id=ep_a.id, event_type="order.*"))

    # Organization & Project B (for cross-tenant tests)
    org_b = Organization(name=f"HTMX Org B {uid}")
    db.add(org_b)
    db.flush()

    user_b = User(email=f"htmx_b_{uid}@test.com", password_hash=hash_password("password123"))
    db.add(user_b)
    db.flush()
    db.add(OrganizationMember(organization_id=org_b.id, user_id=user_b.id, role="owner"))

    proj_b = Project(organization_id=org_b.id, name=f"HTMX Proj B {uid}")
    db.add(proj_b)
    db.flush()

    db.commit()

    # Ingest event for Project A
    event_a, _, _ = ingest_event(
        db=db,
        project_id=proj_a.id,
        event_type="order.shipped",
        payload_data={"order_id": f"ord_{uid}", "tracking": "XYZ123"},
    )
    delivery_a = db.query(Delivery).filter(Delivery.event_id == event_a.id).first()

    session_a = create_session_token(user_a.id, org_id=org_a.id)
    session_b = create_session_token(user_b.id, org_id=org_b.id)

    db_context = {
        "user_a": user_a,
        "org_a": org_a,
        "proj_a": proj_a,
        "session_a": session_a,
        "delivery_a": delivery_a,
        "event_a": event_a,
        "user_b": user_b,
        "org_b": org_b,
        "proj_b": proj_b,
        "session_b": session_b,
    }
    yield db_context
    db.close()


def test_dashboard_page_renders_with_charts_and_kpis(htmx_test_data):
    """Verify main dashboard loads with HyperUI KPI cards and SVG chart elements."""
    response = client.get(
        "/dashboard",
        cookies={"wh_session": htmx_test_data["session_a"]},
    )
    assert response.status_code == 200
    html = response.text
    # Should include KPI metric headers
    assert "Total Deliveries" in html
    assert "Eventual Success Rate" in html
    assert "Deliveries Due" in html
    # Should include HTMX auto-poll container and drawer host container
    assert 'id="deliveries-table-container"' in html
    assert 'id="inspector-drawer-container"' in html


def test_htmx_metrics_chart_partial(htmx_test_data):
    """Verify HTMX endpoint /dashboard/metrics/chart returns dynamic SVG curves and donut chart."""
    for r in ["1h", "24h", "7d", "30d"]:
        response = client.get(
            f"/dashboard/metrics/chart?range={r}",
            cookies={"wh_session": htmx_test_data["session_a"]},
        )
        assert response.status_code == 200
        html = response.text
        # Assert SVG curve & charts are present
        assert "<svg" in html
        assert "Latency Breakdown" in html
        assert "Avg Round-trip" in html
        assert "Outcome Distribution" in html


def test_htmx_deliveries_table_partial(htmx_test_data):
    """Verify HTMX endpoint /dashboard/deliveries/table returns live rows with slide-over triggers."""
    delivery = htmx_test_data["delivery_a"]
    response = client.get(
        "/dashboard/deliveries/table",
        cookies={"wh_session": htmx_test_data["session_a"]},
    )
    assert response.status_code == 200
    html = response.text
    # Check that table contains the delivery ID and HTMX drawer trigger
    assert delivery.id in html
    assert f'hx-get="/dashboard/deliveries/{delivery.id}/drawer"' in html
    assert 'hx-target="#inspector-drawer-content"' in html


def test_htmx_deliveries_table_search_filter(htmx_test_data):
    """Verify debounced search filtering works on the HTMX partial."""
    delivery = htmx_test_data["delivery_a"]

    # Filter with match
    resp_match = client.get(
        f"/dashboard/deliveries/table?q={delivery.id[:8]}",
        cookies={"wh_session": htmx_test_data["session_a"]},
    )
    assert resp_match.status_code == 200
    assert delivery.id in resp_match.text

    # Filter with non-matching query
    resp_empty = client.get(
        "/dashboard/deliveries/table?q=non_existent_payload_query_xyz",
        cookies={"wh_session": htmx_test_data["session_a"]},
    )
    assert resp_empty.status_code == 200
    assert "No deliveries found" in resp_empty.text


def test_htmx_inspector_drawer_details(htmx_test_data):
    """Verify slide-over drawer returns full Svix/Stripe payload inspection, headers, and tabs."""
    delivery = htmx_test_data["delivery_a"]

    response = client.get(
        f"/dashboard/deliveries/{delivery.id}/drawer",
        cookies={"wh_session": htmx_test_data["session_a"]},
    )
    assert response.status_code == 200
    html = response.text

    # Drawer tabs & details
    assert "Request Envelope" in html
    assert "Response" in html
    assert "Attempt Timeline" in html
    assert "Wire Payload Body" in html
    assert delivery.endpoint.url in html
    assert "order.shipped" in html
    assert "ord_" in html  # Payload excerpt
    assert "Open in Full Page" in html

    # Verify that when status is DEAD, the Replay button is rendered
    db = SessionLocal()
    deliv_record = db.query(Delivery).filter(Delivery.id == delivery.id).first()
    deliv_record.status = "DEAD"
    db.commit()
    db.close()

    resp_dead = client.get(
        f"/dashboard/deliveries/{delivery.id}/drawer",
        cookies={"wh_session": htmx_test_data["session_a"]},
    )
    assert resp_dead.status_code == 200
    assert "Replay Delivery" in resp_dead.text


def test_htmx_inspector_drawer_cross_tenant_isolation(htmx_test_data):
    """Verify User B cannot inspect Delivery A via the drawer endpoint (returns 404)."""
    delivery_a = htmx_test_data["delivery_a"]

    response = client.get(
        f"/dashboard/deliveries/{delivery_a.id}/drawer",
        cookies={"wh_session": htmx_test_data["session_b"]},
    )
    assert response.status_code == 404


def test_csp_allows_htmx_eval_and_chartjs(htmx_test_data):
    """Verify CSP headers allow 'unsafe-eval' for HTMX and Chart.js."""
    response = client.get(
        "/dashboard",
        cookies={"wh_session": htmx_test_data["session_a"]},
    )
    assert response.status_code == 200
    csp = response.headers.get("Content-Security-Policy", "")
    assert "'unsafe-eval'" in csp
    assert "'unsafe-inline'" in csp
    # Script tag for chart.js must not have defer (to ensure it is ready before inline body scripts execute)
    assert '<script src="/static/js/chart.umd.min.js"></script>' in response.text


def test_favicon_endpoint():
    """Verify favicon endpoint exists and returns 204 No Content."""
    response = client.get("/favicon.ico")
    assert response.status_code == 204
