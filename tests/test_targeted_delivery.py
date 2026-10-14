"""Targeted delivery: publish to selected endpoints or all matches."""

import json
import uuid
from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient

from app.config import settings as _s
from app.db.session import SessionLocal
from app.main import app
from app.models import Delivery, Endpoint, EndpointSubscription, Organization, OrganizationMember, Project, User
from app.models import Event as EventModel
from app.services.delivery_service import replay_delivery
from app.services.event_service import ingest_event
from app.services.security import create_session_token, encrypt_secret, get_csrf_token_for_request, hash_password


def _project_with_endpoints(db, uid: str, patterns: list[str]):
    u = User(email=f"t_{uid}@example.com", password_hash=hash_password("Password123!"), status="approved")
    db.add(u)
    db.flush()
    o = Organization(name=f"T Org {uid}")
    db.add(o)
    db.flush()
    db.add(OrganizationMember(organization_id=o.id, user_id=u.id, role="owner"))
    p = Project(organization_id=o.id, name="P")
    db.add(p)
    db.flush()
    eps = []
    for i, pat in enumerate(patterns):
        ep = Endpoint(
            project_id=p.id,
            url=f"https://recv-{uid}-{i}.example.com/hook",
            encrypted_signing_secret=encrypt_secret(f"secret-{uid}-{i}-1234567890"),
            enabled=True,
        )
        db.add(ep)
        db.flush()
        db.add(EndpointSubscription(endpoint_id=ep.id, event_type=pat))
        eps.append(ep)
    db.commit()
    return u, o, p, eps


def test_service_targets_selected_endpoints():
    db = SessionLocal()
    uid = uuid.uuid4().hex[:8]
    try:
        _, _, p, eps = _project_with_endpoints(db, uid, ["payment.succeeded", "payment.succeeded"])
        _, _, count_all = ingest_event(db, p.id, "payment.succeeded", {"a": 1}, idempotency_key=f"k-{uid}-1")
        assert count_all == 2
        _, _, count_one = ingest_event(
            db, p.id, "payment.succeeded", {"a": 2}, idempotency_key=f"k-{uid}-2", endpoint_ids=[eps[0].id]
        )
        assert count_one == 1
    finally:
        db.close()


def test_service_rejects_unknown_or_empty_selection():
    db = SessionLocal()
    uid = uuid.uuid4().hex[:8]
    try:
        _, _, p, _ = _project_with_endpoints(db, uid, ["*"])
        with pytest.raises(ValueError, match="unknown endpoint"):
            ingest_event(db, p.id, "x.y", {"a": 1}, endpoint_ids=["ep_nope"])
        with pytest.raises(ValueError, match="at least one endpoint"):
            ingest_event(db, p.id, "x.y", {"a": 1}, endpoint_ids=[])
    finally:
        db.close()


def test_dashboard_publish_selected(monkeypatch):
    monkeypatch.setattr(_s, "ALLOW_PENDING_REGISTRATION", False)
    db = SessionLocal()
    client = TestClient(app)
    uid = uuid.uuid4().hex[:8]
    try:
        u, o, p, eps = _project_with_endpoints(db, uid, ["*", "*"])
        tok = create_session_token(u.id, org_id=o.id)
        mock_req = MagicMock()
        mock_req.cookies = {"wh_session": tok}
        csrf, _ = get_csrf_token_for_request(mock_req)
        res = client.post(
            "/dashboard/events/send-test",
            data={
                "event_type": "payment.succeeded",
                "idempotency_key": f"dash-{uid}",
                "payload_data": json.dumps({"a": 1}),
                "target_mode": "selected",
                "endpoint_ids": eps[1].id,
                "csrf_token": csrf,
            },
            cookies={"wh_session": tok},
            follow_redirects=False,
        )
        assert res.status_code == 303
        loc = res.headers["location"]
        detail = client.get(loc, cookies={"wh_session": tok})
        assert detail.status_code == 200
        assert eps[1].url in detail.text
        assert eps[0].url not in detail.text
    finally:
        db.close()


def _dead_delivery(db, project_id: str, endpoint_id: str | None, url: str):
    evt = db.query(EventModel).filter_by(project_id=project_id).first()
    if evt is None:
        evt = EventModel(
            project_id=project_id, event_type="t.replay", payload_json="{}",
            wire_payload="{}", request_hash="h-replay",
        )
        db.add(evt)
        db.flush()
    d = Delivery(
        event_id=evt.id,
        endpoint_id=endpoint_id,
        target_url_snapshot=url,
        status="DEAD",
        attempt_count=5,
    )
    db.add(d)
    db.commit()
    return d


def test_replay_defaults_to_same_endpoint():
    db = SessionLocal()
    uid = uuid.uuid4().hex[:8]
    try:
        _, _, p, eps = _project_with_endpoints(db, uid, ["*"])
        d = _dead_delivery(db, p.id, eps[0].id, eps[0].url)
        new = replay_delivery(db, d.id)
        assert new is not None
        assert new.endpoint_id == eps[0].id
        assert new.target_url_snapshot == eps[0].url
        assert new.replay_of_delivery_id == d.id
    finally:
        db.close()


def test_replay_can_retarget_different_endpoint():
    db = SessionLocal()
    uid = uuid.uuid4().hex[:8]
    try:
        _, _, p, eps = _project_with_endpoints(db, uid, ["*", "*"])
        d = _dead_delivery(db, p.id, eps[0].id, eps[0].url)
        new = replay_delivery(db, d.id, new_endpoint_id=eps[1].id)
        assert new is not None
        assert new.endpoint_id == eps[1].id
        assert new.target_url_snapshot == eps[1].url
    finally:
        db.close()


def test_replay_rejects_foreign_endpoint():
    db = SessionLocal()
    uid = uuid.uuid4().hex[:8]
    try:
        _, _, p, eps = _project_with_endpoints(db, uid, ["*"])
        _, _, p2, eps2 = _project_with_endpoints(db, uid + "b", ["*"])
        d = _dead_delivery(db, p.id, eps[0].id, eps[0].url)
        with pytest.raises(ValueError, match="unknown endpoint"):
            replay_delivery(db, d.id, new_endpoint_id=eps2[0].id)
    finally:
        db.close()


def test_dashboard_replay_page_and_retarget(monkeypatch):
    monkeypatch.setattr(_s, "ALLOW_PENDING_REGISTRATION", False)
    db = SessionLocal()
    client = TestClient(app)
    uid = uuid.uuid4().hex[:8]
    try:
        u, o, p, eps = _project_with_endpoints(db, uid, ["*", "*"])
        d = _dead_delivery(db, p.id, eps[0].id, eps[0].url)
        tok = create_session_token(u.id, org_id=o.id)
        mock_req = MagicMock()
        mock_req.cookies = {"wh_session": tok}
        csrf, _ = get_csrf_token_for_request(mock_req)
        page = client.get(f"/dashboard/deliveries/{d.id}/replay", cookies={"wh_session": tok})
        assert page.status_code == 200
        assert eps[0].url in page.text and eps[1].url in page.text
        res = client.post(
            f"/dashboard/deliveries/{d.id}/replay",
            data={"endpoint_id": eps[1].id, "csrf_token": csrf},
            cookies={"wh_session": tok},
            follow_redirects=False,
        )
        assert res.status_code == 303
        db.expire_all()
        new = db.query(Delivery).filter(Delivery.replay_of_delivery_id == d.id).first()
        assert new is not None and new.target_url_snapshot == eps[1].url
    finally:
        db.close()
