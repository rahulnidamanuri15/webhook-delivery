from app.services.event_service import _subscription_matches


def test_unit_matching():
    assert _subscription_matches("*", "a.b")
    assert _subscription_matches("order.*", "order.shipped")
    assert not _subscription_matches("order.*", "payment.succeeded")
