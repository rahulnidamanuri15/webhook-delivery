from app.config import settings
from app.services.ssrf import resolve_and_pin_destination


def test_resolve_and_pin_public_domain():
    settings.ALLOW_LOCAL_RECEIVERS = True
    # Test localhost pinning
    is_safe, err, pinned_url, headers = resolve_and_pin_destination("http://127.0.0.1:8001/webhook")
    assert is_safe is True
    assert err is None
    assert "8001" in pinned_url


def test_resolve_and_pin_blocks_forbidden():
    settings.ALLOW_LOCAL_RECEIVERS = False
    is_safe, err, pinned_url, headers = resolve_and_pin_destination("http://10.0.0.1:8000/webhook")
    assert is_safe is False
    assert "restricted or private network range" in err or "scheme" in err
    settings.ALLOW_LOCAL_RECEIVERS = True
