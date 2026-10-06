from app.config import settings
from app.services.ssrf import is_ip_prohibited, validate_webhook_url


def test_ip_prohibited_ranges():
    # Loopback
    assert is_ip_prohibited("127.0.0.1") is True
    assert is_ip_prohibited("::1") is True
    # Private RFC1918
    assert is_ip_prohibited("10.0.0.1") is True
    assert is_ip_prohibited("172.16.0.1") is True
    assert is_ip_prohibited("192.168.1.1") is True
    # Link local & Cloud Metadata (AWS/GCP/Azure)
    assert is_ip_prohibited("169.254.169.254") is True
    # CGNAT (100.64.0.0/10) & reserved
    assert is_ip_prohibited("100.64.0.1") is True
    assert is_ip_prohibited("0.0.0.0") is True
    assert is_ip_prohibited("198.51.100.1") is True
    # Public IP
    assert is_ip_prohibited("8.8.8.8") is False
    assert is_ip_prohibited("1.1.1.1") is False

def test_url_validation_embedded_credentials():
    valid, err = validate_webhook_url("https://user:pass@example.com/webhook")
    assert valid is False
    assert "embedded credentials" in err

def test_url_validation_disallowed_scheme():
    valid, err = validate_webhook_url("ftp://example.com/webhook")
    assert valid is False
    assert "scheme" in err

def test_url_validation_localhost_with_dev_override():
    # With ALLOW_LOCAL_RECEIVERS = True
    settings.ALLOW_LOCAL_RECEIVERS = True
    valid, err = validate_webhook_url("http://127.0.0.1:8001/webhook")
    assert valid is True
    assert err is None

    # With ALLOW_LOCAL_RECEIVERS = False (Production mode)
    settings.ALLOW_LOCAL_RECEIVERS = False
    valid, err = validate_webhook_url("http://127.0.0.1:8001/webhook")
    assert valid is False
    assert "restricted or private network range" in err or "scheme" in err

    # Restore setting
    settings.ALLOW_LOCAL_RECEIVERS = True

def test_https_pinning_preserves_sni_and_url():
    from unittest.mock import patch
    from app.services.ssrf import resolve_and_pin_destination

    mock_addr = [(2, 1, 6, "", ("93.184.216.34", 443))]
    with patch("socket.getaddrinfo", return_value=mock_addr):
        res = resolve_and_pin_destination("https://example.com/webhook")
        assert res.is_safe is True
        assert res.url == "https://example.com/webhook"
        assert res.headers["Host"] == "example.com"
        assert res.pinned_ip == "93.184.216.34"

