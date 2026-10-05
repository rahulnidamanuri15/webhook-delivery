import pytest
from app.services.ssrf import validate_webhook_url, is_ip_prohibited
from app.config import settings

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
