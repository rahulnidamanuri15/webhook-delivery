import ipaddress
import socket
from urllib.parse import urlparse, urlunparse
from typing import Tuple, Optional, Dict
from app.config import settings

def is_ip_prohibited(ip_str: str) -> bool:
    """Checks whether an IP address belongs to loopback, private, link-local, multicast, or reserved ranges."""
    try:
        ip = ipaddress.ip_address(ip_str)
        if (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_multicast
            or ip.is_reserved
            or ip.is_unspecified
        ):
            return True
        return False
    except ValueError:
        return True

def get_domain_allowlist() -> list[str]:
    """Parses ALLOWED_RECEIVER_DOMAINS (comma-separated) into lowercase domains."""
    raw = (settings.ALLOWED_RECEIVER_DOMAINS or "").strip()
    if not raw:
        return []
    return [d.strip().lower().lstrip(".") for d in raw.split(",") if d.strip()]


def is_domain_allowed(hostname: str) -> tuple[bool, str | None]:
    """Enforces the public-demo domain allowlist when configured.

    Exact match or subdomain match (e.g. allowlist 'example.com' permits
    'api.example.com'). Returns (allowed, error).
    """
    allowlist = get_domain_allowlist()
    if not allowlist:
        return True, None
    host = (hostname or "").lower()
    for allowed in allowlist:
        if host == allowed or host.endswith("." + allowed):
            return True, None
    return False, (
        f"Domain '{hostname}' is not in the configured receiver allowlist "
        f"({', '.join(allowlist)})."
    )

def validate_webhook_url(url: str) -> Tuple[bool, Optional[str]]:
    """
    Validates a destination URL against SSRF attacks (scheme, credentials, and DNS resolution).
    Returns:
        (is_valid: bool, error_message: Optional[str])
    """
    if not url or not isinstance(url, str):
        return False, "URL cannot be empty."

    try:
        parsed = urlparse(url.strip())
    except Exception:
        return False, "Malformed URL."

    allowed_schemes = ("http", "https") if (settings.DEBUG or settings.ALLOW_LOCAL_RECEIVERS) else ("https",)
    if parsed.scheme.lower() not in allowed_schemes:
        return False, f"URL scheme must be one of: {', '.join(allowed_schemes)}."

    if parsed.username or parsed.password:
        return False, "URLs with embedded credentials are not allowed."

    hostname = parsed.hostname
    if not hostname:
        return False, "URL must contain a valid hostname."

    # Public-demo domain allowlist (checked before localhost exception so that
    # a configured allowlist also restricts even local names unless listed).
    allowed, allow_err = is_domain_allowed(hostname)
    if not allowed:
        return False, allow_err

    # Allow localhost / 127.0.0.1 and Docker container hosts for local demo receiver in development
    local_hosts = ("localhost", "127.0.0.1", "::1", "demo_receiver", "webhook_demo_receiver", "host.docker.internal")
    if settings.ALLOW_LOCAL_RECEIVERS and hostname.lower() in local_hosts:
        return True, None

    # Resolve hostname to IP addresses and verify against restricted ranges
    try:
        addr_info = socket.getaddrinfo(hostname, None)
        if not addr_info:
            return False, "Could not resolve hostname."

        for family, _, _, _, sockaddr in addr_info:
            ip_str = sockaddr[0]
            if is_ip_prohibited(ip_str):
                return False, f"Destination IP {ip_str} is within a restricted or private network range."

    except socket.gaierror:
        return False, f"Hostname '{hostname}' could not be resolved."
    except Exception as e:
        return False, f"Network validation failed: {str(e)}"

    return True, None

def resolve_and_pin_destination(url: str) -> Tuple[bool, Optional[str], str, Dict[str, str]]:
    """
    DNS Rebinding Protection:
    Resolves the hostname, validates every resolved IP address against restricted ranges,
    and returns a direct IP-pinned connection target to prevent DNS rebinding between check and connection.

    Returns:
        (is_safe: bool, error: Optional[str], connection_url: str, pinned_headers: dict)
    """
    url = url.strip()
    is_valid, err = validate_webhook_url(url)
    if not is_valid:
        return False, err, url, {}

    parsed = urlparse(url)
    hostname = parsed.hostname

    # If already an IP or in dev demo mode allowing localhost / Docker hosts
    local_hosts = ("localhost", "127.0.0.1", "::1", "demo_receiver", "webhook_demo_receiver", "host.docker.internal")
    if settings.ALLOW_LOCAL_RECEIVERS and hostname.lower() in local_hosts:
        return True, None, url, {}

    try:
        # Resolve addresses right before outbound request
        addr_info = socket.getaddrinfo(hostname, parsed.port or (443 if parsed.scheme == "https" else 80))
        if not addr_info:
            return False, "Could not resolve destination IP.", url, {}

        # Validate all addresses
        for family, _, _, _, sockaddr in addr_info:
            ip_str = sockaddr[0]
            if is_ip_prohibited(ip_str):
                return False, f"DNS rebinding attack prevented: resolved IP {ip_str} is restricted.", url, {}

        # Pin to the first verified IP
        first_ip = addr_info[0][4][0]
        port_part = f":{parsed.port}" if parsed.port else ""
        pinned_netloc = f"[{first_ip}]{port_part}" if ":" in first_ip else f"{first_ip}{port_part}"
        
        # Replace hostname with pinned IP in target connection URL
        pinned_url = urlunparse((
            parsed.scheme,
            pinned_netloc,
            parsed.path or "/",
            parsed.params,
            parsed.query,
            parsed.fragment
        ))

        # Preserve original Host header
        headers = {"Host": parsed.netloc}
        return True, None, pinned_url, headers

    except Exception as e:
        return False, f"DNS resolution failed: {e}", url, {}
