import concurrent.futures as _futures
import ipaddress
import socket
from urllib.parse import urlparse

from app.config import settings


def _getaddrinfo_timeout(host: str, port: int | None, timeout: float | None = None):
    """DNS with wall-clock timeout (prevents slow-DNS DoS in request path)."""
    if timeout is None:
        try:
            timeout = float(getattr(settings, "DNS_RESOLVE_TIMEOUT_SECONDS", 3.0))
        except Exception:
            timeout = 3.0
    with _futures.ThreadPoolExecutor(max_workers=1) as pool:
        fut = pool.submit(socket.getaddrinfo, host, port)
        try:
            return fut.result(timeout=timeout)
        except _futures.TimeoutError:
            raise socket.gaierror(f"DNS resolution timed out after {timeout}s for '{host}'")


def is_ip_prohibited(ip_str: str) -> bool:
    """Checks whether an IP address belongs to loopback, private, link-local, multicast, or non-global ranges."""
    try:
        ip = ipaddress.ip_address(ip_str)
        return not ip.is_global
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
    return False, (f"Domain '{hostname}' is not in the configured receiver allowlist " f"({', '.join(allowlist)}).")


LOCAL_HOSTS = ("localhost", "127.0.0.1", "::1", "demo_receiver", "webhook_demo_receiver", "host.docker.internal")


def _validate_url_syntax_and_domain(url: str):
    """Performs URL syntax, scheme, credential, length, and domain checks without DNS."""
    if not url or not isinstance(url, str):
        return False, "URL cannot be empty.", None

    url = url.strip()
    if not url:
        return False, "URL cannot be empty.", None

    try:
        parsed = urlparse(url)
    except Exception:
        return False, "Malformed URL.", None

    scheme = (parsed.scheme or "").lower()
    if not scheme:
        return (
            False,
            "URL must start with https:// (e.g. https://api.example.com/webhook). "
            "Did you forget the scheme? http:// is only allowed for local testing.",
            parsed,
        )

    is_prod = False
    try:
        from app.config import is_production_env as _is_prod_env

        is_prod = bool(_is_prod_env(getattr(settings, "ENV", "")))
    except Exception:
        is_prod = str(getattr(settings, "ENV", "") or "").strip().lower() == "production"
    allow_http = bool(settings.DEBUG or settings.ALLOW_LOCAL_RECEIVERS or not is_prod)
    allowed_schemes = ("http", "https") if allow_http else ("https",)
    if scheme not in allowed_schemes:
        if scheme == "http":
            return (
                False,
                "Only https:// URLs are allowed. "
                "Use an https:// receiver URL, or for local testing set "
                "ALLOW_LOCAL_RECEIVERS=True in .env (and restart) to allow "
                "http:// loopback receivers such as http://127.0.0.1:8001/webhook.",
                parsed,
            )
        return (
            False,
            f"URL scheme must be one of: {', '.join(allowed_schemes)}. "
            "Use an https:// URL (http:// is only for local testing).",
            parsed,
        )

    if parsed.username or parsed.password:
        return False, "URLs with embedded credentials are not allowed.", parsed

    hostname = parsed.hostname
    if not hostname:
        return False, "URL must contain a valid hostname.", parsed

    is_local = hostname.lower() in LOCAL_HOSTS
    # Loopback receivers are explicitly opted-in via ALLOW_LOCAL_RECEIVERS and
    # bypass the public-demo domain allowlist (they are still gated below by
    # the ALLOW_LOCAL_RECEIVERS check + scheme policy).
    if not (is_local and settings.ALLOW_LOCAL_RECEIVERS):
        allowed, allow_err = is_domain_allowed(hostname)
        if not allowed:
            return (
                False,
                f"{allow_err} "
                "Add the domain to ALLOWED_RECEIVER_DOMAINS in .env, or clear "
                "ALLOWED_RECEIVER_DOMAINS (empty disables the allowlist) for local dev.",
                parsed,
            )

    # Length + label guards (avoid tiny DoS via 2KB hostnames / deep labels)
    if len(hostname) > 253 or len(url) > 2048:
        return False, "URL or hostname too long.", parsed

    return True, None, parsed


def validate_webhook_url(url: str) -> tuple[bool, str | None]:
    """Validates a destination URL against SSRF attacks (scheme, credentials, and DNS resolution).

    Returns:
        (is_valid: bool, error_message: Optional[str])
    """
    ok, err, parsed = _validate_url_syntax_and_domain(url)
    if not ok:
        return False, err

    hostname = parsed.hostname
    if settings.ALLOW_LOCAL_RECEIVERS and hostname.lower() in LOCAL_HOSTS:
        return True, None

    # Resolve hostname to IP addresses and verify against restricted ranges
    try:
        addr_info = _getaddrinfo_timeout(hostname, None)
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


class PinnedResolutionResult(tuple):
    """Result tuple supporting 4-tuple unpacking (is_safe, error, url, headers)
    for backward-compatibility, while also exposing pinned_ip and error_kind.

    error_kind: None when safe, else "transient" (DNS timeout/unresolved —
    safe to retry) or "permanent" (SSRF forbidden / config — dead-letter).
    """

    def __new__(
        cls,
        is_safe: bool,
        error: str | None,
        url: str,
        headers: dict[str, str],
        pinned_ip: str | None = None,
        error_kind: str | None = None,
    ):
        return super().__new__(cls, (is_safe, error, url, headers))

    def __init__(
        self,
        is_safe: bool,
        error: str | None,
        url: str,
        headers: dict[str, str],
        pinned_ip: str | None = None,
        error_kind: str | None = None,
    ):
        self.is_safe = is_safe
        self.error = error
        self.url = url
        self.headers = headers
        self.pinned_ip = pinned_ip
        self.error_kind = error_kind

    @property
    def is_transient(self) -> bool:
        return not self.is_safe and self.error_kind == "transient"


def resolve_and_pin_destination(url: str) -> PinnedResolutionResult:
    """DNS Rebinding Protection:
    Resolves the hostname once, validates every resolved IP address against restricted
    non-global ranges, and returns a PinnedResolutionResult with verified pinned IP.
    Single resolution eliminates double-DNS TOCTOU rebinding vulnerability.

    Returns:
        PinnedResolutionResult(is_safe, error, connection_url, pinned_headers, pinned_ip)
    """
    url = url.strip()
    ok, err, parsed = _validate_url_syntax_and_domain(url)
    if not ok:
        return PinnedResolutionResult(False, err, url, {}, error_kind="permanent")

    hostname = parsed.hostname
    if settings.ALLOW_LOCAL_RECEIVERS and hostname and hostname.lower() in LOCAL_HOSTS:
        return PinnedResolutionResult(True, None, url, {"Host": parsed.netloc}, None)

    try:
        # Resolve addresses ONCE right before outbound request (bounded timeout)
        addr_info = _getaddrinfo_timeout(hostname, parsed.port or (443 if parsed.scheme == "https" else 80))
        if not addr_info:
            return PinnedResolutionResult(False, "Could not resolve destination IP.", url, {}, error_kind="transient")

        # Validate all addresses from this single resolution
        for family, _, _, _, sockaddr in addr_info:
            ip_str = sockaddr[0]
            if is_ip_prohibited(ip_str):
                return PinnedResolutionResult(
                    False,
                    f"Destination IP {ip_str} is within a restricted or private network range.",
                    url,
                    {},
                    error_kind="permanent",
                )

        # Pin to the first verified IP
        first_ip = addr_info[0][4][0]
        # Preserve original URL so HTTPS TLS SNI / certificate validation check against hostname
        headers = {"Host": parsed.netloc}
        return PinnedResolutionResult(True, None, url, headers, pinned_ip=first_ip)

    except socket.gaierror as e:
        msg = str(e) or ""
        # DNS timeouts / transient resolver blips are retryable; unknown-host
        # for a well-formed public name is usually transient too (DNS propagation).
        # Truly forbidden destinations are already rejected above via IP checks.
        if "timed out" in msg or "could not be resolved" in msg.lower() or "temporary" in msg.lower():
            return PinnedResolutionResult(False, f"DNS transient failure for '{hostname}': {e}", url, {}, error_kind="transient")
        return PinnedResolutionResult(False, f"Hostname '{hostname}' could not be resolved.", url, {}, error_kind="transient")
    except Exception as e:
        return PinnedResolutionResult(False, f"DNS resolution failed: {e}", url, {}, error_kind="transient")
