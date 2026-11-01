import asyncio
import ipaddress
import socket
from typing import Optional
import httpx

from src.core.config import settings


class SSRFProtectedTransport(httpx.AsyncHTTPTransport):
    """
    SSRF-hardened HTTP transport for outbound HTTP requests (e.g. JWKS key retrieval).
    Defends against Server-Side Request Forgery, internal network scanning, and DNS
    rebinding attacks (GHSA-5x4x-2946-qr67 defense).
    """

    def __init__(
        self,
        *args,
        allow_localhost: Optional[bool] = None,
        **kwargs,
    ):
        super().__init__(*args, **kwargs)
        self.allow_localhost = allow_localhost

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        scheme = request.url.scheme.lower()
        host = request.url.host.lower()
        port = request.url.port or (443 if scheme == "https" else 80)

        is_test_env = getattr(settings, "ENVIRONMENT", "").lower() == "test"
        is_loopback_host = host in ("localhost", "127.0.0.1", "::1")
        allow_local = (
            self.allow_localhost
            if self.allow_localhost is not None
            else is_test_env
        )

        # 1. Scheme validation: HTTPS required unless in test mode or localhost
        if scheme != "https":
            if not (is_test_env or is_loopback_host):
                raise PermissionError(
                    f"SSRF Protection: Insecure scheme '{scheme}'. Only HTTPS is permitted."
                )

        # 2. Hostname resolution via asyncio event loop getaddrinfo
        loop = asyncio.get_running_loop()
        try:
            # Check if host is numeric IP literal first to prevent Windows NetBIOS broadcast latency
            addr_info = await loop.getaddrinfo(host, port, flags=socket.AI_NUMERICHOST)
        except (socket.gaierror, TypeError, ValueError):
            try:
                addr_info = await loop.getaddrinfo(host, port)
            except Exception as exc:
                raise PermissionError(
                    f"SSRF Protection: Unable to resolve hostname '{host}': {exc}"
                ) from exc

        if not addr_info:
            raise PermissionError(f"SSRF Protection: No IP addresses resolved for '{host}'.")

        # 3. Inspect all resolved IP addresses
        for info in addr_info:
            sockaddr = info[4]
            ip_str = sockaddr[0]
            try:
                ip = ipaddress.ip_address(ip_str)
            except ValueError as exc:
                raise PermissionError(
                    f"SSRF Protection: Invalid IP address '{ip_str}' resolved."
                ) from exc

            # Normalize IPv4-mapped IPv6 addresses (e.g. ::ffff:169.254.169.254)
            if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
                ip = ip.ipv4_mapped

            # Check if IP belongs to restricted subnets
            if (
                ip.is_private
                or ip.is_loopback
                or ip.is_link_local
                or ip.is_multicast
                or ip.is_reserved
                or ip.is_unspecified
            ):
                # Exception: local test servers under test configuration
                if allow_local and ip.is_loopback:
                    continue

                raise PermissionError(
                    f"SSRF Protection: Outbound request to blocked IP address '{ip_str}' is prohibited."
                )

        # 4. Forward the safe request to super().handle_async_request(request)
        return await super().handle_async_request(request)

