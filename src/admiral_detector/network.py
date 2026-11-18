import contextlib
import ipaddress
import logging
import socket
import threading
from typing import Optional
import dns.resolver
import httpx

logger = logging.getLogger("AdmiralDetector")

DEFAULT_NETWORK_TIMEOUT = 15
DEFAULT_NETWORK_REDIRECTS = 5

_dns_local = threading.local()
_orig_getaddrinfo = socket.getaddrinfo


def _resolve_with_dns(host: str, dns_server: str) -> str:
    resolver = dns.resolver.Resolver(configure=False)
    if(":" in dns_server and not dns_server.startswith("[")):
        host_part, port_part = dns_server.rsplit(":", 1)
        resolver.nameservers = [host_part]
        resolver.port = int(port_part)
    else:
        resolver.nameservers = [dns_server]

    for record_type in ("A", "AAAA"):
        try:
            answers = resolver.resolve(host, record_type)
            for rdata in answers:
                resolved = rdata.to_text()
                logger.debug(f"Custom DNS ({dns_server}) resolved {host} -> {resolved} ({record_type})")
                return resolved
        except Exception:
            continue

    raise socket.gaierror(f"Custom DNS ({dns_server}) failed to resolve hostname: {host}")


def _patched_getaddrinfo(host, port, family=0, type=0, proto=0, flags=0):
    dns_server = getattr(_dns_local, "nameserver", None)
    if(not dns_server or not isinstance(host, str)):
        return _orig_getaddrinfo(host, port, family, type, proto, flags)

    try:
        ipaddress.ip_address(host)
        return _orig_getaddrinfo(host, port, family, type, proto, flags)
    except ValueError:
        pass

    resolved_ip = _resolve_with_dns(host, dns_server)
    return _orig_getaddrinfo(resolved_ip, port, family, type, proto, flags)


socket.getaddrinfo = _patched_getaddrinfo


@contextlib.contextmanager
def use_dns(dns_server: Optional[str]):
    previous = getattr(_dns_local, "nameserver", None)
    _dns_local.nameserver = dns_server
    try:
        yield
    finally:
        _dns_local.nameserver = previous


def create_http_client(
    timeout_seconds: int = DEFAULT_NETWORK_TIMEOUT,
    max_redirects: int = DEFAULT_NETWORK_REDIRECTS,
    proxy: Optional[str] = None,
    verify_ssl: bool = True,
) -> httpx.Client:
    return httpx.Client(
        proxy=proxy,
        timeout=timeout_seconds,
        max_redirects=max_redirects,
        follow_redirects=True,
        verify=verify_ssl,
    )
