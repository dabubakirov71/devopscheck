"""
Per-request custom DNS resolver.

Patches socket.getaddrinfo once at import time.  The patch is a no-op unless
a custom DNS server is active for the current thread (set via the
`custom_dns_server` context manager).  All other outbound connections (Stripe,
GitHub, NOWPayments …) are completely unaffected.
"""
import socket
import threading
from contextlib import contextmanager

_local = threading.local()
_orig_getaddrinfo = socket.getaddrinfo


def _is_ip(host):
    try:
        socket.inet_aton(host)
        return True
    except OSError:
        return False


def _patched_getaddrinfo(host, port, family=0, type=0, proto=0, flags=0):
    server = getattr(_local, 'server', None)
    if server and host and not _is_ip(host):
        try:
            import dns.resolver
            r = dns.resolver.Resolver()
            r.nameservers = [server]
            r.timeout = 4
            r.lifetime = 4
            ip = str(r.resolve(host, 'A')[0])
            return _orig_getaddrinfo(ip, port, family, type, proto, flags)
        except Exception:
            pass  # fall through to system DNS on any failure
    return _orig_getaddrinfo(host, port, family, type, proto, flags)


socket.getaddrinfo = _patched_getaddrinfo


@contextmanager
def custom_dns_server(server):
    """Temporarily route DNS for the current thread through *server* (IP str).

    Usage::

        with custom_dns_server(profile.custom_dns):
            requests.get(...)
    """
    _local.server = server or None
    try:
        yield
    finally:
        _local.server = None
