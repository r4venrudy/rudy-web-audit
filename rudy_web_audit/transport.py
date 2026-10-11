"""Resolve once, validate every address, and connect to a pinned address."""

import hashlib
import http.client
import ipaddress
import re
import socket
import ssl
import time
from datetime import datetime, timezone
from urllib.parse import parse_qsl, quote, urlencode, urlsplit, urlunsplit

from . import __version__
from .models import Hop


class AuditError(Exception):
    """An expected target, policy, or network failure."""


def normalize_url(value: str) -> str:
    value = value.strip()
    if not value or len(value) > 4096 or re.search(r"[\x00-\x20\x7f]", value):
        raise AuditError("URL is empty, too long, or contains whitespace/control characters.")
    if "://" not in value:
        value = "https://" + value
    try:
        parts = urlsplit(value)
        if parts.scheme not in {"http", "https"}:
            raise AuditError("Only http:// and https:// targets are supported.")
        if parts.username is not None or parts.password is not None:
            raise AuditError("Credentials in URLs are not supported.")
        host = (parts.hostname or "").encode("idna").decode("ascii").lower().rstrip(".")
        if not host or "%" in host or "\\" in host:
            raise AuditError("Target has an invalid hostname.")
        try:
            ipaddress.ip_address(host)
        except ValueError:
            if len(host) > 253 or any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
                                     for label in host.split(".")):
                raise AuditError("Target has an invalid hostname.")
        port = parts.port
        if port is not None and not 1 <= port <= 65535:
            raise AuditError("Port must be between 1 and 65535.")
        authority = f"[{host}]" if ":" in host else host
        if port and port != (443 if parts.scheme == "https" else 80):
            authority += f":{port}"
        path = quote(parts.path or "/", safe="/%:@!$&'()*+,;=-._~")
        query = quote(parts.query, safe="%=&;/:?@!$'()*+,-._~")
        return urlunsplit((parts.scheme, authority, path, query, ""))
    except (ValueError, UnicodeError) as exc:
        raise AuditError("Target has an invalid URL or port.") from exc


def display_url(url: str) -> str:
    """Query values are never exported. URL paths may still be sensitive."""
    parts = urlsplit(url)
    query = urlencode([(key, "[redacted]") for key, _ in parse_qsl(parts.query, keep_blank_values=True)])
    return urlunsplit((parts.scheme, parts.netloc, parts.path, query, ""))


def target_id(url: str) -> str:
    return hashlib.sha256(url.encode()).hexdigest()


def _public(address: str) -> bool:
    ip = ipaddress.ip_address(address)
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return ip.is_global and not (ip.is_multicast or ip.is_reserved or ip.is_unspecified)


def resolve(host: str, port: int, allow_private: bool = False) -> list[tuple]:
    try:
        addresses = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except OSError as exc:
        raise AuditError("DNS resolution failed.") from exc
    if not addresses:
        raise AuditError("DNS returned no addresses.")
    if not allow_private and any(not _public(item[4][0]) for item in addresses):
        raise AuditError("Non-public destination blocked. Use --allow-private for your own local network.")
    return addresses


def _connect(addresses: list[tuple], timeout: float) -> socket.socket:
    deadline = time.monotonic() + timeout
    for family, socktype, proto, _, sockaddr in addresses:
        sock = socket.socket(family, socktype, proto)
        try:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                sock.close()
                break
            sock.settimeout(remaining)
            sock.connect(sockaddr)
            return sock
        except OSError:
            sock.close()
    raise AuditError("Connection failed or timed out.")


def _tls_info(sock: ssl.SSLSocket) -> dict:
    cert = sock.getpeercert()
    expiration = cert.get("notAfter")
    expires_at = datetime.fromtimestamp(ssl.cert_time_to_seconds(expiration), timezone.utc) if expiration else None
    cipher = sock.cipher()
    return {
        "verified": True,
        "version": sock.version(),
        "cipher": cipher[0] if cipher else None,
        "expires_at": expires_at.isoformat() if expires_at else None,
        "days_remaining": int((expires_at - datetime.now(timezone.utc)).total_seconds() // 86400) if expires_at else None,
        "sha256": hashlib.sha256(sock.getpeercert(binary_form=True)).hexdigest(),
    }


def fetch(url: str, timeout: float, allow_private: bool = False) -> Hop:
    parts = urlsplit(url)
    host = parts.hostname
    port = parts.port or (443 if parts.scheme == "https" else 80)
    started = time.monotonic()
    addresses = resolve(host, port, allow_private)
    connection = http.client.HTTPConnection(host, port, timeout=timeout)
    sock = None
    try:
        sock = _connect(addresses, timeout)
        ip = sock.getpeername()[0]
        tls = None
        if parts.scheme == "https":
            context = ssl.create_default_context()
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            sock = context.wrap_socket(sock, server_hostname=host)
            tls = _tls_info(sock)
        connection.sock = sock
        path = urlunsplit(("", "", parts.path or "/", parts.query, ""))
        connection.request("GET", path, headers={
            "Host": parts.netloc,
            "User-Agent": f"RudyWebAudit/{__version__} (+https://github.com/r4venrudy/rudy-web-audit)",
            "Accept": "text/html,application/xhtml+xml,application/json;q=0.8,*/*;q=0.5",
            "Connection": "close",
        })
        response = connection.getresponse()
        return Hop(url=url, status=response.status, ip=ip,
                   elapsed_ms=round((time.monotonic() - started) * 1000, 1),
                   headers=response.getheaders(), tls=tls)
    except ssl.SSLCertVerificationError as exc:
        raise AuditError("TLS certificate verification failed.") from exc
    except ssl.SSLError as exc:
        raise AuditError("TLS handshake failed (minimum supported TLS is 1.2).") from exc
    except (OSError, http.client.HTTPException) as exc:
        raise AuditError("HTTP request failed or timed out.") from exc
    finally:
        connection.close()
        if sock is not None:
            sock.close()
