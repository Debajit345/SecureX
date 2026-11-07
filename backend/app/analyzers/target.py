"""URL normalization and public-network guard for outbound probes."""
import ipaddress
import socket
from urllib.parse import urlsplit, urlunsplit


def normalize_url(value: str) -> str:
    value = value.strip()
    if not value:
        raise ValueError("Enter a website URL.")
    if "://" not in value:
        value = "https://" + value
    parts = urlsplit(value)
    if parts.scheme.lower() not in {"http", "https"} or not parts.hostname:
        raise ValueError("Only valid HTTP or HTTPS URLs can be checked.")
    if parts.username or parts.password:
        raise ValueError("URLs containing username or password are not accepted.")
    if len(value) > 2048:
        raise ValueError("URL is too long (maximum 2048 characters).")
    try:
        port = parts.port
    except ValueError as exc:
        raise ValueError("URL contains an invalid port.") from exc
    if port and not 1 <= port <= 65535:
        raise ValueError("URL contains an invalid port.")
    hostname = parts.hostname.encode("idna").decode("ascii").lower().rstrip(".")
    authority_host = f"[{hostname}]" if ":" in hostname else hostname
    authority = authority_host + ((f":{port}") if port else "")
    return urlunsplit((parts.scheme.lower(), authority, parts.path or "/", parts.query, ""))


def ensure_public_host(host: str) -> None:
    try:
        addresses = [ipaddress.ip_address(host)]
    except ValueError:
        try:
            addresses = [ipaddress.ip_address(item[4][0]) for item in socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)]
        except socket.gaierror as exc:
            raise ValueError("The website hostname could not be resolved.") from exc
    if not addresses or any(not ip.is_global for ip in addresses):
        raise ValueError("Private, local, and reserved network addresses cannot be scanned.")
