"""URL normalization and public-network guard for outbound probes."""
import ipaddress
import socket
import ssl
import http.client
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


def resolve_public_host(host: str) -> list[str]:
    try:
        addresses = [ipaddress.ip_address(host)]
    except ValueError:
        try:
            addresses = [ipaddress.ip_address(item[4][0]) for item in socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)]
        except socket.gaierror as exc:
            raise ValueError("The website hostname could not be resolved.") from exc
    if not addresses or any(not ip.is_global for ip in addresses):
        raise ValueError("Private, local, and reserved network addresses cannot be scanned.")
    return sorted({str(ip) for ip in addresses})


def ensure_public_host(host: str) -> None:
    resolve_public_host(host)


class PinnedHTTPConnection(http.client.HTTPConnection):
    """Connect to a validated IP while retaining the hostname for Host/SNI."""
    def __init__(self, host: str, port: int, address: str, timeout: float):
        super().__init__(host, port, timeout=timeout)
        self.address = address

    def connect(self):
        self.sock = socket.create_connection((self.address, self.port), self.timeout)


class PinnedHTTPSConnection(PinnedHTTPConnection):
    def __init__(self, host: str, port: int, address: str, timeout: float):
        super().__init__(host, port, address, timeout)
        self.context = ssl.create_default_context()

    def connect(self):
        raw = socket.create_connection((self.address, self.port), self.timeout)
        self.sock = self.context.wrap_socket(raw, server_hostname=self.host)


def pinned_request(url: str, timeout: float = 5):
    parts = urlsplit(url)
    host = parts.hostname or ""
    port = parts.port or (443 if parts.scheme == "https" else 80)
    addresses = resolve_public_host(host)
    last_error = None
    for address in addresses:
        conn_type = PinnedHTTPSConnection if parts.scheme == "https" else PinnedHTTPConnection
        conn = conn_type(host, port, address, timeout)
        path = parts.path or "/"
        if parts.query:
            path += "?" + parts.query
        try:
            conn.request("GET", path, headers={"Host": parts.netloc, "User-Agent": "SecureX-Safety-Checker/1.0", "Connection": "close"})
            return conn, conn.getresponse()
        except OSError as exc:
            last_error = exc
            conn.close()
    if last_error:
        raise last_error
    raise ValueError("No public address was available for the website host.")
