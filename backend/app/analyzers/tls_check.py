import socket, ssl
from datetime import datetime, timezone
from urllib.parse import urlsplit
import json
from urllib.parse import urlencode
from urllib.request import urlopen
from .target import ensure_public_host


def inspect_tls(url: str) -> dict:
    p = urlsplit(url)
    host = p.hostname or ""
    if p.scheme != "https":
        return {"available": False, "findings": [{"severity": "medium", "title": "No TLS certificate", "detail": "This URL uses HTTP."}]}
    ensure_public_host(host)
    port = p.port or 443
    ctx = ssl.create_default_context()
    with socket.create_connection((host, port), timeout=5) as raw:
        with ctx.wrap_socket(raw, server_hostname=host) as conn:
            cert = conn.getpeercert()
            cipher = conn.cipher()
            tls_version = conn.version()
    expiry = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
    days = (expiry - datetime.now(timezone.utc)).days
    findings = []
    if days < 0:
        findings.append({"severity": "high", "title": "Certificate expired", "detail": f"Certificate expired {-days} days ago."})
    elif days <= 14:
        findings.append({"severity": "medium", "title": "Certificate expires soon", "detail": f"Certificate expires in {days} days."})
    # crt.sh is a public Certificate Transparency search interface. Its result is
    # supporting context only; CT presence does not establish that a site is safe.
    ct = {"available": False, "logged_certificates": None}
    try:
        query = urlencode({"q": host, "output": "json"})
        with urlopen(f"https://crt.sh/?{query}", timeout=3) as response:
            entries = json.loads(response.read(2_000_000))
            exact_names = {name.strip().lower() for entry in entries for name in entry.get("name_value", "").splitlines()}
            ct = {"available": True, "logged_certificates": len(entries), "hostname_seen": host.lower() in exact_names}
    except (OSError, ValueError, TypeError):
        pass
    return {"available": True, "issuer": dict(x[0] for x in cert.get("issuer", [])).get("organizationName", "Unknown issuer"), "expires_at": expiry.isoformat(), "days_remaining": days, "tls_version": tls_version, "cipher": cipher[0] if cipher else "Unknown", "certificate_transparency": ct, "findings": findings}
