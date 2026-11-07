from urllib.parse import urljoin, urlsplit
from .target import normalize_url, pinned_request

TIMEOUT = 5

def inspect_site(url: str) -> dict:
    current = url
    response = None
    redirects = []
    for _ in range(6):
        parts = urlsplit(current)
        conn, response = pinned_request(current, timeout=TIMEOUT)
        status = response.status
        headers = response.headers
        if 300 <= status < 400:
            location = headers.get("Location")
            response.close()
            conn.close()
            if not location:
                break
            current = urljoin(current, location)
            current = normalize_url(current)
            redirects.append(current)
            continue
        break
    if response is None:
        raise ValueError("No response received.")
    headers = {k.lower(): v for k, v in headers.items()}
    response.close()
    conn.close()
    findings = []
    for name, label in [("content-security-policy", "Content-Security-Policy"), ("x-content-type-options", "X-Content-Type-Options"), ("strict-transport-security", "Strict-Transport-Security"), ("x-frame-options", "X-Frame-Options")]:
        if name not in headers:
            findings.append({"severity": "info", "title": f"Missing {label} header", "detail": "This response does not set this common browser security header."})
    return {"status_code": status, "final_url": current, "redirects": redirects, "findings": findings}
