from urllib.error import HTTPError
from urllib.request import HTTPRedirectHandler, Request, build_opener
from urllib.parse import urljoin, urlsplit
from .target import ensure_public_host

TIMEOUT = 5

class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def inspect_site(url: str) -> dict:
    current = url
    response = None
    redirects = []
    for _ in range(6):
        parts = urlsplit(current)
        ensure_public_host(parts.hostname or "")
        request = Request(current, headers={"User-Agent": "SecureX-Safety-Checker/1.0"})
        opener = build_opener(_NoRedirect())
        try:
            response = opener.open(request, timeout=TIMEOUT)
            status = response.status
            headers = response.headers
        except HTTPError as exc:
            response = exc
            status = exc.code
            headers = exc.headers
        if 300 <= status < 400:
            location = headers.get("Location")
            response.close()
            if not location:
                break
            current = urljoin(current, location)
            from .target import normalize_url
            current = normalize_url(current)
            redirects.append(current)
            continue
        break
    if response is None:
        raise ValueError("No response received.")
    headers = {k.lower(): v for k, v in headers.items()}
    response.close()
    findings = []
    for name, label in [("content-security-policy", "Content-Security-Policy"), ("x-content-type-options", "X-Content-Type-Options"), ("strict-transport-security", "Strict-Transport-Security"), ("x-frame-options", "X-Frame-Options")]:
        if name not in headers:
            findings.append({"severity": "info", "title": f"Missing {label} header", "detail": "This response does not set this common browser security header."})
    return {"status_code": status, "final_url": current, "redirects": redirects, "findings": findings}
