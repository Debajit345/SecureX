"""Dependency-free local runner for SecureX when Vercel dependencies are unavailable."""
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import json
import os
from urllib.parse import urlsplit
from backend.app.analyzers.target import normalize_url, ensure_public_host
from backend.app.analyzers.url_check import analyze_url
from backend.app.analyzers.tls_check import inspect_tls
from backend.app.analyzers.web_check import inspect_site
from backend.app.storage import db_request

ROOT = Path(__file__).resolve().parent


def load_env():
    path = ROOT / ".env"
    if path.exists():
        for line in path.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                name, value = line.split("=", 1)
                os.environ.setdefault(name.strip(), value.strip().strip('"\''))


def scan_url(raw_url):
    url = normalize_url(raw_url)
    ensure_public_host(urlsplit(url).hostname or "")
    findings, errors = analyze_url(url), []
    web = tls = None
    try:
        web = inspect_site(url)
        findings.extend(web["findings"])
        if web["final_url"] != url:
            findings.append({"severity":"info", "title":"Website redirected", "detail":f"Final destination: {web['final_url']}"})
    except Exception as exc:
        errors.append("Web response check: " + str(exc)[:160])
    try:
        tls = inspect_tls(url)
        findings.extend(tls.get("findings", []))
        ct = tls.get("certificate_transparency", {})
        if ct.get("available"):
            findings.append({"severity":"info", "title":"Certificate Transparency lookup", "detail":f"crt.sh returned {ct['logged_certificates']} certificate entries; exact hostname listed: {'yes' if ct['hostname_seen'] else 'no'}. CT presence is not a safety verdict."})
    except Exception as exc:
        errors.append("TLS check: " + str(exc)[:160])
    try:
        reports = db_request("GET", "reports", params={"url":f"eq.{url}","select":"category,created_at","order":"created_at.desc","limit":"100"})
    except Exception as exc:
        reports = []
        errors.append("Community intelligence unavailable: " + str(exc)[:160])
    if reports:
        categories = sorted({report["category"] for report in reports})
        findings.append({"severity":"high" if len(reports) >= 3 else "medium", "title":f"Community reports ({len(reports)})", "detail":"Reported categories: " + ", ".join(categories) + ". Reports are user-submitted and unverified."})
    score = min(100, sum({"high":35,"medium":18,"low":7,"info":0}.get(f["severity"], 0) for f in findings))
    return {"url":url,"scanned_at":datetime.now(timezone.utc).isoformat(),"score":score,"risk":"High risk" if score >= 50 else "Caution" if score >= 20 else "Low indicators found","findings":findings,"tls":tls,"web":web,"community_reports":reports,"errors":errors}


class Handler(BaseHTTPRequestHandler):
    def _json(self, status, payload):
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/api/health":
            try:
                db_request("GET", "reports", params={"select":"url", "limit":"1"})
                return self._json(200, {"ok":True,"service":"SecureX","database":"connected"})
            except Exception:
                return self._json(503, {"ok":False,"service":"SecureX","database":"unavailable"})
        path = "/" if self.path == "/" else self.path.split("?", 1)[0]
        candidate = (ROOT / "frontend" / path.lstrip("/")).resolve()
        if ROOT / "frontend" not in candidate.parents and candidate != ROOT / "frontend":
            return self._json(404, {"detail":"Not found"})
        if candidate.is_dir():
            candidate /= "index.html"
        if not candidate.is_file():
            return self._json(404, {"detail":"Not found"})
        content_type = "text/html; charset=utf-8" if candidate.suffix == ".html" else "text/css; charset=utf-8" if candidate.suffix == ".css" else "text/javascript; charset=utf-8"
        body = candidate.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if not 0 < length <= 4096:
                return self._json(413, {"detail":"Request body too large or empty."})
            body = json.loads(self.rfile.read(length))
            if self.path == "/api/scan":
                return self._json(200, scan_url(body.get("url", "")))
            if self.path == "/api/reports":
                url = normalize_url(body.get("url", ""))
                ensure_public_host(urlsplit(url).hostname or "")
                category = str(body.get("category", "")).strip().lower()
                if category not in {"phishing","impersonation","payment scam","malware","other"}:
                    return self._json(422, {"detail":"Choose a listed report category."})
                note = " ".join(str(body.get("note", "")).split())[:300]
                db_request("POST", "reports", payload={"url":url,"category":category,"note":note}, prefer="return=minimal")
                return self._json(201, {"ok":True,"message":"Report received. Community reports are not independently verified."})
            return self._json(404, {"detail":"Not found"})
        except ValueError as exc:
            return self._json(400, {"detail":str(exc)[:250]})
        except RuntimeError as exc:
            status = 503 if "Supabase" in str(exc) else 502
            return self._json(status, {"detail":str(exc)[:250]})
        except Exception:
            return self._json(500, {"detail":"SecureX could not complete this request."})

    def log_message(self, format, *args):
        print("SecureX:", format % args)


if __name__ == "__main__":
    load_env()
    server = ThreadingHTTPServer(("127.0.0.1", int(os.getenv("PORT", "8000"))), Handler)
    print(f"SecureX running at http://{server.server_address[0]}:{server.server_address[1]}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("Stopping SecureX…")
        server.server_close()
