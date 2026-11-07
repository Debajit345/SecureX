from datetime import datetime, timezone
from pathlib import Path
import os
from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from urllib.parse import urlsplit
from backend.app.analyzers.target import normalize_url, ensure_public_host
from backend.app.analyzers.url_check import analyze_url
from backend.app.analyzers.tls_check import inspect_tls
from backend.app.analyzers.web_check import inspect_site
from backend.app.storage import db_request

ROOT = Path(__file__).resolve().parents[2]
FRONTEND = ROOT / "frontend"
app = FastAPI(title="SecureX", version="0.1.0")

class ScanRequest(BaseModel):
    url: str = Field(min_length=1, max_length=2048)

class ReportRequest(BaseModel):
    url: str = Field(min_length=1, max_length=2048)
    category: str = Field(min_length=3, max_length=40)
    note: str = Field(default="", max_length=300)

CATEGORIES = {"phishing", "impersonation", "payment scam", "malware", "other"}

def safe_error(exc: Exception):
    message = str(exc)
    if "Supabase" in message:
        raise HTTPException(503, message)
    raise HTTPException(400, message[:250])

@app.get("/api/health")
def health():
    try:
        db_request("GET", "reports", params={"select":"url", "limit":"1"})
        return {"ok": True, "service": "SecureX", "database": "connected"}
    except Exception as exc:
        raise HTTPException(503, "Supabase is not reachable or its reports policy is not configured.") from exc

@app.post("/api/scan")
def scan(body: ScanRequest):
    try:
        url = normalize_url(body.url)
        host = urlsplit(url).hostname
        ensure_public_host(host or "")
        findings = analyze_url(url)
        web = tls = None
        errors = []
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
                findings.append({"severity":"info", "title":"Certificate Transparency lookup", "detail":f"crt.sh returned {ct['logged_certificates']} certificate entr{'y' if ct['logged_certificates'] == 1 else 'ies'}; exact hostname listed: {'yes' if ct['hostname_seen'] else 'no'}. CT presence is not a safety verdict."})
        except Exception as exc:
            errors.append("TLS check: " + str(exc)[:160])
        try:
            reports = db_request("GET", "reports", params={"url": f"eq.{url}", "select":"category,created_at", "order":"created_at.desc", "limit":"100"})
        except Exception as exc:
            reports = []
            errors.append("Community intelligence unavailable: " + str(exc)[:160])
        if reports:
            cats = sorted({r["category"] for r in reports})
            findings.append({"severity":"high" if len(reports) >= 3 else "medium", "title":f"Community reports ({len(reports)})", "detail":"Reported categories: " + ", ".join(cats) + ". Reports are user-submitted and unverified."})
        weights = {"high": 35, "medium": 18, "low": 7, "info": 0}
        # Several missing headers should not overwhelm stronger phishing evidence.
        score = min(100, sum(weights.get(f["severity"], 0) for f in findings))
        level = "High risk" if score >= 50 else "Caution" if score >= 20 else "Low indicators found"
        return {"url":url, "scanned_at":datetime.now(timezone.utc).isoformat(), "score":score, "risk":level, "findings":findings, "tls":tls, "web":web, "community_reports":reports, "errors":errors}
    except HTTPException:
        raise
    except Exception as exc:
        safe_error(exc)

@app.post("/api/reports", status_code=201)
def submit_report(body: ReportRequest):
    try:
        url = normalize_url(body.url)
        parts = urlsplit(url)
        ensure_public_host(parts.hostname or "")
        category = body.category.strip().lower()
        if category not in CATEGORIES:
            raise HTTPException(422, "Choose a listed report category.")
        note = " ".join(body.note.split())
        db_request("POST", "reports", payload={"url":url,"category":category,"note":note}, prefer="return=minimal")
        return {"ok":True, "message":"Report received. Community reports are not independently verified."}
    except HTTPException:
        raise
    except Exception as exc:
        safe_error(exc)

app.mount("/", StaticFiles(directory=FRONTEND, html=True), name="frontend")
