from datetime import datetime, timezone, timedelta
from pathlib import Path
from urllib.parse import urlsplit
from urllib.request import Request, urlopen
from urllib.error import URLError
import base64, gzip, hashlib, json, os, re

from fastapi import FastAPI, HTTPException, Header
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from backend.app.analyzers.target import normalize_url, ensure_public_host
from backend.app.analyzers.url_check import analyze_url
from backend.app.analyzers.tls_check import inspect_tls
from backend.app.analyzers.web_check import inspect_site
from backend.app.storage import db_request, auth_user, admin_users

ROOT = Path(__file__).resolve().parents[2]
FRONTEND = ROOT / "frontend"
app = FastAPI(title="SecureX", version="0.2.0")

class ScanRequest(BaseModel):
    url: str = Field(min_length=1, max_length=2048)

class ReportRequest(BaseModel):
    url: str = Field(min_length=1, max_length=2048)
    category: str = Field(min_length=3, max_length=40)
    note: str = Field(default="", max_length=300)

class SaveRequest(BaseModel):
    cache_id: str = Field(min_length=64, max_length=64)

CATEGORIES = {"phishing", "impersonation", "payment scam", "malware", "other"}

def current_user(authorization):
    token = authorization.removeprefix("Bearer ") if authorization else ""
    user = auth_user(token)
    if not user or not user.get("id"):
        raise HTTPException(401, "Sign in with Google to continue.")
    return user, token

def cache_key(url):
    return hashlib.sha256(url.encode()).hexdigest()

def compress_report(report):
    return base64.b64encode(gzip.compress(json.dumps(report, separators=(",", ":")).encode())).decode()

def unpack_report(value):
    return json.loads(gzip.decompress(base64.b64decode(value)))

def redact_url_params(value):
    if isinstance(value, dict): return {k:redact_url_params(v) for k,v in value.items()}
    if isinstance(value, list): return [redact_url_params(v) for v in value]
    if isinstance(value, str):
        return re.sub(r"(https?://[^\s?#]+)[^\s#]*", r"\1", value)
    return value

def posture(tls, web):
    checks = []
    if tls is not None:
        checks.append(("TLS certificate trusted", bool(tls.get("available"))))
        if tls.get("available"):
            checks.append(("Certificate not near expiry", (tls.get("days_remaining") or 0) > 14))
            checks.append(("Modern TLS version", tls.get("tls_version") in {"TLSv1.2", "TLSv1.3"}))
    if web is not None:
        checks.append(("Final destination uses HTTPS", web.get("final_url", "").startswith("https://")))
        missing = {f.get("title", "") for f in web.get("findings", [])}
        for header in ("Content-Security-Policy", "X-Content-Type-Options", "Strict-Transport-Security", "X-Frame-Options"):
            checks.append((f"{header} configured", f"Missing {header} header" not in missing))
    passed = sum(ok for _, ok in checks)
    return {"score": round(100 * passed / len(checks)) if checks else None, "passed": passed, "total": len(checks), "checks": [{"name": n, "passed": ok} for n, ok in checks]}

def perform_scan(url):
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
            findings.append({"severity":"info", "title":"Certificate Transparency lookup", "detail":f"crt.sh returned {ct['logged_certificates']} certificate entries; exact hostname listed: {'yes' if ct['hostname_seen'] else 'no'}. CT presence is not a safety verdict."})
    except Exception as exc:
        errors.append("TLS check: " + str(exc)[:160])
    try:
        reports = db_request("GET", "reports", params={"url":f"eq.{url}","select":"category,created_at","order":"created_at.desc","limit":"100"})
    except Exception as exc:
        reports = []
        errors.append("Community intelligence unavailable: " + str(exc)[:160])
    if reports:
        cats = sorted({r["category"] for r in reports})
        findings.append({"severity":"high" if len(reports) >= 3 else "medium", "title":f"Community reports ({len(reports)})", "detail":"Reported categories: " + ", ".join(cats) + ". Reports are user-submitted and unverified."})
    score = min(100, sum({"high":35,"medium":18,"low":7}.get(f["severity"], 0) for f in findings))
    return {"url":url, "scanned_at":datetime.now(timezone.utc).isoformat(), "score":score,
        "risk":"High risk" if score >= 50 else "Caution" if score >= 20 else "Low indicators found",
        "posture":posture(tls, web), "findings":findings, "tls":tls, "web":web,
        "community_reports":reports, "errors":errors}

def save_history(user_id, key):
    rows = db_request("POST", "saved_reports", payload={"user_id":user_id,"cache_id":key}, prefer="return=representation", privileged=True)
    if not rows:
        raise RuntimeError("Could not save report history.")
    return rows[0]["id"]

@app.get("/api/health")
def health():
    try:
        db_request("GET", "reports", params={"select":"url","limit":"1"})
        return {"ok":True,"service":"SecureX","database":"connected"}
    except Exception as exc:
        raise HTTPException(503, "Supabase is not reachable or community report policies are not configured.") from exc

@app.get("/api/config")
def public_config():
    return {"url":os.getenv("SUPABASE_URL", ""),"anon_key":os.getenv("SUPABASE_ANON_KEY", "")}

@app.get("/api/auth/status")
def auth_status():
    """Return a safe provider readiness signal so disabled OAuth never dumps raw auth errors to visitors."""
    base=os.getenv("SUPABASE_URL","").rstrip("/")
    key=os.getenv("SUPABASE_ANON_KEY","")
    if not base or not key:
        return {"google_enabled":False,"message":"Sign-in is temporarily unavailable because authentication is not configured."}
    try:
        req=Request(f"{base}/auth/v1/settings",headers={"apikey":key})
        with urlopen(req,timeout=5) as response: settings=json.loads(response.read(100_000))
        providers=settings.get("external",[])
        if isinstance(providers,dict): enabled=bool(providers.get("google"))
        else: enabled="google" in providers
        return {"google_enabled":enabled,"message":"" if enabled else "Google sign-in needs setup: enable Google in Supabase Auth with a Google Web OAuth client ID and secret, then allow https://securex-security.vercel.app as a redirect URL."}
    except Exception:
        return {"google_enabled":False,"message":"SecureX could not check sign-in availability. Please try again shortly."}

@app.post("/api/scan")
def scan(body: ScanRequest, authorization: str | None = Header(default=None)):
    try:
        url = normalize_url(body.url)
        ensure_public_host(urlsplit(url).hostname or "")
        key = cache_key(url)
        now = datetime.now(timezone.utc)
        rows = []
        cache_error = None
        try:
            rows = db_request("GET", "scan_cache", params={"id":f"eq.{key}","select":"id,report_gzip,scanned_at","limit":"1"}, privileged=True)
        except Exception as exc:
            cache_error = str(exc)
        cached = False
        if rows:
            timestamp = datetime.fromisoformat(rows[0]["scanned_at"].replace("Z", "+00:00"))
            if now - timestamp < timedelta(minutes=15):
                report = unpack_report(rows[0]["report_gzip"])
                cached = True
        if not cached:
            report = perform_scan(url)
            report = redact_url_params(report)
            try:
                db_request("POST", "scan_cache", payload={"id":key,"url_hash":key,"report_gzip":compress_report(report),"scanned_at":report["scanned_at"]}, prefer="resolution=merge-duplicates,return=minimal", privileged=True)
                cache_error = None
            except Exception as exc:
                cache_error = str(exc)
                report.setdefault("errors", []).append("Shared scan cache unavailable; this result was not saved for reuse.")
        saved_id = None
        if authorization:
            try:
                user, _ = current_user(authorization)
                saved_id = save_history(user["id"], key)
            except Exception:
                # A secondary account-history write must never discard a completed scan.
                report.setdefault("errors", []).append("Could not save this scan to account history.")
        cache_saved = not cache_error
        return {**report,"cache_id":key if cache_saved else None,"cache_saved":cache_saved,"cached":cached,"cache_age_seconds":max(0,int((now-datetime.fromisoformat(report['scanned_at'].replace('Z','+00:00'))).total_seconds())),"saved_report_id":saved_id}
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(503, str(exc)[:200]) from exc

@app.post("/api/saved-reports", status_code=201)
def save_report(body: SaveRequest, authorization: str | None = Header(default=None)):
    user, _ = current_user(authorization)
    exists = db_request("GET", "scan_cache", params={"id":f"eq.{body.cache_id}","select":"id","limit":"1"}, privileged=True)
    if not exists:
        raise HTTPException(404, "Scan report not found. Run the scan again.")
    try:
        return {"id":save_history(user["id"], body.cache_id)}
    except Exception as exc:
        raise HTTPException(503, "Could not save report.") from exc

@app.get("/api/saved-reports")
def list_saved_reports(authorization: str | None = Header(default=None)):
    user, _ = current_user(authorization)
    rows = db_request("GET", "saved_reports", params={"user_id":f"eq.{user['id']}","select":"id,cache_id,created_at","order":"created_at.desc","limit":"100"}, privileged=True)
    keys=sorted({row["cache_id"] for row in rows})
    output=[]
    if keys:
        cache_rows=db_request("GET","scan_cache",params={"id":f"in.({','.join(keys)})","select":"id,report_gzip"},privileged=True)
        cache_by_id={item["id"]:unpack_report(item["report_gzip"]) for item in cache_rows}
        for row in rows:
            report=cache_by_id.get(row["cache_id"])
            if report:
                output.append({"id":row["id"],"created_at":row["created_at"],"url":report["url"],"risk":report["risk"],"score":report["score"]})
    return {"reports":output}

@app.get("/api/saved-reports/{report_id}")
def get_saved_report(report_id: str, authorization: str | None = Header(default=None)):
    user, _ = current_user(authorization)
    rows=db_request("GET","saved_reports",params={"id":f"eq.{report_id}","user_id":f"eq.{user['id']}","select":"id,cache_id,created_at","limit":"1"},privileged=True)
    if not rows: raise HTTPException(404,"Saved report not found.")
    cache=db_request("GET","scan_cache",params={"id":f"eq.{rows[0]['cache_id']}","select":"report_gzip","limit":"1"},privileged=True)
    if not cache: raise HTTPException(404,"Cached scan has expired.")
    return {**unpack_report(cache[0]["report_gzip"]),"saved_report_id":rows[0]["id"]}

@app.post("/api/saved-reports/{report_id}/summary")
def summary(report_id: str, authorization: str | None = Header(default=None)):
    user, _ = current_user(authorization)
    rows=db_request("GET","saved_reports",params={"id":f"eq.{report_id}","user_id":f"eq.{user['id']}","select":"cache_id","limit":"1"},privileged=True)
    if not rows: raise HTTPException(404,"Saved report not found.")
    account=os.getenv("CLOUDFLARE_ACCOUNT_ID"); token=os.getenv("CLOUDFLARE_API_TOKEN")
    if not account or not token: raise HTTPException(503,"AI summaries are not configured yet.")
    cache=db_request("GET","scan_cache",params={"id":f"eq.{rows[0]['cache_id']}","select":"report_gzip","limit":"1"},privileged=True)
    report=unpack_report(cache[0]["report_gzip"])
    safe={k:report.get(k) for k in ("risk","score","posture","findings","tls","web","errors")}
    url=f"https://api.cloudflare.com/client/v4/accounts/{account}/ai/run/@cf/google/gemma-4-26b-a4b-it"
    payload={"messages":[{"role":"system","content":"Summarize website security scan evidence for a non-expert in 3 concise sentences. Do not claim a site is safe; mention uncertainty and cite only supplied facts."},{"role":"user","content":json.dumps(safe)}],"max_tokens":180,"temperature":0.2}
    try:
        req=Request(url,data=json.dumps(payload).encode(),headers={"Authorization":f"Bearer {token}","Content-Type":"application/json"})
        with urlopen(req,timeout=20) as response: result=json.loads(response.read(100_000))
        return {"summary":result.get("result",{}).get("response","Summary unavailable.")}
    except Exception as exc:
        raise HTTPException(503,"AI summary is temporarily unavailable.") from exc

@app.get("/api/admin/overview")
def admin_overview(authorization: str | None = Header(default=None)):
    user, _=current_user(authorization)
    admin_id=os.getenv("SECUREX_ADMIN_USER_ID","")
    if not admin_id or user["id"] != admin_id: raise HTTPException(403,"Admin access required.")
    users=admin_users()
    histories=db_request("GET","saved_reports",params={"select":"id,user_id,cache_id,created_at","order":"created_at.desc","limit":"100"},privileged=True)
    cache=db_request("GET","scan_cache",params={"select":"id,scanned_at","order":"scanned_at.desc","limit":"100"},privileged=True)
    reports=db_request("GET","reports",params={"select":"id,url,category,note,created_at","order":"created_at.desc","limit":"100"},privileged=True)
    safe_users=[{"id":u.get("id"),"email":u.get("email"),"created_at":u.get("created_at"),"last_sign_in_at":u.get("last_sign_in_at")} for u in users]
    return {"users":safe_users,"saved_reports":histories,"cache":cache,"community_reports":reports}

@app.post("/api/reports", status_code=201)
def submit_report(body: ReportRequest):
    try:
        url=normalize_url(body.url); ensure_public_host(urlsplit(url).hostname or "")
        category=body.category.strip().lower()
        if category not in CATEGORIES: raise HTTPException(422,"Choose a listed report category.")
        db_request("POST","reports",payload={"url":url,"category":category,"note":" ".join(body.note.split())},prefer="return=minimal")
        return {"ok":True,"message":"Report received. Community reports are not independently verified."}
    except HTTPException: raise
    except Exception as exc: raise HTTPException(503,"Could not submit report.") from exc

app.mount("/", StaticFiles(directory=FRONTEND, html=True), name="frontend")
