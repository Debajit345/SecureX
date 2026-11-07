"""Small Supabase REST helpers. Privileged keys are only read in the server runtime."""
import json
import os
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen


def db_request(method: str, table: str, *, params=None, payload=None, prefer=None, privileged=False, token=None):
    base = os.getenv("SUPABASE_URL", "").rstrip("/")
    key = os.getenv("SUPABASE_SERVICE_ROLE_KEY", "") if privileged else os.getenv("SUPABASE_ANON_KEY", "")
    if not base or not key:
        raise RuntimeError("Supabase is not configured.")
    url = f"{base}/rest/v1/{table}"
    if params:
        url += "?" + urlencode(params)
    headers = {"apikey": key, "Content-Type": "application/json"}
    # New Supabase secret keys are opaque API keys, not JWTs. Sending one as a
    # Bearer token makes Supabase try to parse it as a JWT and reject the call.
    # Keep Bearer auth for user JWTs and legacy service_role JWT keys.
    if token:
        headers["Authorization"] = f"Bearer {token}"
    elif not (privileged and key.startswith("sb_secret_")):
        headers["Authorization"] = f"Bearer {key}"
    if prefer:
        headers["Prefer"] = prefer
    body = json.dumps(payload).encode() if payload is not None else None
    try:
        with urlopen(Request(url, data=body, headers=headers, method=method), timeout=10) as response:
            content = response.read(2_000_000)
            return json.loads(content) if content else []
    except HTTPError as exc:
        raise RuntimeError(f"Supabase returned HTTP {exc.code}.") from exc
    except URLError as exc:
        raise RuntimeError("Supabase request failed.") from exc


def auth_user(token: str):
    base = os.getenv("SUPABASE_URL", "").rstrip("/")
    key = os.getenv("SUPABASE_ANON_KEY", "")
    if not base or not key or not token:
        return None
    request = Request(f"{base}/auth/v1/user", headers={"apikey": key, "Authorization": f"Bearer {token}"})
    try:
        with urlopen(request, timeout=8) as response:
            return json.loads(response.read(100_000))
    except Exception:
        return None


def admin_users(page=1, per_page=100):
    base = os.getenv("SUPABASE_URL", "").rstrip("/")
    key = os.getenv("SUPABASE_SERVICE_ROLE_KEY", "")
    if not base or not key:
        raise RuntimeError("Supabase server credentials are not configured.")
    headers = {"apikey": key}
    if not key.startswith("sb_secret_"):
        headers["Authorization"] = f"Bearer {key}"
    request = Request(f"{base}/auth/v1/admin/users?page={page}&per_page={per_page}", headers=headers)
    try:
        with urlopen(request, timeout=10) as response:
            return json.loads(response.read(1_000_000)).get("users", [])
    except Exception as exc:
        raise RuntimeError("Could not load account list.") from exc
