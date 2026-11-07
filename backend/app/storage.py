"""Small Supabase REST client using only Python's standard library."""
import json
import os
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen


def db_request(method: str, table: str, *, params=None, payload=None, prefer=None):
    base = os.getenv("SUPABASE_URL", "").rstrip("/")
    key = os.getenv("SUPABASE_ANON_KEY", "")
    if not base or not key:
        raise RuntimeError("Supabase is not configured. Set SUPABASE_URL and SUPABASE_ANON_KEY.")
    url = f"{base}/rest/v1/{table}"
    if params:
        url += "?" + urlencode(params)
    headers = {"apikey": key, "Authorization": f"Bearer {key}", "Content-Type": "application/json"}
    if prefer:
        headers["Prefer"] = prefer
    body = json.dumps(payload).encode() if payload is not None else None
    request = Request(url, data=body, headers=headers, method=method)
    try:
        with urlopen(request, timeout=8) as response:
            content = response.read(1_000_000)
            return json.loads(content) if content else []
    except HTTPError as exc:
        raise RuntimeError(f"Supabase returned HTTP {exc.code}.") from exc
    except URLError as exc:
        raise RuntimeError("Supabase request failed.") from exc
