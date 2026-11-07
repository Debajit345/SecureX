# SecureX

SecureX checks public HTTP/HTTPS URLs for basic phishing indicators, TLS certificate status, selected security headers, redirects, and community reports. Results are explainable signals, not a guarantee that a website is safe.

## Live app

Production: https://securex-security.vercel.app

The `Debajit345/SecureX` GitHub repository is connected to the SecureX Vercel project. Production runs at the verified `securex-security.vercel.app` domain. Pushes to `main` trigger production deployments; pull requests get previews.

## Local development

Requires Python 3.12+. The local runner uses only the Python standard library, so it can run without network access.

```bash
cd Projects/SecureX
python local_server.py
```

Open http://127.0.0.1:8000. This runner uses only the standard library. To use the production FastAPI entry point locally instead:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
# Add your Supabase URL, publishable key, and server-only secret key.
set -a; source .env; set +a
uvicorn app:app --reload
```

The API health endpoint is `/api/health`.

## Supabase setup

1. Create a Supabase project.
2. Run `supabase/migrations/20261107000000_create_reports.sql` in the Supabase SQL Editor (or apply it with the Supabase CLI after linking the project).
3. Add `SUPABASE_URL` and `SUPABASE_ANON_KEY` as Vercel project environment variables for Production, Preview, and Development. `SUPABASE_ANON_KEY` accepts a current Supabase publishable key or a legacy `anon` key. The public role can read report signals (without notes) and submit validated reports; RLS is enabled.

The reports table has RLS enabled. The public key can read report signals without notes and submit category validated reports. Community reports are unverified and the UI says so.

### SecureX accounts, saved reports, and AI

1. Apply `supabase/migrations/20261108000000_securex_saved_reports.sql` after the community reports migration.
2. In Google Cloud, create a Web OAuth client. Add `https://securex-security.vercel.app` as an authorized JavaScript origin and the Supabase project's `/auth/v1/callback` URL as an authorized redirect URI. In Supabase Auth, enable Google with that client ID/secret and add `https://securex-security.vercel.app/**` to the allowed redirect URLs.
3. Set `SUPABASE_SERVICE_ROLE_KEY` as a sensitive, server-only Vercel environment variable in all environments. It may contain a current `sb_secret_…` API key or a legacy `service_role` JWT. Never expose it in frontend code. The API verifies Google/Supabase sessions before saving user history or returning private reports.
4. After the administrator signs in with `debaxoid@gmail.com`, set that account's Supabase Auth UUID as `SECUREX_ADMIN_USER_ID` in Vercel. Admin endpoints compare the verified Auth ID; they do not trust UI state or a caller-provided email.
5. Optionally configure `CLOUDFLARE_ACCOUNT_ID` and `CLOUDFLARE_API_TOKEN` in Vercel to enable on-demand report summaries. The token stays server-side. When these are absent, the report page explains that AI summaries are unavailable.

Scan results are compressed and cached for 15 minutes. The shared cache contains technical scan evidence but no account owner or community notes. Saved report references are private and tied to the authenticated Supabase user. `/reports.html`, `/report.html?id=…`, and `/admin.html` provide report history, report details, and administrator data respectively.

## Vercel deployment

Vercel detects the FastAPI application exported from `app.py`; `requirements.txt` is at the project root so its Python runtime can install dependencies. Configure `SUPABASE_URL`, `SUPABASE_ANON_KEY`, `SUPABASE_SERVICE_ROLE_KEY`, and `SECUREX_ADMIN_USER_ID` for Production, Preview, and Development. `vercel.json` adds a content security policy, HSTS, anti-framing and content-type protections, a strict referrer policy, a permissions policy, and no-store caching for API responses.

## Included checks and limits

- URL shape signals: HTTP, punycode, deep subdomains, hyphens, and sensitive-action wording.
- TLS: certificate trust/hostname validation via Python's default certificate store, issuer, expiry, TLS version, and cipher.
- Web response: status, redirects, and selected security response headers.
- Community reports: category, optional note, timestamp, and matching report count.
- Outbound requests reject local/private/reserved IP destinations and re-check redirect destinations. Checks have short timeouts and do not fetch page bodies.

This is a hackathon prototype. Add rate limiting, moderation/abuse controls, better DNS pinning, a proper threat-intelligence feed, and monitoring before public production use.

SecureX also performs a best-effort hostname lookup against the public crt.sh Certificate Transparency search and reports the result as informational context. A missing result can be incomplete or delayed, and a logged certificate is not proof that a site is safe. The TLS connection itself is verified using Python's system trust store and hostname checks.
