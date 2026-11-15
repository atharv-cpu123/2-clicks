# FastAPI backend

The API runs locally and calls the existing scanner, risk analyst, responder,
approval tool, certificate generator, and medium-only sandbox remediation.

From the repository root in PowerShell:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
py -m pip install -r requirements.txt
Copy-Item .env.example .env
py .\frontend\server.py
```

To enable Supabase PostgreSQL storage, paste your **Postgres connection string**
into `DATABASE_URL` in the root `.env` file. Keep `.env` private and out of Git;
the web page uses the local API and never receives this database credential.
Restart the backend, then open http://localhost:8000/api/db-health. A connected
response means the API created or found the `pki_scan_runs`, `pki_certificates`,
and `pki_audit_events` tables. Scans and audit entries are then saved there.
If Supabase reports a network/IPv4 connection issue, use the session pooler
connection string from the Supabase dashboard's Connect panel.

Open http://localhost:8000. The API documentation is at http://localhost:8000/docs.

Before using replacement actions on a new sandbox CA, configure its local
certificate lifetime limit and restart the CA:

```powershell
py .\sandbox\configure_ca_lifetime.py
docker compose -f .\sandbox\docker-compose.yml restart step-ca
```

Approved replacements are issued for eight days so they do not immediately
match the scanner's seven-day expiring-soon rule.


### LLM certificate explanations

The Explain button uses Gemini Flash by default. Create an API key in [Google AI Studio](https://aistudio.google.com/app/apikey) and set these values in the root `.env` file:

```dotenv
LLM_PROVIDER=gemini
GEMINI_API_KEY=your_key_here
GEMINI_MODEL=gemini-3.8-flash
```

Keep the key private and out of frontend code and Git. Restart the backend after editing `.env`. The key stays server-side; only scanner certificate metadata and findings are sent for explanation. Gemini does not approve or run remediation. Gemini Flash currently has a free tier, subject to Google's account and rate limits. Alternatively, set `LLM_PROVIDER=openrouter`, `OPENROUTER_API_KEY`, and `OPENROUTER_MODEL=openrouter/free` to use OpenRouter's free-model route.
Main routes:

- `GET /api/dashboard`, `GET /api/certificates`, `GET /api/certificates/{name}/status`
- `POST /api/scan` runs scanner, analyst, and responder plan in sequence
- `POST /api/analysis` runs the risk analyst
- `POST /api/certificates/generate` accepts a preset sandbox profile
- `POST /api/remediation/approval` records the approval decision; an approval then issues, verifies, backs up, and replaces that sandbox certificate
- `POST /api/remediation/auto-medium` runs the existing medium-only replacement workflow
- `POST /api/remediation/{name}/dry-run` runs the responder's approved dry-run

The interface's demo login is not production authentication. General-purpose
automatic revocation is not available in the current responder; revocation is
restricted to the dedicated test fixture. Keep this API bound to localhost.
