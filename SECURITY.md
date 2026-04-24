# Security model

## Where secrets live

| Secret | Stored in | Who can see it | Shipped to browser? |
|---|---|---|---|
| `SUPABASE_URL` | Fly.io secret store (encrypted) | Only the running VM, via `os.getenv` at runtime | **No** |
| `SUPABASE_KEY` (service_role) | Fly.io secret store (encrypted) | Only the running VM, via `os.getenv` at runtime | **No** |
| `FLY_API_TOKEN` | GitHub repo secrets (encrypted) | Only the GitHub Actions runner during deploy | **No** |
| `BR_PROXY_URL` (optional) | Fly.io secret store (encrypted) | Only the running VM | **No** |

Nothing sensitive lives in:
- The git repo — `.env` is in `.gitignore`, only `.env.example` (placeholders) is committed
- The Docker image — `.dockerignore` excludes `.env`, `*.pem`, `*.key`, `secrets.json`
- The HTML/JS frontend — `templates/index.html` only calls same-origin `/api/*` endpoints on our own backend; the browser never sees Supabase credentials
- Git history — as long as you never `git add .env`, it can't leak

## Why the Supabase key is safe on the server

This app uses the **service_role** key (full database access). That's fine because:
1. It's read from `os.getenv("SUPABASE_KEY")` inside the Python process
2. The Python process runs inside the Fly VM — the key never crosses the network except once (server → Supabase over TLS)
3. The browser talks to our FastAPI backend, which talks to Supabase. The browser never sees the key or the Supabase URL.

If you ever need a key that the browser can see (e.g. real-time subscriptions from JS), use the **anon** key with Row-Level Security policies — never the service_role key. This app doesn't need that.

## Setting secrets on Fly.io

```bash
fly secrets set SUPABASE_URL=https://xxx.supabase.co SUPABASE_KEY=eyJhbGc...
fly secrets list                      # shows names only, never values
fly secrets unset SUPABASE_KEY        # remove
```

Fly stores secrets encrypted at rest and injects them as env vars only into the running VM. They are not visible in build logs, image layers, or the dashboard UI.

## Setting secrets on GitHub (for Actions deploy)

Repo → **Settings → Secrets and variables → Actions → New repository secret**:

| Name | Value |
|---|---|
| `FLY_API_TOKEN` | Output of `fly tokens create deploy` |

That's the only secret GitHub needs. Your Supabase credentials stay on Fly — GitHub Actions just runs `flyctl deploy` and Fly handles the rest.

## If you accidentally commit a secret

1. **Rotate immediately** — regenerate the Supabase key in `supabase.com → Settings → API → regenerate`.
2. Purge from git history:
   ```bash
   git filter-repo --invert-paths --path .env      # requires: pip install git-filter-repo
   git push --force
   ```
3. Update the new key in Fly: `fly secrets set SUPABASE_KEY=<new_key>`.

Rotation is cheap (2 minutes). Assume any leaked key is compromised forever — rotate, don't try to "delete" it.

## Other hardening notes

- The FastAPI app has **no authentication on the `/api/*` endpoints** by design — it's a public research tool. If you plan to expose it widely and worry about scrapers hammering it, put Fly's built-in rate limiter in front, or add a simple shared-token header check in `main.py`.
- The scanner's outbound HTTP calls (to `crt.sh`, `ip-api.com`, `publica.cnpj.ws`, target betting sites) do not carry any credentials.
- The CNPJ lookups hit a free public API with no secret.
- Telegram scraping uses the anonymous public preview at `t.me/s/` — no bot token, no phone number.

No personally identifiable data is stored. The database only holds public-record data: domain names, WHOIS-adjacent infrastructure info (ASN, hosting country), and CNPJ references that appear in the public HTML of scanned pages.
