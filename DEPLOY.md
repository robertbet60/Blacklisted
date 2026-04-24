# Deploy Guide

Two paths below. Do them in this order: **first run it locally to see it work, then push to Fly.io for a Brazilian public URL.**

---

## 1) Run on your computer (macOS / Linux / WSL)

From a terminal:

```bash
cd path/to/illegalbet-scanner
./run.sh
```

That's it. The script:
1. Finds Python 3.10+ (installs guidance if missing).
2. Creates `.venv/` and installs dependencies (one-time, ~30 seconds).
3. Starts the scanner on `http://localhost:8000`.
4. Opens your browser.

Stop with `Ctrl-C`. To wipe the venv and start fresh: `./run.sh clean`.

### Windows

Double-click `run.bat` (or from a terminal: `run.bat`). Same behavior.

### Prerequisites if the script complains

- **macOS:** `brew install python@3.11`
- **Ubuntu/Debian:** `sudo apt install python3.11 python3.11-venv`
- **Windows:** install from [python.org](https://python.org/downloads) — check "Add Python to PATH"

---

## 2) Deploy to a Brazilian server — Fly.io São Paulo

This gets you a public HTTPS URL with a Brazilian IP so illegal operators don't geo-block the scanner when it fetches their homepages.

### One-time setup (5 minutes)

**Step 1 — Install flyctl** (Fly.io's CLI):

```bash
# macOS
brew install flyctl

# Linux / WSL
curl -L https://fly.io/install.sh | sh

# Windows PowerShell
iwr https://fly.io/install.ps1 -useb | iex
```

**Step 2 — Sign up / log in:**

```bash
fly auth signup      # or: fly auth login
```

This opens a browser. Create an account and add a payment method. Fly.io gives you $5/month in free credits which covers this app entirely (we use a `shared-cpu-1x` + 512MB VM = roughly $1.94/mo if sized like our `fly.toml`).

### First deploy

From inside the project folder:

```bash
fly launch --copy-config --no-deploy
```

It will:
- Read the provided `fly.toml` (São Paulo region, Dockerfile build).
- Ask you to pick an app name — accept the default or type your own (this becomes your subdomain: `your-name.fly.dev`).
- Confirm the region — **keep `gru` (São Paulo)**.
- Skip deploying (we just want to register the app first).

Now push:

```bash
fly deploy
```

Wait ~90 seconds. When it finishes, the CLI prints your live URL. Open it — the dashboard should be there, already scanning.

### Useful commands afterward

```bash
fly status                  # is it up? how many VMs?
fly logs                    # live log stream
fly open                    # open the dashboard in a browser
fly ssh console             # shell into the running VM
fly deploy                  # redeploy after code changes
fly scale memory 1024       # bump memory if you add more channels
fly secrets set SUPABASE_URL=... SUPABASE_KEY=...   # add env vars
```

### Auto-deploy from GitHub (recommended once you're committing code)

A workflow is already checked in at `.github/workflows/fly-deploy.yml`. Once
you push this project to a GitHub repo, every commit to `main` will redeploy
to Fly.

**One-time setup:**

1. Push the repo:
   ```bash
   gh repo create illegalbet-scanner --private --source=. --push
   ```
   (or normal `git init && git remote add origin ... && git push -u origin main`)

2. Create a Fly deploy token:
   ```bash
   fly tokens create deploy
   ```
   Copy the long string it prints.

3. On GitHub: repo → **Settings → Secrets and variables → Actions → New repository secret**
   - **Name:** `FLY_API_TOKEN`
   - **Value:** paste the token

4. Done. Push any commit to `main` and the Actions tab will show the deploy
   running. Your Supabase credentials stay on Fly — GitHub Actions never sees
   them.

**Why this is safe:** `FLY_API_TOKEN` only has permission to deploy the app,
not to read its secrets. GitHub Actions runs `fly deploy`, Fly pulls the
pre-configured secrets into the new VM, and that's it. See [SECURITY.md](SECURITY.md).

### Cost estimate

With the default `fly.toml`:
- 1 VM × shared-cpu-1x × 512 MB, always-on
- ~$1.94/mo for compute
- Bandwidth: the scanner outbound is tiny (~100MB/day), well within free allowance
- **Effective monthly cost: $0** (covered by the free credits)

If you scale up (add more channels, Playwright, etc.), raise `memory` in `fly.toml` to `1024mb` — still under $5/mo.

---

## 3) Alternatives for the Brazilian server

If you can't use Fly.io for any reason:

| Provider | BR region | ~ Cost | Setup effort |
|---|---|---|---|
| **Fly.io** | São Paulo (`gru`) | ~$2/mo, free credits | 5 min — recommended |
| **AWS Lightsail** | São Paulo (`sa-east-1`) | $3.50/mo | 15 min, needs AWS account |
| **Vultr** | São Paulo | $6/mo | 10 min |
| **Hetzner** | EU (not BR) | €4/mo | not Brazilian IP |
| **Hostinger BR VPS** | São Paulo | R$10–30/mo | good BR IP, slower UX |

For Lightsail/Vultr, SSH in, install Docker, then:

```bash
git clone <your-repo> && cd illegalbet-scanner
docker build -t illegalbet-scanner .
docker run -d --restart=always -p 80:8000 --name scanner illegalbet-scanner
```

Put nginx + Let's Encrypt in front for HTTPS.

---

## 4) Add Supabase (optional — persistent data)

Without this, data resets on every restart. With it, every scan is saved forever.

1. Go to [supabase.com](https://supabase.com) → **New project** (free).
2. SQL Editor → paste contents of `supabase_schema.sql` → **Run**.
3. Settings → API → copy **Project URL** and **service_role key**.
4. Add to Fly.io:
   ```bash
   fly secrets set SUPABASE_URL=https://xxx.supabase.co SUPABASE_KEY=eyJ...
   fly deploy
   ```
5. Or locally, in a `.env` file next to `main.py`:
   ```
   SUPABASE_URL=https://xxx.supabase.co
   SUPABASE_KEY=eyJ...
   ```

---

## Troubleshooting

**"Permission denied: ./run.sh"** → `chmod +x run.sh` then retry.

**"fly: command not found" after install** → open a new terminal window, or add flyctl to your PATH (`export PATH="$HOME/.fly/bin:$PATH"` on Linux/macOS).

**"App already exists" on `fly launch`** → pick a unique name or run `fly apps destroy <name>` first.

**Dashboard shows no data after 2 minutes** → check `fly logs`. Common causes:
- crt.sh returning HTTP 503 (they throttle occasionally) — it'll self-recover
- Out of memory → `fly scale memory 1024`

**Telegram channels all show "error: http_404"** → Telegram disabled web previews for that handle. Try different channels via the "+ Add" button in the UI.
