# IllegalBet Scanner

Brazilian illegal betting-domain detector. Streams new TLS certificate issuances from `crt.sh`, filters by Portuguese betting keywords, validates each candidate (DNS, hosting ASN, page fingerprints, CNPJ references), cross-references against the SPA/MF licensed-operator whitelist, and scores each domain on a 0–100 risk scale. Dark-terminal dashboard + public REST API, fully monolithic (one Python file + one HTML).

Zero paid API keys. Everything free tier.

---

## Quick start (local)

```bash
unzip illegalbet-scanner.zip
cd illegalbet-scanner
pip install -r requirements.txt
python main.py
# open http://localhost:8000
```

The poller starts automatically and cycles through all six keywords (`bet`, `aposta`, `cassino`, `jogo`, `pix`, `sorte`) every 60 seconds.

---

## What's in the box

```
main.py              FastAPI app + crt.sh poller + validation + WebSocket logs
templates/index.html Live dashboard (tables, stats, modal, live event stream)
requirements.txt     5 core packages
supabase_schema.sql  Postgres/Supabase schema (optional)
README.md            You are here
```

---

## API endpoints

```
GET  /                        → dashboard
GET  /api/stats               → counters
GET  /api/domains             → list tracked domains (?risk=&q=&limit=)
GET  /api/domain/{domain}     → full record
GET  /api/check?domain=xxx    → scan any domain on demand (public)
POST /api/scan                → same, JSON body {"domain": "..."}
GET  /api/logs?limit=200      → ring-buffer of recent log lines
GET  /api/whitelist           → licensed operators list
POST /api/poller/{start|stop} → control the background poller
WS   /ws/logs                 → live log stream
```

Example:

```bash
curl "http://localhost:8000/api/check?domain=betsuspeita.com"
```

---

## How the risk scoring works

Every candidate domain goes through:

1. DNS resolution
2. `ip-api.com` ASN / hosting country lookup
3. HTTP(S) fetch of the homepage
4. Keyword + regex scan for Portuguese betting signals
5. Tech fingerprint scan (Pragmatic Play, Evolution, Aviator, Pix)
6. CNPJ extraction + `publica.cnpj.ws` lookup
7. Cross-reference against the SPA whitelist scraped from gov.br

Scoring (0–100):

| Condition | +points |
|---|---|
| Any `.bet.br` domain | → forced to 0 / licensed |
| On SPA whitelist | → forced to 0 / licensed |
| Known gambling provider fingerprint (Pragmatic Play, Evolution, Aviator, PG Soft) | **+55** |
| Provider fingerprint on a `.bet`-family domain (combo bonus) | +15 |
| Betting keyword signals in page text | up to +40 (8 per match, capped) |
| Pix payment references | +10 |
| Portuguese content hosted outside Brazil | +10 (only if signals present) |
| Betting-related page title | +5 |
| Site unreachable | flat 20 / `unreachable` |

Labels: `high_risk` (≥70), `suspicious` (≥40), `low_risk` (≥20), `clean` (<20), `unreachable`, `licensed`.

**`.bet.br` is auto-licensed.** Under the registro.br / CGI.br policy the `.bet.br` second-level domain is reserved for SPA-authorized operators — registration itself requires proof of authorization from the Secretaria de Prêmios e Apostas. Every `.bet.br` that appears in CT logs is therefore licensed by construction, so the scanner short-circuits the TLD to `licensed` / 0.

**The whitelist adds everything else.** The scanner is seeded from the official SPA publications — the "Planilha de Autorizações" plus the list of operators running under judicial injunction — and augments that with a live gov.br scrape at startup. Non-`.bet.br` domains that aren't on the whitelist are judged purely on observed signals.

**Why provider fingerprint is weighted so high:** Pragmatic Play, Evolution Gaming, Spribe (Aviator), and PG Soft license their game content through contractual B2B relationships with operators only. Their JS bundles do not legitimately appear outside real-money gambling products. A single fingerprint hit is near-definitive.

---

## Deploy

### Option 1 — Railway (easiest, free tier)

1. Push the folder to a GitHub repo.
2. `railway.app` → New Project → Deploy from GitHub.
3. Railway auto-detects Python and runs `python main.py`.
4. (Optional) Add env vars `SUPABASE_URL` + `SUPABASE_KEY` for persistence.

### Option 2 — Render.com (also free)

1. New Web Service → connect repo.
2. Build command: `pip install -r requirements.txt`
3. Start command: `uvicorn main:app --host 0.0.0.0 --port $PORT`
4. Runtime: Python 3.11.

### Option 3 — Fly.io / Hetzner / any VPS

Create `systemd` unit `/etc/systemd/system/illegalbet.service`:

```ini
[Unit]
Description=IllegalBet Scanner
After=network.target

[Service]
WorkingDirectory=/opt/illegalbet-scanner
ExecStart=/usr/bin/python3 main.py
Environment=PORT=8000
Restart=always
User=www-data

[Install]
WantedBy=multi-user.target
```

Then `sudo systemctl enable --now illegalbet`. Put nginx in front for HTTPS:

```nginx
server {
    server_name scanner.yourdomain.com;
    location / { proxy_pass http://127.0.0.1:8000; proxy_http_version 1.1; proxy_set_header Upgrade $http_upgrade; proxy_set_header Connection "upgrade"; }
    listen 443 ssl;  # certbot handles this for you
}
```

---

## Adding Supabase (10 minutes)

1. `supabase.com` → new project.
2. SQL editor → paste `supabase_schema.sql` → run.
3. Settings → API → copy **URL** and **service_role** key.
4. `pip install supabase`.
5. In `main.py`, add at the top:

    ```python
    from supabase import create_client
    SB = create_client(os.environ["SUPABASE_URL"], os.environ["SUPABASE_KEY"]) \
        if os.getenv("SUPABASE_URL") else None
    ```

6. At the bottom of `validate_domain`, just before `return record`:

    ```python
    if SB:
        SB.table("domains").upsert({
            "domain": record["domain"],
            "first_seen": record["first_seen"],
            "last_checked": record["last_checked"],
            "source": record["source"],
            "ip": record["ip"],
            "licensed": record["licensed"],
            "risk_score": record["risk_score"],
            "risk_label": record["risk_label"],
            "reasons": record["reasons"],
            "infra": record["infra"],
            "site": record["site"],
            "cnpj": record["cnpj"],
        }).execute()
    ```

7. Set env vars on your host → redeploy.

---

## Telegram channel scraper

The app also runs a background **Telegram scraper** that monitors the public `t.me/s/{channel}` preview pages of Brazilian betting-adjacent channels. Every outbound URL posted in a message gets pushed through the same validator the CT-log poller uses, and each tracked domain shows its `source` as `telegram:@channelname`.

**Zero Telegram auth** — no phone number, no bot token, no API key. Just scraping the public HTML preview every 5 minutes with a polite User-Agent.

**Seed list** (all discovered via public web search, all public channels):

| Handle | Category |
|---|---|
| `@apostasepalpites` | Sports-betting tips |
| `@aposta10` | Sports-betting tips |
| `@apostasfc` | Sports-betting tips |
| `@robotip` | Sports-betting tips |
| `@tipsclubedaposta` | Sports-betting tips |
| `@daniloqa` | Tipster |
| `@nettunotrader` | Trader |
| `@Tipsbrasiloficial` | Tipster |
| `@sinais_telegram` | Fortune Tiger / casino signals |
| `@betpassoficial` | Operator channel (benchmark) |
| `@Bettigreoficial` | Operator channel (benchmark) |
| `@canalvaidebetoficial` | Operator channel (benchmark) |

Adjust at runtime via the "Telegram" button in the dashboard (add any public handle) or override the full list via env var:

```bash
export TELEGRAM_CHANNELS="handle1,handle2,handle3"
```

**UI:** click the "Telegram" button in the header for a per-channel view — subscriber count, messages scanned, domains discovered, flagged count, high-risk count. Click any row to drill into that channel's domain list.

**API:**
```
GET  /api/telegram/channels              → all channels + stats
GET  /api/telegram/channel/{handle}      → per-channel detail with domain list
POST /api/telegram/add/{handle}          → add a channel at runtime
```

**What the scraper extracts:** every `<a href>` inside `.tgme_widget_message_text` and `.tgme_widget_message_link_preview`. Telegram-internal links (t.me/), social media (Instagram, YouTube, X/Twitter, TikTok, WhatsApp) and link shorteners are filtered out automatically.

**Limitations:**
- Private channels / groups are invisible (no auth).
- Some channel admins disable web previews — `t.me/s/xyz` returns 404.
- Only the most recent ~20 messages per channel are visible in the public preview.

If you need full message history or private channels, swap the scraper for **Option A (Telethon)** — the rest of the pipeline stays identical.

---

## APIs used (all free, no key)

| Source | Auth | Limit | Purpose |
|---|---|---|---|
| `crt.sh` | none | polite (~6 req/min) | Certificate Transparency log keyword search |
| `ip-api.com` | none | 45/min | ASN / hosting country |
| `publica.cnpj.ws` | none | public | CNPJ lookup |
| `gov.br` | none | scraped once | SPA whitelist |

The poller rate-limits itself: 1.5s between validations, 2s between keywords, max 15 new domains per keyword per cycle. You'll stay well inside every free tier.

---

## Roadmap (phase 2)

- Telegram channel + YouTube description crawler (influencer graph)
- pgvector embeddings of fingerprinted sites for self-learning similarity
- Public `/report.json` feed for IBJR / journalists
- Playwright-based headless crawler for JS-heavy sites
# Blacklisted
# Blacklisted
# Blacklisted
# Blacklisted
# Blacklisted
