"""
IllegalBet Scanner - Brazilian Illegal Betting Domain Detection
Monolithic FastAPI app: CT log polling + validation + API + dashboard
"""
import asyncio
import os
import re
import json
import time
import socket
import logging
from datetime import datetime, timezone
from collections import deque
from typing import Optional, Dict, List, Any
from contextlib import asynccontextmanager

import httpx
from bs4 import BeautifulSoup
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Query
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi import Request
from pydantic import BaseModel

# Supabase is optional — app runs fine without it (in-memory mode).
try:
    from supabase import create_client, Client as SupabaseClient  # type: ignore
except ImportError:  # pragma: no cover
    create_client = None  # type: ignore
    SupabaseClient = None  # type: ignore

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
POLL_INTERVAL = int(os.getenv("POLL_INTERVAL", "60"))
TELEGRAM_POLL_INTERVAL = int(os.getenv("TELEGRAM_POLL_INTERVAL", "300"))  # 5 min
KEYWORDS = ["bet", "aposta", "cassino", "jogo", "pix", "sorte"]
CRT_URL = "https://crt.sh/?q=%25{kw}%25&output=json"
SPA_WHITELIST_URL = "https://www.gov.br/fazenda/pt-br/assuntos/loterias/bets/empresas-autorizadas-a-operar-bets"
IP_API_URL = "http://ip-api.com/json/{host}"
CNPJ_URL = "https://publica.cnpj.ws/cnpj/{cnpj}"
TELEGRAM_PREVIEW_URL = "https://t.me/s/{channel}"

# ---------------------------------------------------------------------------
# Telegram channel seed list
# ---------------------------------------------------------------------------
# Public Brazilian betting / palpites / sinais / tigrinho / aviator channels.
# Every handle here was discovered via public web search on indexed
# t.me/s/ preview pages — no private channels, no guesswork.
# Override at runtime via TELEGRAM_CHANNELS env var (comma-separated).
_DEFAULT_TELEGRAM_CHANNELS = [
    # Sports-betting tips / palpites
    "apostasepalpites",     # Apostas e Palpites | Futebol
    "aposta10",             # Aposta10
    "apostasfc",            # ApostasFC
    "robotip",              # Apostas Esportivas | RobôTip
    "tipsclubedaposta",     # Clube da Aposta Tips
    "daniloqa",             # Danilo Martins (tipster)
    "nettunotrader",        # Canal do Nettuno
    "Tipsbrasiloficial",    # Tips Brasil Oficial
    # Casino / tigrinho / aviator signals
    "sinais_telegram",      # Sinais Telegram (Fortune Tiger)
    # Operator-affiliated (useful as benchmarks — expect to hit licensed domains)
    "betpassoficial",       # BetPass
    "Bettigreoficial",      # BetTigre
    "canalvaidebetoficial", # Vaidebet
]
TELEGRAM_CHANNELS = [
    c.strip() for c in os.getenv(
        "TELEGRAM_CHANNELS", ",".join(_DEFAULT_TELEGRAM_CHANNELS)
    ).split(",") if c.strip()
]

# Brazilian TLDs and betting signal patterns
BETTING_SIGNALS = [
    r"\baposte\b", r"\bsaque\s*r[aá]pido\b", r"\bpix\b",
    r"\bcassino\b", r"\bslots?\b", r"\bca[cç]a-?n[ií]queis?\b",
    r"\bbônus\s*de\s*boas?-?vindas\b", r"\bjogo\s*do\s*tigrinho\b",
    r"\bfortune\s*tiger\b", r"\bavi[aã]tor\b", r"\bpragmatic\b",
    r"\bevolution\s*gaming\b", r"\brolet[ae]\b", r"\bblackjack\b",
]
BETTING_SIGNAL_RE = re.compile("|".join(BETTING_SIGNALS), re.IGNORECASE)

# ---------------------------------------------------------------------------
# Supabase (optional)
# ---------------------------------------------------------------------------
SUPABASE_URL = os.getenv("SUPABASE_URL", "").strip()
SUPABASE_KEY = os.getenv("SUPABASE_KEY", "").strip()
SB: Optional["SupabaseClient"] = None
if SUPABASE_URL and SUPABASE_KEY and create_client is not None:
    try:
        SB = create_client(SUPABASE_URL, SUPABASE_KEY)
    except Exception as _e:
        # Fall back to in-memory mode; we'll log this from push_log once ready.
        SB = None
        _SB_INIT_ERROR = str(_e)[:200]
    else:
        _SB_INIT_ERROR = None
else:
    _SB_INIT_ERROR = None


def _sb_persist_domain(record: Dict[str, Any]) -> None:
    """Best-effort upsert into `domains` + append `scan_events`. Never raises."""
    if not SB:
        return
    try:
        SB.table("domains").upsert({
            "domain":       record["domain"],
            "first_seen":   record["first_seen"],
            "last_checked": record["last_checked"],
            "source":       record.get("source"),
            "ip":           record.get("ip"),
            "licensed":     record.get("licensed", False),
            "risk_score":   record.get("risk_score", 0),
            "risk_label":   record.get("risk_label", "unknown"),
            "reasons":      record.get("reasons") or [],
            "infra":        record.get("infra") or {},
            "site":         record.get("site") or {},
            "cnpj":         record.get("cnpj"),
        }, on_conflict="domain").execute()
        SB.table("scan_events").insert({
            "domain":     record["domain"],
            "source":     record.get("source"),
            "risk_score": record.get("risk_score"),
            "risk_label": record.get("risk_label"),
            "snapshot":   {
                "reasons": record.get("reasons"),
                "infra":   record.get("infra"),
                "site":    record.get("site"),
                "cnpj":    record.get("cnpj"),
            },
        }).execute()
    except Exception as e:
        # Bubble up to the log stream but don't crash the pipeline.
        asyncio.create_task(
            push_log(f"supabase write failed for {record['domain']}: {e}", "warn")
        )


def _sb_persist_whitelist(domains: set) -> None:
    if not SB or not domains:
        return
    try:
        rows = [{"domain": d} for d in sorted(domains)]
        # Upsert in chunks to stay under PostgREST request-size limits.
        for i in range(0, len(rows), 500):
            SB.table("spa_whitelist").upsert(
                rows[i:i + 500], on_conflict="domain"
            ).execute()
    except Exception as e:
        asyncio.create_task(
            push_log(f"supabase whitelist upsert failed: {e}", "warn")
        )


def _sb_hydrate_db() -> int:
    """Load the most recent N domains from Supabase into the in-memory DB on startup."""
    if not SB:
        return 0
    try:
        r = SB.table("domains").select("*") \
            .order("last_checked", desc=True).limit(2000).execute()
        hydrated = 0
        for row in (r.data or []):
            DB[row["domain"]] = {
                "domain":       row["domain"],
                "first_seen":   row.get("first_seen"),
                "last_checked": row.get("last_checked"),
                "source":       row.get("source"),
                "ip":           row.get("ip"),
                "licensed":     row.get("licensed", False),
                "risk_score":   row.get("risk_score", 0),
                "risk_label":   row.get("risk_label", "unknown"),
                "reasons":      row.get("reasons") or [],
                "infra":        row.get("infra") or {},
                "site":         row.get("site") or {},
                "cnpj":         row.get("cnpj"),
            }
            hydrated += 1
        return hydrated
    except Exception as e:
        asyncio.create_task(push_log(f"supabase hydrate failed: {e}", "warn"))
        return 0


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("scanner")

# ---------------------------------------------------------------------------
# In-memory DB + live log ring buffer
# ---------------------------------------------------------------------------
DB: Dict[str, Dict[str, Any]] = {}
SPA_WHITELIST: set = set()
LOG_BUFFER: deque = deque(maxlen=500)
WS_CLIENTS: List[WebSocket] = []
TELEGRAM_DB: Dict[str, Dict[str, Any]] = {}

STATS = {
    "running": False,
    "started_at": None,
    "last_poll": None,
    "total_scanned": 0,
    "total_flagged": 0,
    "total_licensed": 0,
    "total_unknown": 0,
    "keywords_cycled": 0,
}


async def push_log(msg: str, level: str = "info"):
    """Broadcast a log line to all websocket clients + ring buffer."""
    entry = {
        "t": datetime.now(timezone.utc).isoformat(),
        "level": level,
        "msg": msg,
    }
    LOG_BUFFER.append(entry)
    log.info(msg)
    dead = []
    for ws in WS_CLIENTS:
        try:
            await ws.send_json(entry)
        except Exception:
            dead.append(ws)
    for ws in dead:
        if ws in WS_CLIENTS:
            WS_CLIENTS.remove(ws)


# ---------------------------------------------------------------------------
# SPA Whitelist (licensed Brazilian operators)
# ---------------------------------------------------------------------------
# Seeded from official SPA (Secretaria de Prêmios e Apostas) publications:
#   - planilha-de-autorizacoes (administrative authorizations)
#   - ProcessosjudiciaisSPA (operators running under court injunction)
# The live gov.br scrape at startup augments this with any newer entries.
SEED_LICENSED = {
    # --- Administratively authorized (SPA Portarias) .bet.br ---
    "1pra1.bet.br", "1xbet.bet.br", "4play.bet.br", "4win.bet.br", "55w.bet.br",
    "5g.bet.br", "6r.bet.br", "6z.bet.br", "7games.bet.br", "7k.bet.br", "9d.bet.br",
    "9f.bet.br", "a247.bet.br", "afun.bet.br", "ai.bet.br", "alfa.bet.br", "aposta.bet.br",
    "aposta1.bet.br", "apostaganha.bet.br", "apostamax.bet.br", "apostaonline.bet.br",
    "apostar.bet.br", "apostatudo.bet.br", "apostou.bet.br", "arenaplus.bet.br",
    "aviao.bet.br", "b1bet.bet.br", "bacanaplay.bet.br", "bandbet.bet.br", "bateu.bet.br",
    "bau.bet.br", "bet365.bet.br", "bet4.bet.br", "betaki.bet.br", "betano.bet.br",
    "betao.bet.br", "betapp.bet.br", "betboo.bet.br", "betboom.bet.br", "betbra.bet.br",
    "betbuffalos.bet.br", "betcaixa.bet.br", "betcopa.bet.br", "betdasorte.bet.br",
    "betespecial.bet.br", "betesporte.bet.br", "betfair.bet.br", "betfalcons.bet.br",
    "betfast.bet.br", "betfusion.bet.br", "betgo.bet.br", "betgorillas.bet.br",
    "betmgm.bet.br", "betnacional.bet.br", "betou.bet.br", "betpix365.bet.br",
    "betpontobet.bet.br", "betsson.bet.br", "betsul.bet.br", "betvip.bet.br",
    "betwarrior.bet.br", "big.bet.br", "bingo.bet.br", "bingoplus.bet.br", "blaze.bet.br",
    "bolsadeaposta.bet.br", "br4.bet.br", "bra.bet.br", "brasil.bet.br",
    "brasildasorte.bet.br", "bravo.bet.br", "brazino777.bet.br", "brbet.bet.br",
    "brx.bet.br", "bullsbet.bet.br", "bz.bet.br", "casadeapostas.bet.br", "cassino.bet.br",
    "cbesportes.bet.br", "cgg.bet.br", "donald.bet.br", "donosdabola.bet.br",
    "drbingo.bet.br", "energia.bet.br", "esporte365.bet.br", "esportesdasorte.bet.br",
    "esportiva.bet.br", "esportivavip.bet.br", "estrelabet.bet.br", "f12.bet.br",
    "fanbit.bet.br", "faz1.bet.br", "fazo.bet.br", "fogo777.bet.br", "fulltbet.bet.br",
    "fybet.bet.br", "galera.bet.br", "ganhei.bet.br", "geralbet.bet.br", "ginga.bet.br",
    "goldebet.bet.br", "h2.bet.br", "hiper.bet.br", "ice.bet.br", "ijogo.bet.br",
    "jogajunto.bet.br", "jogalimpo.bet.br", "jogao.bet.br", "jogodeouro.bet.br",
    "jogoonline.bet.br", "jogos.bet.br", "jonbet.bet.br", "kbet.bet.br",
    "kingpanda.bet.br", "kto.bet.br", "lancedesorte.bet.br", "lider.bet.br",
    "lotogreen.bet.br", "lottoland.bet.br", "lottu.bet.br", "luck.bet.br", "luva.bet.br",
    "magicjackpot.bet.br", "matchbook.bet.br", "maxima.bet.br", "mcgames.bet.br",
    "megabet.bet.br", "megaposta.bet.br", "meridianbet.bet.br", "mgm.bet.br",
    "milhao.bet.br", "mmabet.bet.br", "montecarlos.bet.br", "multi.bet.br", "nossa.bet.br",
    "novibet.bet.br", "obabet.bet.br", "oleybet.bet.br", "ona.bet.br", "onlybets.bet.br",
    "p9.bet.br", "pagol.bet.br", "papigames.bet.br", "pin.bet.br", "pinnacle.bet.br",
    "pitaco.bet.br", "pix.bet.br", "play.bet.br", "playuzu.bet.br", "pq777.bet.br",
    "qg.bet.br", "r7.bet.br", "rdp.bet.br", "reals.bet.br", "receba.bet.br",
    "reidopitaco.bet.br", "rico.bet.br", "rivalo.bet.br", "seguro.bet.br", "seu.bet.br",
    "sortenabet.bet.br", "sorteonline.bet.br", "spin.bet.br", "sportingbet.bet.br",
    "sporty.bet.br", "stake.bet.br", "start.bet.br", "super.bet.br", "superbet.bet.br",
    "suprema.bet.br", "tiger.bet.br", "tivo.bet.br", "tradicional.bet.br",
    "tropino.bet.br", "ultra.bet.br", "up.bet.br", "vaidebet.bet.br", "vbet.bet.br",
    "vera.bet.br", "versus.bet.br", "vert.bet.br", "vivaro.bet.br", "vivasorte.bet.br",
    "vupi.bet.br", "wjcasino.bet.br", "xbetcaixa.bet.br", "zonadejogo.bet.br",
    # --- Operating under judicial injunction (count as authorized) ---
    "energia.bet", "sportvip.bet", "zeroum.bet",
}


async def load_spa_whitelist():
    """Scrape gov.br for licensed operators. Fallback to seed list."""
    global SPA_WHITELIST
    SPA_WHITELIST = set(SEED_LICENSED)
    try:
        async with httpx.AsyncClient(
            timeout=30.0,
            headers={"User-Agent": "IllegalBetScanner/1.0 (journalism research)"},
            follow_redirects=True,
        ) as client:
            r = await client.get(SPA_WHITELIST_URL)
            if r.status_code == 200:
                soup = BeautifulSoup(r.text, "html.parser")
                text = soup.get_text(" ", strip=True)
                # Extract domain-like tokens that end with .bet.br (SPA regulated TLD)
                found = set(re.findall(r"[a-z0-9][a-z0-9\-]*\.bet\.br", text, re.I))
                if found:
                    SPA_WHITELIST |= {d.lower() for d in found}
        await push_log(
            f"SPA whitelist loaded: {len(SPA_WHITELIST)} licensed operators", "info"
        )
    except Exception as e:
        await push_log(f"SPA whitelist load failed: {e} (using seed list)", "warn")
    # Mirror to Supabase (no-op if SB not configured).
    _sb_persist_whitelist(SPA_WHITELIST)


# ---------------------------------------------------------------------------
# Core validation pipeline
# ---------------------------------------------------------------------------
async def resolve_ip(domain: str) -> Optional[str]:
    try:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, socket.gethostbyname, domain)
    except Exception:
        return None


async def fetch_infra(ip: str, client: httpx.AsyncClient) -> Dict[str, Any]:
    try:
        r = await client.get(IP_API_URL.format(host=ip), timeout=10.0)
        if r.status_code == 200:
            d = r.json()
            return {
                "country": d.get("country"),
                "country_code": d.get("countryCode"),
                "isp": d.get("isp"),
                "org": d.get("org"),
                "asn": d.get("as"),
            }
    except Exception:
        pass
    return {}


async def fetch_site(domain: str, client: httpx.AsyncClient) -> Dict[str, Any]:
    """Grab the homepage, look for betting signals, extract fingerprints."""
    for scheme in ("https", "http"):
        url = f"{scheme}://{domain}"
        try:
            r = await client.get(
                url,
                timeout=12.0,
                follow_redirects=True,
                headers={
                    "User-Agent": (
                        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                        "AppleWebKit/537.36 (KHTML, like Gecko) "
                        "Chrome/124.0.0.0 Safari/537.36"
                    ),
                    "Accept-Language": "pt-BR,pt;q=0.9,en;q=0.8",
                },
            )
            html = r.text or ""
            soup = BeautifulSoup(html, "html.parser")
            title = (soup.title.string or "").strip() if soup.title else ""
            text = soup.get_text(" ", strip=True)[:8000]

            signals = sorted(set(m.group(0).lower() for m in BETTING_SIGNAL_RE.finditer(text)))

            # Tech fingerprints
            fingerprints = []
            lower = html.lower()
            if "pragmatic" in lower or "pragmaticplay" in lower:
                fingerprints.append("pragmatic-play")
            if "evolution" in lower and ("gaming" in lower or "live" in lower):
                fingerprints.append("evolution-gaming")
            if "spribe" in lower or "aviator" in lower:
                fingerprints.append("spribe-aviator")
            if "pgsoft" in lower or "pg soft" in lower:
                fingerprints.append("pg-soft")
            if "pix" in lower:
                fingerprints.append("pix-payment")
            if "hotjar" in lower:
                fingerprints.append("hotjar")
            if "googletagmanager" in lower:
                fingerprints.append("gtm")

            # Look for CNPJ strings
            cnpj_hits = re.findall(
                r"\b\d{2}\.\d{3}\.\d{3}/\d{4}-\d{2}\b", html
            )

            return {
                "final_url": str(r.url),
                "status_code": r.status_code,
                "title": title[:300],
                "signals": signals,
                "fingerprints": fingerprints,
                "cnpj_hits": list(set(cnpj_hits)),
                "content_length": len(html),
                "ok": True,
            }
        except httpx.ConnectError:
            continue
        except httpx.TimeoutException:
            continue
        except Exception as e:
            return {"ok": False, "error": str(e)[:200]}
    return {"ok": False, "error": "connection_failed"}


async def check_cnpj(cnpj: str, client: httpx.AsyncClient) -> Dict[str, Any]:
    """Look up CNPJ via the free public API."""
    clean = re.sub(r"\D", "", cnpj)
    if len(clean) != 14:
        return {"valid": False}
    try:
        r = await client.get(CNPJ_URL.format(cnpj=clean), timeout=15.0)
        if r.status_code == 200:
            d = r.json()
            return {
                "valid": True,
                "name": d.get("razao_social") or d.get("estabelecimento", {}).get("nome_fantasia"),
                "status": d.get("estabelecimento", {}).get("situacao_cadastral"),
                "city": d.get("estabelecimento", {}).get("cidade", {}).get("nome"),
                "state": d.get("estabelecimento", {}).get("estado", {}).get("sigla"),
            }
    except Exception:
        pass
    return {"valid": False}


def score_risk(record: Dict[str, Any]) -> (int, str, List[str]):
    """Return (score 0-100, label, reasons)."""
    score = 0
    reasons = []

    site = record.get("site") or {}
    signals = site.get("signals", [])
    fingerprints = site.get("fingerprints", [])
    domain = record["domain"]
    licensed = record.get("licensed", False)
    infra = record.get("infra") or {}

    if licensed:
        if domain.endswith(".bet.br"):
            return 0, "licensed", [
                "`.bet.br` is a restricted second-level domain — registro.br "
                "only issues it to SPA-authorized operators, so every "
                "`.bet.br` registration is licensed by definition"
            ]
        return 0, "licensed", ["Domain is on SPA licensed operator whitelist"]

    if not site.get("ok"):
        # Unreachable — treat uniformly regardless of TLD. A parked or
        # not-yet-deployed domain is not evidence of active operation.
        return 20, "unreachable", ["Site unreachable or no response"]

    if signals:
        score += min(40, 8 * len(signals))
        reasons.append(f"Betting keyword signals detected: {', '.join(signals[:6])}")

    if fingerprints:
        gambling_fp = [f for f in fingerprints if f in (
            "pragmatic-play", "evolution-gaming", "spribe-aviator", "pg-soft"
        )]
        if gambling_fp:
            # Provider fingerprint is a near-definitive signal: these four
            # vendors license their content exclusively to operators — their
            # JS does not appear on non-gambling sites.
            score += 55
            reasons.append(
                f"Known gambling provider fingerprints: {', '.join(gambling_fp)}"
            )
            # .bet-family TLD (generic .bet, ccTLDs like .bet.ar, etc.) with
            # operator-grade tech — canonical illegal-operator signature.
            # Note: .bet.br is intentionally NOT treated as special; if it's
            # licensed it short-circuits to 0 above, and if not we score it
            # on observed signals like any other unlicensed domain.
            if domain.endswith(".bet") or ".bet." in domain:
                score += 15
                reasons.append(
                    "Gambling provider JS on a .bet-family domain "
                    "(combined signal)"
                )
        if "pix-payment" in fingerprints:
            score += 10
            reasons.append("Pix payment references detected")

    # Non-BR hosting for Portuguese betting content is a red flag
    cc = (infra.get("country_code") or "").upper()
    if cc and cc not in ("BR", ""):
        if signals:
            score += 10
            reasons.append(
                f"Portuguese-language betting content hosted outside Brazil ({cc})"
            )

    # Title check
    title_lower = (site.get("title") or "").lower()
    if any(k in title_lower for k in ("aposta", "cassino", "bet", "jogo")) and not licensed:
        score += 5
        reasons.append("Betting-related page title")

    score = max(0, min(100, score))
    if score >= 70:
        label = "high_risk"
    elif score >= 40:
        label = "suspicious"
    elif score >= 20:
        label = "low_risk"
    else:
        label = "clean"

    return score, label, reasons


async def validate_domain(domain: str, source: str = "manual") -> Dict[str, Any]:
    """Full validation pipeline for a single domain."""
    domain = domain.lower().strip(". ")
    if domain.startswith("*."):
        domain = domain[2:]
    if not domain or " " in domain:
        return {"error": "invalid domain"}

    existing = DB.get(domain)
    first_seen = existing["first_seen"] if existing else datetime.now(timezone.utc).isoformat()

    # `.bet.br` is reserved by registro.br policy for SPA-authorized operators
    # only — every `.bet.br` registration is, by the registration rule itself,
    # licensed. Treat the TLD as whitelist-equivalent.
    licensed = (
        domain.endswith(".bet.br")
        or domain in SPA_WHITELIST
        or any(domain.endswith("." + w) for w in SPA_WHITELIST)
    )

    ip = await resolve_ip(domain)

    async with httpx.AsyncClient(follow_redirects=True) as client:
        infra = await fetch_infra(ip, client) if ip else {}
        site = await fetch_site(domain, client) if ip else {"ok": False, "error": "dns_fail"}

        cnpj_info = None
        if site.get("ok") and site.get("cnpj_hits"):
            # Check first CNPJ found on the page
            cnpj_info = await check_cnpj(site["cnpj_hits"][0], client)

    record = {
        "domain": domain,
        "first_seen": first_seen,
        "last_checked": datetime.now(timezone.utc).isoformat(),
        "source": source,
        "ip": ip,
        "licensed": licensed,
        "infra": infra,
        "site": site,
        "cnpj": cnpj_info,
    }
    score, label, reasons = score_risk(record)
    record["risk_score"] = score
    record["risk_label"] = label
    record["reasons"] = reasons

    DB[domain] = record
    _sb_persist_domain(record)
    STATS["total_scanned"] = len(DB)
    STATS["total_flagged"] = sum(1 for r in DB.values() if r["risk_label"] in ("high_risk", "suspicious"))
    STATS["total_licensed"] = sum(1 for r in DB.values() if r["licensed"])
    STATS["total_unknown"] = sum(1 for r in DB.values() if r["risk_label"] in ("unreachable", "low_risk", "clean") and not r["licensed"])

    await push_log(
        f"[{label.upper()}] {domain} score={score} ip={ip or 'n/a'} signals={len(site.get('signals', []))}",
        "warn" if label in ("high_risk", "suspicious") else "info",
    )
    return record


# ---------------------------------------------------------------------------
# CT log poller
# ---------------------------------------------------------------------------
async def crt_poll_keyword(kw: str, client: httpx.AsyncClient) -> List[str]:
    """Query crt.sh for a keyword, return unique domain candidates."""
    try:
        r = await client.get(CRT_URL.format(kw=kw), timeout=30.0)
        if r.status_code != 200:
            return []
        try:
            entries = r.json()
        except Exception:
            return []
        domains = set()
        for e in entries[:200]:  # cap per keyword per cycle
            name = (e.get("name_value") or "").strip()
            for line in name.splitlines():
                line = line.strip(" .*").lower()
                if not line or " " in line:
                    continue
                # Only track actual domain names
                if re.match(r"^[a-z0-9][a-z0-9\.\-]*\.[a-z]{2,}$", line):
                    domains.add(line)
        return list(domains)
    except httpx.TimeoutException:
        return []
    except Exception as e:
        await push_log(f"crt.sh error for '{kw}': {e}", "error")
        return []


async def poller_loop():
    """Background loop: poll crt.sh, validate new candidates."""
    await push_log("CT log poller started", "info")
    STATS["running"] = True
    STATS["started_at"] = datetime.now(timezone.utc).isoformat()

    async with httpx.AsyncClient() as client:
        while STATS["running"]:
            cycle_start = time.time()
            STATS["last_poll"] = datetime.now(timezone.utc).isoformat()
            STATS["keywords_cycled"] += 1

            for kw in KEYWORDS:
                if not STATS["running"]:
                    break
                await push_log(f"Polling crt.sh for '{kw}'...", "info")
                candidates = await crt_poll_keyword(kw, client)
                # Only process ones we've never seen
                new = [d for d in candidates if d not in DB][:15]
                if new:
                    await push_log(
                        f"  {len(candidates)} cert entries, {len(new)} new candidates", "info"
                    )
                for d in new:
                    try:
                        await validate_domain(d, source=f"crt.sh:{kw}")
                    except Exception as e:
                        await push_log(f"Validation error for {d}: {e}", "error")
                    # Rate-limit: ip-api free = 45/min
                    await asyncio.sleep(1.5)
                await asyncio.sleep(2)

            elapsed = time.time() - cycle_start
            sleep_for = max(5, POLL_INTERVAL - int(elapsed))
            await push_log(
                f"Cycle complete in {elapsed:.1f}s. Next poll in {sleep_for}s. "
                f"Total tracked: {len(DB)} / flagged: {STATS['total_flagged']}",
                "info",
            )
            for _ in range(sleep_for):
                if not STATS["running"]:
                    break
                await asyncio.sleep(1)


# ---------------------------------------------------------------------------
# Telegram scraper (Option C — t.me/s/CHANNEL public preview, no auth)
# ---------------------------------------------------------------------------
_HOST_RE = re.compile(r"^https?://([^/\s]+)", re.I)
_SKIP_HOSTS = {
    "t.me", "telegram.me", "telegram.org", "telesco.pe",
    "youtube.com", "youtu.be", "instagram.com", "facebook.com",
    "twitter.com", "x.com", "whatsapp.com", "wa.me", "tiktok.com",
    "google.com", "bit.ly",
}


def _extract_domain(href: str) -> Optional[str]:
    m = _HOST_RE.match(href.strip())
    if not m:
        return None
    host = m.group(1).lower().split("@")[-1].split(":")[0]
    # Strip path/querystring already handled by regex
    if host in _SKIP_HOSTS:
        return None
    if any(host.endswith("." + s) for s in _SKIP_HOSTS):
        return None
    if not re.match(r"^[a-z0-9][a-z0-9.\-]*\.[a-z]{2,}$", host):
        return None
    return host


async def scrape_telegram_channel(channel: str, client: httpx.AsyncClient) -> Dict[str, Any]:
    """Fetch https://t.me/s/{channel} preview, parse outbound links."""
    url = TELEGRAM_PREVIEW_URL.format(channel=channel)
    result = {
        "channel": channel,
        "url": url,
        "last_scraped": datetime.now(timezone.utc).isoformat(),
        "messages_scanned": 0,
        "domains_found": [],
        "error": None,
    }
    try:
        r = await client.get(
            url,
            timeout=20.0,
            follow_redirects=True,
            headers={
                "User-Agent": (
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/124.0.0.0 Safari/537.36"
                ),
                "Accept-Language": "pt-BR,pt;q=0.9,en;q=0.8",
            },
        )
        if r.status_code != 200:
            result["error"] = f"http_{r.status_code}"
            return result

        soup = BeautifulSoup(r.text, "html.parser")
        title_el = soup.select_one(".tgme_channel_info_header_title")
        if title_el:
            result["channel_title"] = title_el.get_text(strip=True)
        desc_el = soup.select_one(".tgme_channel_info_description")
        if desc_el:
            result["channel_description"] = desc_el.get_text(" ", strip=True)[:500]
        counters = soup.select(".tgme_channel_info_counter")
        for c in counters:
            label = c.select_one(".counter_type")
            value = c.select_one(".counter_value")
            if label and value:
                key = label.get_text(strip=True).lower()  # "subscribers", "photos"
                result[f"count_{key}"] = value.get_text(strip=True)

        messages = soup.select(".tgme_widget_message")
        result["messages_scanned"] = len(messages)
        domains = set()
        for m in messages:
            for a in m.select(".tgme_widget_message_text a[href]"):
                d = _extract_domain(a.get("href", ""))
                if d:
                    domains.add(d)
            # Also check link previews embedded in messages
            for a in m.select(".tgme_widget_message_link_preview a[href]"):
                d = _extract_domain(a.get("href", ""))
                if d:
                    domains.add(d)
        result["domains_found"] = sorted(domains)
        return result
    except httpx.TimeoutException:
        result["error"] = "timeout"
    except Exception as e:
        result["error"] = str(e)[:200]
    return result


async def telegram_poller_loop():
    """Background loop: scrape each Telegram channel, feed new domains to validator."""
    await push_log(
        f"Telegram poller started ({len(TELEGRAM_CHANNELS)} channels, "
        f"every {TELEGRAM_POLL_INTERVAL}s)",
        "info",
    )
    async with httpx.AsyncClient() as client:
        while STATS["running"]:
            cycle_start = time.time()
            for ch in TELEGRAM_CHANNELS:
                if not STATS["running"]:
                    break
                res = await scrape_telegram_channel(ch, client)

                prev = TELEGRAM_DB.get(ch, {})
                known = set(prev.get("all_domains", []))
                fresh = [d for d in res.get("domains_found", []) if d not in known]

                TELEGRAM_DB[ch] = {
                    **prev,
                    **res,
                    "all_domains": sorted(known | set(res.get("domains_found", []))),
                    "new_domains_count": len(fresh),
                    "first_seen": prev.get(
                        "first_seen", datetime.now(timezone.utc).isoformat()
                    ),
                }

                if res.get("error"):
                    await push_log(
                        f"telegram:@{ch} error: {res['error']}", "warn"
                    )
                else:
                    await push_log(
                        f"telegram:@{ch} — {res['messages_scanned']} msgs, "
                        f"{len(res['domains_found'])} domains "
                        f"({len(fresh)} new)",
                        "info",
                    )

                # Push NEW domains through the validation pipeline
                for d in fresh[:10]:  # cap per channel per cycle
                    try:
                        await validate_domain(d, source=f"telegram:@{ch}")
                    except Exception as e:
                        await push_log(
                            f"validation error for {d} (from @{ch}): {e}", "error"
                        )
                    await asyncio.sleep(1.5)  # ip-api rate limit

                await asyncio.sleep(3)  # politeness between channels

            elapsed = time.time() - cycle_start
            sleep_for = max(30, TELEGRAM_POLL_INTERVAL - int(elapsed))
            await push_log(
                f"Telegram cycle complete in {elapsed:.0f}s. "
                f"Next cycle in {sleep_for}s.",
                "info",
            )
            for _ in range(sleep_for):
                if not STATS["running"]:
                    break
                await asyncio.sleep(1)


# ---------------------------------------------------------------------------
# FastAPI app + routes
# ---------------------------------------------------------------------------
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Supabase status line
    if SB:
        await push_log("Supabase persistence ENABLED", "info")
        n = _sb_hydrate_db()
        if n:
            await push_log(f"Hydrated {n} domains from Supabase", "info")
        STATS["total_scanned"] = len(DB)
        STATS["total_flagged"] = sum(
            1 for r in DB.values() if r["risk_label"] in ("high_risk", "suspicious")
        )
        STATS["total_licensed"] = sum(1 for r in DB.values() if r.get("licensed"))
    elif _SB_INIT_ERROR:
        await push_log(
            f"Supabase init failed ({_SB_INIT_ERROR}) — running in-memory only",
            "warn",
        )
    else:
        await push_log(
            "Supabase NOT configured (no SUPABASE_URL/SUPABASE_KEY) — in-memory only",
            "info",
        )

    await load_spa_whitelist()
    t_ct = asyncio.create_task(poller_loop())
    t_tg = asyncio.create_task(telegram_poller_loop())
    yield
    STATS["running"] = False
    for t in (t_ct, t_tg):
        t.cancel()
        try:
            await t
        except Exception:
            pass


app = FastAPI(title="IllegalBet Scanner", version="1.0.0", lifespan=lifespan)
templates = Jinja2Templates(directory="templates")
app.mount("/static", StaticFiles(directory="static"), name="static")


class ScanRequest(BaseModel):
    domain: str


@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})


@app.get("/api/stats")
async def api_stats():
    return {
        **STATS,
        "whitelist_size": len(SPA_WHITELIST),
        "tracked_domains": len(DB),
    }


@app.get("/api/domains")
async def api_domains(
    risk: Optional[str] = None,
    limit: int = Query(200, ge=1, le=2000),
    q: Optional[str] = None,
):
    items = list(DB.values())
    if risk:
        items = [r for r in items if r["risk_label"] == risk]
    if q:
        items = [r for r in items if q.lower() in r["domain"]]
    items.sort(key=lambda r: (r["risk_score"], r["last_checked"]), reverse=True)
    return {"count": len(items), "items": items[:limit]}


@app.get("/api/domain/{domain}")
async def api_domain(domain: str):
    r = DB.get(domain.lower())
    if not r:
        raise HTTPException(404, "not tracked yet")
    return r


@app.get("/api/check")
async def api_check(domain: str):
    """Public endpoint - validate any domain on demand."""
    if not re.match(r"^[a-z0-9][a-z0-9\.\-]*\.[a-z]{2,}$", domain.lower()):
        raise HTTPException(400, "invalid domain format")
    return await validate_domain(domain, source="api_check")


@app.post("/api/scan")
async def api_scan(req: ScanRequest):
    return await validate_domain(req.domain, source="dashboard")


@app.get("/api/logs")
async def api_logs(limit: int = 200):
    return {"logs": list(LOG_BUFFER)[-limit:]}


@app.get("/api/whitelist")
async def api_whitelist():
    return {"count": len(SPA_WHITELIST), "operators": sorted(SPA_WHITELIST)}


@app.get("/api/keywords")
async def api_keywords():
    """Every pattern the scanner checks for. Used by the Keywords UI."""
    return {
        "ct_poll_keywords": {
            "description": "Keywords queried against crt.sh Certificate Transparency logs every cycle",
            "items": KEYWORDS,
        },
        "betting_signals": {
            "description": "Portuguese-language text patterns scanned in page body (regex, case-insensitive)",
            "items": [
                {"label": "aposte",              "pattern": r"\baposte\b"},
                {"label": "saque rápido",        "pattern": r"\bsaque\s*r[aá]pido\b"},
                {"label": "pix",                 "pattern": r"\bpix\b"},
                {"label": "cassino",             "pattern": r"\bcassino\b"},
                {"label": "slots",               "pattern": r"\bslots?\b"},
                {"label": "caça-níqueis",        "pattern": r"\bca[cç]a-?n[ií]queis?\b"},
                {"label": "bônus de boas-vindas","pattern": r"\bbônus\s*de\s*boas?-?vindas\b"},
                {"label": "jogo do tigrinho",    "pattern": r"\bjogo\s*do\s*tigrinho\b"},
                {"label": "fortune tiger",       "pattern": r"\bfortune\s*tiger\b"},
                {"label": "aviator",             "pattern": r"\bavi[aã]tor\b"},
                {"label": "pragmatic",           "pattern": r"\bpragmatic\b"},
                {"label": "evolution gaming",    "pattern": r"\bevolution\s*gaming\b"},
                {"label": "roleta",              "pattern": r"\brolet[ae]\b"},
                {"label": "blackjack",           "pattern": r"\bblackjack\b"},
            ],
        },
        "tech_fingerprints": {
            "description": "Tech stack / script fingerprints scanned in raw HTML",
            "gambling_providers": [
                {"name": "pragmatic-play",   "detects": "Pragmatic Play slot / casino content — operator-exclusive"},
                {"name": "evolution-gaming", "detects": "Evolution Gaming live dealer — operator-exclusive"},
                {"name": "spribe-aviator",   "detects": "Spribe / Aviator crash game — operator-exclusive"},
                {"name": "pg-soft",          "detects": "PG Soft slot content (e.g. Fortune Tiger) — operator-exclusive"},
            ],
            "payment": [
                {"name": "pix-payment", "detects": "Pix (BRL instant-payment) references in HTML"},
            ],
            "analytics": [
                {"name": "hotjar", "detects": "Hotjar session recording"},
                {"name": "gtm",    "detects": "Google Tag Manager"},
            ],
        },
        "tld_rules": [
            {
                "tld": ".bet.br",
                "rule": "auto-licensed → score 0",
                "rationale": "registro.br issues .bet.br only to SPA-authorized operators, so every .bet.br registration is licensed by definition. The scanner treats the TLD as whitelist-equivalent.",
            },
            {
                "tld": ".bet (generic) or any other .bet-family ccTLD",
                "rule": "+15 combo bonus when a gambling-provider fingerprint is also present",
                "rationale": "generic .bet is legal to register but the combination with operator-only tech is a textbook illegal-operator signature",
            },
        ],
        "score_thresholds": {
            "licensed":    "whitelisted → 0 (short-circuit)",
            "high_risk":   "≥ 70",
            "suspicious":  "40–69",
            "low_risk":    "20–39",
            "clean":       "< 20",
            "unreachable": "flat 20 when homepage fetch fails",
        },
    }


@app.get("/api/telegram/channels")
async def api_telegram_channels():
    items = []
    for ch in TELEGRAM_CHANNELS:
        d = TELEGRAM_DB.get(ch, {})
        # How many of this channel's domains are flagged in the main DB?
        all_domains = d.get("all_domains", [])
        flagged = 0
        high_risk = 0
        for dm in all_domains:
            rec = DB.get(dm)
            if not rec:
                continue
            if rec["risk_label"] in ("high_risk", "suspicious"):
                flagged += 1
            if rec["risk_label"] == "high_risk":
                high_risk += 1
        items.append({
            "channel": ch,
            "url": TELEGRAM_PREVIEW_URL.format(channel=ch),
            "title": d.get("channel_title"),
            "description": d.get("channel_description"),
            "subscribers": d.get("count_subscribers"),
            "last_scraped": d.get("last_scraped"),
            "messages_scanned": d.get("messages_scanned", 0),
            "domains_count": len(all_domains),
            "flagged_count": flagged,
            "high_risk_count": high_risk,
            "error": d.get("error"),
        })
    items.sort(key=lambda x: (x["high_risk_count"], x["flagged_count"]), reverse=True)
    return {"count": len(TELEGRAM_CHANNELS), "items": items}


@app.get("/api/telegram/channel/{channel}")
async def api_telegram_channel(channel: str):
    d = TELEGRAM_DB.get(channel)
    if not d:
        raise HTTPException(404, "channel not yet scraped — wait for next cycle")
    rows = []
    for dm in d.get("all_domains", []):
        rec = DB.get(dm)
        rows.append({
            "domain": dm,
            "risk_label": rec["risk_label"] if rec else "pending",
            "risk_score": rec["risk_score"] if rec else None,
            "licensed": rec["licensed"] if rec else None,
        })
    rows.sort(key=lambda r: (r["risk_score"] or 0), reverse=True)
    return {**d, "domains_detail": rows}


@app.post("/api/telegram/add/{channel}")
async def api_telegram_add(channel: str):
    """Add a Telegram channel handle at runtime."""
    ch = channel.strip().lstrip("@").lstrip("/").strip()
    if not re.match(r"^[A-Za-z0-9_]{3,64}$", ch):
        raise HTTPException(400, "invalid handle")
    if ch in TELEGRAM_CHANNELS:
        return {"ok": True, "already": True, "channel": ch}
    TELEGRAM_CHANNELS.append(ch)
    await push_log(f"Added Telegram channel @{ch} (total {len(TELEGRAM_CHANNELS)})", "info")
    # Trigger one immediate scrape so the user sees data fast
    asyncio.create_task(_scrape_one_now(ch))
    return {"ok": True, "channel": ch, "total": len(TELEGRAM_CHANNELS)}


async def _scrape_one_now(ch: str):
    async with httpx.AsyncClient() as client:
        res = await scrape_telegram_channel(ch, client)
        prev = TELEGRAM_DB.get(ch, {})
        known = set(prev.get("all_domains", []))
        fresh = [d for d in res.get("domains_found", []) if d not in known]
        TELEGRAM_DB[ch] = {
            **prev, **res,
            "all_domains": sorted(known | set(res.get("domains_found", []))),
            "new_domains_count": len(fresh),
            "first_seen": prev.get("first_seen", datetime.now(timezone.utc).isoformat()),
        }
        for d in fresh[:10]:
            try:
                await validate_domain(d, source=f"telegram:@{ch}")
            except Exception:
                pass
            await asyncio.sleep(1.5)


@app.post("/api/poller/{action}")
async def api_poller_control(action: str):
    # Poller control is disabled on the public dashboard — the scanner is
    # designed to run 24/7. To pause/resume, ssh into the VM and restart it.
    raise HTTPException(
        403,
        "poller control is disabled on this deployment",
    )


@app.websocket("/ws/logs")
async def ws_logs(ws: WebSocket):
    await ws.accept()
    WS_CLIENTS.append(ws)
    # Send last 30 buffered lines
    for entry in list(LOG_BUFFER)[-30:]:
        try:
            await ws.send_json(entry)
        except Exception:
            break
    try:
        while True:
            # Keep the connection open; client sends pings via ws.ping
            await asyncio.sleep(30)
            try:
                await ws.send_json({"t": datetime.now(timezone.utc).isoformat(),
                                    "level": "ping", "msg": "keepalive"})
            except Exception:
                break
    except WebSocketDisconnect:
        pass
    finally:
        if ws in WS_CLIENTS:
            WS_CLIENTS.remove(ws)


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", "8000"))
    uvicorn.run("main:app", host="0.0.0.0", port=port, reload=False)
