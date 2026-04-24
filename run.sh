#!/usr/bin/env bash
# IllegalBet Scanner — one-command local launcher (macOS / Linux)
# Usage:  ./run.sh        (first run creates venv, installs deps, starts app)
#         ./run.sh clean  (wipe venv and start fresh)
set -e
cd "$(dirname "$0")"

if [ "$1" = "clean" ]; then
    echo "→ Removing .venv..."
    rm -rf .venv
fi

# --- locate a usable Python --------------------------------------------------
PY=""
for candidate in python3.12 python3.11 python3.10 python3; do
    if command -v "$candidate" >/dev/null 2>&1; then
        ver=$("$candidate" -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
        major=${ver%.*}; minor=${ver#*.}
        if [ "$major" -ge 3 ] && [ "$minor" -ge 10 ]; then
            PY="$candidate"
            break
        fi
    fi
done
if [ -z "$PY" ]; then
    echo "✗ Python 3.10+ not found. Install it first:"
    echo "   macOS:   brew install python@3.11"
    echo "   Ubuntu:  sudo apt install python3.11 python3.11-venv"
    exit 1
fi
echo "→ Using $(command -v $PY) ($($PY --version))"

# --- venv --------------------------------------------------------------------
if [ ! -d .venv ]; then
    echo "→ Creating virtualenv in .venv/..."
    "$PY" -m venv .venv
fi
# shellcheck disable=SC1091
source .venv/bin/activate

# --- deps --------------------------------------------------------------------
if [ ! -f .venv/.deps-installed ] || [ requirements.txt -nt .venv/.deps-installed ]; then
    echo "→ Installing dependencies..."
    pip install --upgrade pip >/dev/null
    pip install -r requirements.txt
    touch .venv/.deps-installed
else
    echo "→ Dependencies already installed."
fi

# --- run ---------------------------------------------------------------------
PORT="${PORT:-8000}"
echo
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  IllegalBet Scanner"
echo "  Dashboard:     http://localhost:$PORT"
echo "  API docs:      http://localhost:$PORT/docs"
echo "  Keywords:      http://localhost:$PORT/api/keywords"
echo "  Telegram:      http://localhost:$PORT/api/telegram/channels"
echo "  Stop:          Ctrl-C"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo

# Open the browser automatically (mac + most linux)
(sleep 2 && (command -v open >/dev/null && open "http://localhost:$PORT" \
    || command -v xdg-open >/dev/null && xdg-open "http://localhost:$PORT" \
    || true)) &

exec python main.py
