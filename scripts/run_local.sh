#!/usr/bin/env sh
# Desarrollo local sin Docker (SQLite). Terminal 1: API. Terminal 2: frontend (npm run dev).
set -e
cd "$(dirname "$0")/../backend"
[ -d .venv ] || python3 -m venv .venv
. .venv/bin/activate
pip install -q -r requirements.txt
SEED_DEMO=true ADMIN_PASSWORD="${ADMIN_PASSWORD:-Admin#Local-2026}" uvicorn app.main:app --reload --port 8000
