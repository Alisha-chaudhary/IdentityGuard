#!/bin/sh
# IdentityGuard Render start script: seed demo data, then serve on $PORT
set -e
python -m app.db.seed
exec uvicorn app.main:app --host 0.0.0.0 --port "$PORT"
