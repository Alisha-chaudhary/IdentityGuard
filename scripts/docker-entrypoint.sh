#!/bin/sh
# Creates tables (and optionally demo data) before starting the API.
set -e
if [ "${IDENTITYGUARD_AUTO_SEED:-false}" = "true" ]; then
  python -m app.db.seed
fi
exec "$@"
