#!/usr/bin/env bash
# Haalt de laatste versie op en herstart de tool. Gebruik: ./update.sh
set -euo pipefail
cd "$(dirname "$0")"
git pull --ff-only
docker compose up -d --build
docker image prune -f >/dev/null
echo "Bijgewerkt naar: $(git log -1 --format='%h %s')"
