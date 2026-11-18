#!/usr/bin/env bash
# Pulls the latest version and restarts the tool. Usage: ./update.sh
set -euo pipefail
cd "$(dirname "$0")"
git pull --ff-only
docker compose up -d --build
docker image prune -f >/dev/null
echo "Updated to: $(git log -1 --format='%h %s')"
