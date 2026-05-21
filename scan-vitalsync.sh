#!/usr/bin/env bash
# scan-vitalsync.sh — run cosai-mcp against local VitalSync (http://localhost:3000/api/mcp)
# Uses VITALSYNC_TOKEN from /Users/rags/CoSAI/.env.local
#
# ONE-TIME TOKEN SETUP (only needed once, or after token rotation):
#   1. Start VitalSync:  cd ~/vitalsync && pnpm dev
#   2. Open http://localhost:3000  → Settings → MCP → copy your API key (vk_live_...)
#   3. echo "VITALSYNC_TOKEN=vk_live_..." >> /Users/rags/CoSAI/.env.local
#
# Run from anywhere: bash /Users/rags/CoSAI/scan-vitalsync.sh

set -euo pipefail

COSAI=/Users/rags/.pyenv/versions/3.11.9/bin/cosai
ENV=/Users/rags/CoSAI/.env.local
OUT=/tmp/cosai-vitalsync

TOKEN=$(grep '^VITALSYNC_TOKEN=' "$ENV" | cut -d= -f2-)
if [ -z "$TOKEN" ]; then
  echo "❌ VITALSYNC_TOKEN not found in $ENV"
  echo "   See setup instructions at the top of this script."
  exit 1
fi

TARGET=http://localhost:3000/api/mcp
export COSAI_NO_SIGN=1

mkdir -p "$OUT"
echo "▶ Scanning $TARGET  (42 probes — ~2 min)"
echo "  reports → $OUT/"
echo "  (no per-probe output — wait for Done)"
echo ""

"$COSAI" scan "$TARGET" \
  --auth-token "$TOKEN" \
  --allow-private-targets \
  --probe-timeout 10 \
  --probe-delay   0.5 \
  --report-html  "$OUT/report.html" \
  --report-sarif "$OUT/report.sarif" \
  --report-mode  developer

echo ""
echo "Done. Run: open $OUT/report.html"
