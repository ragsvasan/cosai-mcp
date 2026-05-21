#!/usr/bin/env bash
# scan-mnemo.sh — run cosai-mcp against local Mnemo (http://localhost:8080)
# Uses MCP_TOKEN from /Users/rags/CoSAI/.env.local
# Run from anywhere: bash /Users/rags/CoSAI/scan-mnemo.sh

set -euo pipefail

COSAI=/Users/rags/.pyenv/versions/3.11.9/bin/cosai
ENV=/Users/rags/CoSAI/.env.local
OUT=/tmp/cosai-mnemo

TOKEN=$(grep '^MCP_TOKEN=' "$ENV" | cut -d= -f2-)
TARGET=http://localhost:8080/mcp
export COSAI_NO_SIGN=1

mkdir -p "$OUT"
echo "▶ Scanning $TARGET  (41 probes — ~2 min)"
echo "  reports → $OUT/"
echo "  (no per-probe output — wait for Done)"
echo ""

"$COSAI" scan "$TARGET" \
  --auth-token "$TOKEN" \
  --allow-private-targets \
  --probe-timeout 30 \
  --probe-delay   2.0 \
  --report-html  "$OUT/report.html" \
  --report-sarif "$OUT/report.sarif" \
  --report-mode  developer

echo ""
echo "Done. Run: open $OUT/report.html"
