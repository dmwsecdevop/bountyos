#!/usr/bin/env bash
set -euo pipefail

BASE="${BASE:-https://bountyos-wyr2fxj3ta-el.a.run.app}"
TARGET="${1:-}"

if [ -z "$TARGET" ]; then
  echo "Usage: $0 example.com"
  exit 1
fi

submit_job() {
  local tool="$1"
  shift

  curl -sS -X POST "$BASE/api/v1/runners/jobs" \
    -H "Content-Type: application/json" \
    -d "$(python3 - <<PY
import json
print(json.dumps({
  "tool": "$tool",
  "target": "$TARGET",
  "args": list($@),
  "approved": True
}))
PY
)"
}

echo "[1/7] subfinder"
submit_job subfinder '["-d","'"$TARGET"'","-silent"]'

echo "[2/7] naabu"
submit_job naabu '["-host","'"$TARGET"'","-top-ports","100"]'

echo "[3/7] gau"
submit_job gau '["'"$TARGET"'"]'

echo "[4/7] waybackurls"
submit_job waybackurls '["'"$TARGET"'"]'

echo "[5/7] katana"
submit_job katana '["-u","https://'"$TARGET"'","-silent"]'

echo "[6/7] nuclei"
submit_job nuclei '["-u","https://'"$TARGET"'","-severity","low,medium,high,critical"]'

echo "[7/7] jobs"
curl -sS "$BASE/api/v1/runners/jobs" | python3 -m json.tool
