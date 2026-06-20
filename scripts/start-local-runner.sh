#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_FILE="${ROOT_DIR}/.runner.env"
SERVER="${SERVER:-${BOUNTYOS_SERVER:-http://127.0.0.1:8080}}"
RUNNER_NAME="${RUNNER_NAME:-${BOUNTYOS_RUNNER_NAME:-bountyos-local-runner}}"
RUNNER_LABELS="${RUNNER_LABELS:-${BOUNTYOS_RUNNER_LABELS:-local,kali,parrot,wsl,self-hosted}}"

if [[ -f "$ENV_FILE" ]]; then
  set -a
  # shellcheck disable=SC1090
  source "$ENV_FILE"
  set +a
fi

SERVER="${SERVER:-${BOUNTYOS_SERVER:-http://127.0.0.1:8080}}"
RUNNER_ID="${RUNNER_ID:-${BOUNTYOS_RUNNER_ID:-}}"
RUNNER_TOKEN="${RUNNER_TOKEN:-${BOUNTYOS_RUNNER_TOKEN:-}}"
RUNNER_NAME="${RUNNER_NAME:-${BOUNTYOS_RUNNER_NAME:-bountyos-local-runner}}"
RUNNER_LABELS="${RUNNER_LABELS:-${BOUNTYOS_RUNNER_LABELS:-local,kali,parrot,wsl,self-hosted}}"

create_runner() {
  python3 - "$SERVER" "$RUNNER_NAME" "$RUNNER_LABELS" <<'PY'
import json, sys, urllib.request
server, name, labels = sys.argv[1:4]
payload = json.dumps({"name": name, "labels": [x.strip() for x in labels.split(',') if x.strip()]}).encode()
req = urllib.request.Request(server.rstrip('/') + '/api/v1/runners/', data=payload, headers={'Content-Type': 'application/json'}, method='POST')
with urllib.request.urlopen(req, timeout=20) as resp:
    data = json.load(resp)
print(data['runner']['id'])
print(data['token'])
PY
}

if [[ -z "$RUNNER_ID" || -z "$RUNNER_TOKEN" ]]; then
  echo "No runner credentials found; creating a local runner via $SERVER ..."
  mapfile -t created < <(create_runner)
  RUNNER_ID="${created[0]}"
  RUNNER_TOKEN="${created[1]}"
  cat > "$ENV_FILE" <<EOFENV
SERVER=$SERVER
RUNNER_ID=$RUNNER_ID
RUNNER_TOKEN=$RUNNER_TOKEN
RUNNER_NAME=$RUNNER_NAME
RUNNER_LABELS=$RUNNER_LABELS
EOFENV
  chmod 600 "$ENV_FILE"
  echo "Saved runner credentials to $ENV_FILE"
fi

export BOUNTYOS_SERVER="$SERVER"
export BOUNTYOS_RUNNER_ID="$RUNNER_ID"
export BOUNTYOS_RUNNER_TOKEN="$RUNNER_TOKEN"
export BOUNTYOS_RUNNER_NAME="$RUNNER_NAME"
export BOUNTYOS_RUNNER_LABELS="$RUNNER_LABELS"

echo "Starting BountyOS runner '$RUNNER_NAME' against $SERVER"
exec python3 "$ROOT_DIR/runner/bountyos_runner.py" \
  --server "$SERVER" \
  --runner-id "$RUNNER_ID" \
  --token "$RUNNER_TOKEN" \
  --name "$RUNNER_NAME" \
  --labels "$RUNNER_LABELS"
