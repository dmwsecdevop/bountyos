#!/usr/bin/env bash
set -euo pipefail

SERVER="${SERVER:-http://host.docker.internal:8080}"
RUNNER_ID="${RUNNER_ID:-}"
RUNNER_TOKEN="${RUNNER_TOKEN:-}"
RUNNER_NAME="${RUNNER_NAME:-bountyos-self-hosted-runner}"
RUNNER_LABELS="${RUNNER_LABELS:-kali,self-hosted,77-tools,container}"

if [ -z "$RUNNER_ID" ] || [ -z "$RUNNER_TOKEN" ]; then
  echo "RUNNER_ID and RUNNER_TOKEN are required. Create a runner in BountyOS and export the shown credentials." >&2
  exit 1
fi

exec python3 runner/bountyos_runner.py \
  --server "$SERVER" \
  --runner-id "$RUNNER_ID" \
  --token "$RUNNER_TOKEN" \
  --name "$RUNNER_NAME" \
  --labels "$RUNNER_LABELS"
