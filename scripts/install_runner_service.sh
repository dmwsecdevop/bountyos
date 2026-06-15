#!/usr/bin/env bash
set -euo pipefail

: "${BOUNTYOS_SERVER:?Set BOUNTYOS_SERVER, e.g. https://your-service.run.app}"
: "${BOUNTYOS_RUNNER_ID:?Set BOUNTYOS_RUNNER_ID}"
: "${BOUNTYOS_RUNNER_TOKEN:?Set BOUNTYOS_RUNNER_TOKEN}"

NAME="${BOUNTYOS_RUNNER_NAME:-$(hostname)}"
LABELS="${BOUNTYOS_RUNNER_LABELS:-parrot,remote}"
ROOT="${HOME}/.local/share/bountyos-runner"
SERVICE_DIR="${HOME}/.config/systemd/user"
SOURCE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

mkdir -p "$ROOT" "$SERVICE_DIR"
python3 -m venv "$ROOT/venv"
"$ROOT/venv/bin/pip" install --upgrade pip websockets
install -m 0755 "$SOURCE_DIR/runner/bountyos_runner.py" "$ROOT/bountyos_runner.py"
install -m 0644 "$SOURCE_DIR/runner/tool_specs.json" "$ROOT/tool_specs.json"

cat > "$ROOT/runner.env" <<EOF
BOUNTYOS_SERVER=$BOUNTYOS_SERVER
BOUNTYOS_RUNNER_ID=$BOUNTYOS_RUNNER_ID
BOUNTYOS_RUNNER_TOKEN=$BOUNTYOS_RUNNER_TOKEN
BOUNTYOS_RUNNER_NAME=$NAME
BOUNTYOS_RUNNER_LABELS=$LABELS
EOF
chmod 600 "$ROOT/runner.env"

cat > "$SERVICE_DIR/bountyos-runner.service" <<EOF
[Unit]
Description=BountyOS outbound tool runner
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
EnvironmentFile=$ROOT/runner.env
ExecStart=$ROOT/venv/bin/python $ROOT/bountyos_runner.py
Restart=always
RestartSec=5
NoNewPrivileges=true
PrivateTmp=true

[Install]
WantedBy=default.target
EOF

systemctl --user daemon-reload
systemctl --user enable --now bountyos-runner.service
loginctl enable-linger "$USER" >/dev/null 2>&1 || true

echo "Installed BountyOS runner."
echo "Status: systemctl --user status bountyos-runner"
echo "Logs:   journalctl --user -u bountyos-runner -f"
