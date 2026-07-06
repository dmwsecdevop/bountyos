#!/usr/bin/env bash
# Updated start script to point to the new port 8081
SERVER="${BOUNTYOS_SERVER:-http://127.0.0.1:8081}"
exec python3 runner/bountyos_runner.py --server "$SERVER" ...
