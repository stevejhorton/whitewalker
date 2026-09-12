#!/usr/bin/env sh
set -eu
cd "$(dirname "$0")"
(sleep 1 && { command -v open >/dev/null 2>&1 && open http://127.0.0.1:8765 || true; }) &
python3 server.py
