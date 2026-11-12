#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
if [ ! -d .venv ]; then
  echo "Environment not set up. Run ./setup.sh first."
  exit 1
fi
. .venv/bin/activate
python web_app.py
