#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
echo "[1/3] Checking Python..."
python3 --version
if ! command -v nmap >/dev/null 2>&1; then
  echo "NOTE: Nmap is not installed. The sample demo will work, but live scans require:"
  echo "  sudo apt update && sudo apt install -y nmap"
fi
echo "[2/3] Creating virtual environment..."
python3 -m venv .venv || { echo "Could not create venv. On Kali install it with: sudo apt install -y python3-venv"; exit 1; }
. .venv/bin/activate
echo "[3/3] Installing Python dependencies..."
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
mkdir -p reports
echo
echo "Setup complete. Start the dashboard with: ./run.sh"
