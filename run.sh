#!/bin/sh
# CyberShield Wi-Fi launcher (macOS and Linux).
# Windows: use run.bat, or: pip install -r backend\requirements.txt && python -m uvicorn main:app --host 0.0.0.0 --port 8000 --app-dir backend
set -e
cd "$(dirname "$0")/backend"
if ! command -v python3 >/dev/null 2>&1; then
  echo "python3 not found. Install Python 3.12+ first." >&2
  exit 1
fi
python3 -m pip install -r requirements.txt
case "$(uname -s)" in
  Linux*)
    if ! command -v nmcli >/dev/null 2>&1; then
      echo "Note: nmcli not found — Wi-Fi scan details will be limited."
      echo "Debian/Ubuntu: sudo apt install network-manager"
    fi
    ;;
esac
if ! command -v tcpdump >/dev/null 2>&1; then
  echo "Note: tcpdump not found — packet capture panel will be unavailable (metrics still work)."
fi
python3 -m uvicorn main:app --host 0.0.0.0 --port 8000
