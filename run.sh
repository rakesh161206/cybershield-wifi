#!/bin/sh
# CyberShield Wi-Fi launcher (macOS and Linux).
# Windows: use run.bat, or: pip install -r backend\requirements.txt && python -m uvicorn main:app --port 8000 --app-dir backend
#
# The server binds to 127.0.0.1 by default: only this machine can reach it.
# To view the dashboard from a phone on the same Wi-Fi, opt in explicitly:
#
#   CYBERSHIELD_HOST=0.0.0.0 \
#   CYBERSHIELD_ALLOWED_HOSTS=<your-computer-ip> \
#   CYBERSHIELD_ALLOWED_ORIGINS=http://<your-computer-ip>:8000 \
#   ./run.sh
#
set -e
cd "$(dirname "$0")/backend"
if ! command -v python3 >/dev/null 2>&1; then
  echo "python3 not found. Install Python 3.12+ first." >&2
  exit 1
fi

HOST="${CYBERSHIELD_HOST:-127.0.0.1}"
PORT="${PORT:-8000}"

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
if ! command -v lsof >/dev/null 2>&1; then
  echo "Note: lsof not found — IP Intel will not attribute connections to a local program."
fi

if [ "$HOST" = "127.0.0.1" ]; then
  echo "Binding to 127.0.0.1 only — this dashboard is reachable from this machine only."
  echo "Open http://127.0.0.1:${PORT}"
else
  echo "WARNING: binding to ${HOST}. Anyone who can reach this port can query the dashboard."
  echo "Set CYBERSHIELD_ALLOWED_HOSTS and CYBERSHIELD_ALLOWED_ORIGINS to restrict it."
  echo "Open http://127.0.0.1:${PORT}"
fi

exec python3 -m uvicorn main:app --host "$HOST" --port "$PORT"
