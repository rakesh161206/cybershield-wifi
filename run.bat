@echo off
REM CyberShield Wi-Fi launcher (Windows).
cd /d "%~dp0backend"
where python >nul 2>nul
if errorlevel 1 (
  echo Python not found. Install Python 3.12+ from python.org first.
  exit /b 1
)
python -m pip install -r requirements.txt
where tcpdump >nul 2>nul
if errorlevel 1 (
  echo Note: tcpdump not found - packet capture panel will be unavailable ^(metrics still work^).
  echo For captures install Npcap plus WinDump, or Wireshark ^(tshark^).
)
python -m uvicorn main:app --host 0.0.0.0 --port 8000
