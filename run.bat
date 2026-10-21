@echo off
REM CyberShield Wi-Fi launcher (Windows).
REM
REM The server binds to 127.0.0.1 by default: only this machine can reach it.
REM To view the dashboard from a phone on the same Wi-Fi, opt in explicitly:
REM
REM   set CYBERSHIELD_HOST=0.0.0.0
REM   set CYBERSHIELD_ALLOWED_HOSTS=192.168.1.20
REM   set CYBERSHIELD_ALLOWED_ORIGINS=http://192.168.1.20:8000
REM   run.bat
REM
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
if "%CYBERSHIELD_HOST%"=="" set CYBERSHIELD_HOST=127.0.0.1
if "%PORT%"=="" set PORT=8000
if "%CYBERSHIELD_HOST%"=="127.0.0.1" (
  echo Binding to 127.0.0.1 only - this dashboard is reachable from this machine only.
) else (
  echo WARNING: binding to %CYBERSHIELD_HOST%. Anyone who can reach this port can query the dashboard.
  echo Set CYBERSHIELD_ALLOWED_HOSTS and CYBERSHIELD_ALLOWED_ORIGINS to restrict it.
)
echo Open http://127.0.0.1:%PORT%
python -m uvicorn main:app --host %CYBERSHIELD_HOST% --port %PORT%
