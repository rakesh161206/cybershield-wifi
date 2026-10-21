# CyberShield Wi-Fi — simulated demo mode.
#
# The container runs the SIMULATED mode only. Live mode reads your real
# Wi-Fi, ARP table and packets, none of which exist inside a container, so
# the live panels report "unavailable on this host" and the demo tab works
# fully. This image is for demos and CI, not for inspecting a real network.
FROM python:3.12-slim

WORKDIR /app

COPY backend/requirements.txt backend/requirements.txt
RUN pip install --no-cache-dir -r backend/requirements.txt httpx

COPY backend/ backend/
COPY frontend/ frontend/

ENV PYTHONUNBUFFERED=1 \
    CYBERSHIELD_HOST=0.0.0.0 \
    PORT=8000 \
    CYBERSHIELD_ALLOWED_HOSTS=localhost,127.0.0.1 \
    CYBERSHIELD_ALLOWED_ORIGINS=http://localhost:8000,http://127.0.0.1:8000

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/api/stats', timeout=4)" || exit 1

CMD ["python", "-m", "uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--app-dir", "backend"]
