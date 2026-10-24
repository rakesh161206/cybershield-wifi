# CyberShield Wi-Fi — container preview.
#
# A container cannot read the host's Wi-Fi, ARP table or packets, so live
# host panels will report "unavailable on this host". Use ./run.sh on the
# host for live inspection. This image is useful for UI/API checks and CI.
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
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/api/health', timeout=4)" || exit 1

CMD ["python", "-m", "uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--app-dir", "backend"]
