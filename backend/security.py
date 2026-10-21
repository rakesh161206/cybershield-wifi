"""Security middleware for the CyberShield dashboard.

Fixes three problems:
  1. CORS was open to every website            -> only your own origins allowed
  2. DNS-rebinding attacks (fake hostnames)    -> Host header must be on an allow-list
  3. Any page could POST /api/real/disconnect  -> state-changing requests need a session token

Usage in main.py (replace the existing CORSMiddleware block):

    from security import install_security
    install_security(app)

Environment variables (all optional):
    CYBERSHIELD_HOST            bind address used by run.sh   (default 127.0.0.1)
    CYBERSHIELD_ALLOWED_HOSTS   extra hostnames/IPs, comma separated, e.g. your phone-view IP
    CYBERSHIELD_ALLOWED_ORIGINS extra origins, comma separated, e.g. http://192.168.1.20:8000
    CYBERSHIELD_TOKEN           fixed token (default: random on every start)
"""
import os
import secrets

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

PORT = os.getenv("PORT", "8000")

_default_hosts = {"127.0.0.1", "localhost", "::1"}
_extra_hosts = {h.strip() for h in os.getenv("CYBERSHIELD_ALLOWED_HOSTS", "").split(",") if h.strip()}
ALLOWED_HOSTS = _default_hosts | _extra_hosts

_default_origins = {f"http://127.0.0.1:{PORT}", f"http://localhost:{PORT}"}
_extra_origins = {o.strip() for o in os.getenv("CYBERSHIELD_ALLOWED_ORIGINS", "").split(",") if o.strip()}
ALLOWED_ORIGINS = sorted(_default_origins | _extra_origins)

SESSION_TOKEN = os.getenv("CYBERSHIELD_TOKEN") or secrets.token_urlsafe(32)
TOKEN_HEADER = "x-cybershield-token"
UNSAFE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


def _hostname(host_header: str) -> str:
    """Strip the port from a Host header. Handles IPv6 like [::1]:8000."""
    host = (host_header or "").strip().lower()
    if host.startswith("["):                      # [::1]:8000
        return host[1:].split("]")[0]
    return host.rsplit(":", 1)[0] if host.count(":") == 1 else host


class SecurityMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        # 1) Host check: blocks DNS-rebinding
        if _hostname(request.headers.get("host", "")) not in ALLOWED_HOSTS:
            return JSONResponse({"error": "host not allowed"}, status_code=403)

        # 2) Token check on anything that changes state (CORS preflight is let through)
        if request.method in UNSAFE_METHODS:
            sent = request.headers.get(TOKEN_HEADER, "")
            if not secrets.compare_digest(sent, SESSION_TOKEN):
                return JSONResponse({"error": "missing or bad session token"}, status_code=401)

        return await call_next(request)


def install_security(app: FastAPI) -> None:
    # Added first so it runs after CORS (Starlette runs the last-added middleware first)
    app.add_middleware(SecurityMiddleware)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=ALLOWED_ORIGINS,
        allow_methods=["GET", "POST", "DELETE"],
        allow_headers=["Content-Type", TOKEN_HEADER],
        allow_credentials=False,
    )

    @app.get("/api/session")
    def session():
        # Other websites cannot read this: CORS blocks them and the Host check stops rebinding.
        return {"token": SESSION_TOKEN}

    print(f"[security] allowed hosts: {sorted(ALLOWED_HOSTS)}")
    print(f"[security] allowed origins: {ALLOWED_ORIGINS}")
