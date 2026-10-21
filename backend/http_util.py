"""Shared outbound HTTP helper.

Two things matter here:

1. The CA bundle must actually resolve. Some Python builds (notably the
   python.org macOS framework build) compile in a certificate path that does
   not exist, so every TLS request fails with CERTIFICATE_VERIFY_FAILED even
   though the machine has perfectly good system roots. This module loads
   certifi when present, otherwise falls back to the well-known system
   bundle paths.

2. TLS verification is never disabled. A reputation feed that cannot be
   authenticated is worthless -- an attacker could inject arbitrary addresses
   into the list and every match would be a false positive. If no CA bundle
   can be loaded the caller is told the feed is unavailable rather than
   being handed unverified data.
"""
import os
import ssl
import urllib.request

CA_PATHS = (
    "/etc/ssl/cert.pem",
    "/etc/ssl/certs/ca-certificates.crt",
    "/private/etc/ssl/cert.pem",
    "/etc/pki/tls/certs/ca-bundle.crt",
    "/etc/ssl/ca-bundle.pem",
    "/usr/local/share/certs/ca-root-nss.crt",
    "/usr/share/ssl/certs/ca-certificates.crt",
)


def ssl_context():
    """An SSL context with a usable CA bundle, or a context that will fail
    loudly rather than silently trusting everything."""
    ctx = ssl.create_default_context()
    try:
        import certifi
        ctx.load_verify_locations(cafile=certifi.where())
        return ctx
    except Exception:
        pass
    for p in CA_PATHS:
        try:
            if os.path.isfile(p):
                ctx.load_verify_locations(cafile=p)
                return ctx
        except Exception:
            continue
    return ctx


def fetch(url, timeout=25, ua="CyberShield/1.0", ctx=None):
    """GET a URL and return the body as text. Raises on failure."""
    req = urllib.request.Request(url, headers={"User-Agent": ua, "Accept": "*/*"})
    with urllib.request.urlopen(req, timeout=timeout,
                                context=ctx or ssl_context()) as r:
        return r.read().decode("utf-8", "replace")
