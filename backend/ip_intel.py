"""IP intelligence enrichment — local-first, privacy-aware, never raises.

Design rules
------------
1. Local signals first. IP scope, reverse DNS and Team Cymru's DNS-based
   IP-to-ASN service need no API key, no account and no HTTP request to a
   third party. Those run by default.
2. External lookups are opt-in. Geolocation is disabled unless the
   operator enables it, because it sends an observed IP address to a
   third-party resolver. The dashboard shows which enrichers are on.
3. Reputation is matched locally against downloaded feed files, so a raw
   observed IP is never handed to a reputation API.
4. Every result carries provenance. A lookup that failed is reported as
   `unknown`, never as `safe`.
5. Nothing here reads or stores packet payloads.
"""
import ipaddress
import json
import os
import socket
import subprocess
import threading
import time

try:
    import database as db
except ImportError:  # pragma: no cover - import-style fallback
    from backend import database as db

DNS_TIMEOUT = 2.0
GEO_TIMEOUT = 4.0
ASN_TTL = 7 * 24 * 3600      # ASNs move slowly
RDNS_TTL = 24 * 3600
GEO_TTL = 24 * 3600

_lock = threading.Lock()
_cache = {"ip": {}, "ts": {}}

# Providers for optional geolocation. Each returns (country, city, org).
GEO_PROVIDERS = {
    "ip-api.com": "http://ip-api.com/json/{ip}?fields=status,country,countryCode,regionName,city,isp,org,as,asname,hosting,proxy,mobile",
    "ipapi.co": "https://ipapi.co/{ip}/json/",
    "ipinfo.io": "https://ipinfo.io/{ip}/json",
}


def _run(cmd, timeout=6):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.stdout.strip()
    except Exception:
        return ""


def _normalize(ip: str) -> str:
    """Canonicalise an address (BSD netstat prints IPv6 in a legacy form)."""
    s = (ip or "").strip().strip("[]")
    if not s:
        return s
    try:
        return str(ipaddress.ip_address(s))
    except Exception:
        pass
    if ":" in s and "::" not in s:
        groups = s.split(":")
        if 0 < len(groups) < 8:
            try:
                return str(ipaddress.ip_address(":".join(groups + ["0"] * (8 - len(groups)))))
            except Exception:
                pass
    return s


# ---------------- scope ----------------
def classify_scope(ip: str) -> str:
    """public | private | loopback | linklocal | multicast | reserved | cgnat | unknown"""
    try:
        addr = ipaddress.ip_address(_normalize(ip))
    except Exception:
        return "unknown"
    if addr.is_loopback:
        return "loopback"
    if addr.is_link_local:
        return "linklocal"
    if addr.is_multicast:
        return "multicast"
    # Carrier-grade NAT is checked before is_private because some Python
    # versions do not include 100.64.0.0/10 in the private registry.
    try:
        if addr.version == 4 and addr in ipaddress.ip_network("100.64.0.0/10"):
            return "cgnat"
    except Exception:
        pass
    try:
        if addr.version == 4 and (addr in ipaddress.ip_network("192.0.2.0/24")
                                  or addr in ipaddress.ip_network("198.51.100.0/24")
                                  or addr in ipaddress.ip_network("203.0.113.0/24")):
            return "documentation"
    except Exception:
        pass
    if addr.is_private:
        return "private"
    if addr.is_reserved or addr.is_unspecified:
        return "reserved"
    if addr.version == 6:
        return "public"
    return "public"


def is_public(ip: str) -> bool:
    return classify_scope(ip) == "public"


# ---------------- reverse DNS ----------------
def _rdns_worker(ip):
    try:
        host, _alias, _addr = socket.gethostbyaddr(ip)
        return host or ""
    except Exception:
        return ""


def reverse_dns(ip: str):
    """Reverse DNS with a hard deadline.

    socket.gethostbyaddr uses the system resolver, which does not honour
    socket timeouts and can block for many seconds. It is therefore run on
    a worker thread with a deadline; a slow resolver simply yields no name.
    """
    try:
        from concurrent.futures import ThreadPoolExecutor
        with ThreadPoolExecutor(max_workers=1) as ex:
            fut = ex.submit(_rdns_worker, ip)
            return fut.result(timeout=DNS_TIMEOUT + 1) or ""
    except Exception:
        return ""


# ---------------- Team Cymru IP-to-ASN (DNS, no key, no HTTP) ----------------
def cymru_origin(ip: str):
    """origin ASN lookup via Team Cymru's DNS interface.

    Query form: <reversed-ip>.origin.asn.cymru.com  TXT  ->
    "13335 | 104.16.0.0/12 | US | arin | 2013-07-24"
    """
    try:
        addr = ipaddress.ip_address(ip.strip())
    except Exception:
        return None
    if addr.version == 4:
        q = ".".join(reversed(str(addr).split("."))) + ".origin.asn.cymru.com"
    else:
        nib = "".join(reversed(addr.exploded.replace(":", "")))
        q = nib + ".origin6.asn.cymru.com"
    out = _run(["nslookup", "-type=TXT", q], timeout=DNS_TIMEOUT + 1)
    if not out:
        return None
    line = ""
    for ln in out.splitlines():
        if "text =" in ln:
            line = ln.split("text =", 1)[1].strip().strip('"')
            break
        if ln.strip().startswith('"') and "|" in ln:
            line = ln.strip().strip('"')
            break
    if "|" not in line:
        return None
    f = [x.strip() for x in line.split("|")]
    if len(f) < 5:
        return None
    return {"asn": "AS" + f[0], "prefix": f[1], "country": f[2], "rir": f[3],
            "allocated": f[4]}


def cymru_as_name(asn: str):
    """AS number -> AS name via asn.cymru.com TXT.

    Record format: "<asn> | <country> | <rir> | <allocated> | <as name>"
    """
    if not asn:
        return ""
    num = asn.upper().replace("AS", "").strip()
    out = _run(["nslookup", "-type=TXT", "AS" + num + ".asn.cymru.com"],
               timeout=DNS_TIMEOUT + 1)
    if not out:
        return ""
    for ln in out.splitlines():
        if "text =" in ln:
            txt = ln.split("text =", 1)[1].strip().strip('"')
            parts = [p.strip() for p in txt.split("|")]
            # the AS name is the final field
            for p in reversed(parts):
                if p and not p.isdigit() and p.lower() not in ("us", "eu", "apac"):
                    return p
            return parts[-1] if parts else ""
    return ""


def cymru_prefix_netblocks(prefix: str):
    """Announced netblocks for an origin ASN (hosting/CDN ranges)."""
    if not prefix:
        return []
    out = _run(["nslookup", "-type=TXT", f"AS{prefix}.asn.cymru.com"],
               timeout=DNS_TIMEOUT + 1)
    blocks = []
    for ln in out.splitlines():
        if "text =" in ln:
            txt = ln.split("text =", 1)[1].strip().strip('"')
            for f in txt.split("|"):
                if "/" in f and f.count(".") == 3:
                    blocks.append(f.strip())
    return blocks


# ---------------- optional geolocation ----------------
def geo_enabled() -> bool:
    return os.environ.get("CYBERSHIELD_GEO", "").lower() in ("1", "true", "yes", "on")


def geo_provider() -> str:
    return os.environ.get("CYBERSHIELD_GEO_PROVIDER", "ip-api.com").strip()


def geo_lookup(ip: str):
    """Best-effort geolocation. Only runs when explicitly enabled."""
    if not geo_enabled():
        return None
    provider = geo_provider()
    tmpl = GEO_PROVIDERS.get(provider)
    if not tmpl:
        return None
    url = tmpl.replace("{ip}", ip)
    try:
        import http_util
        raw = http_util.fetch(url, timeout=GEO_TIMEOUT)
        data = json.loads(raw)
    except Exception:
        return None
    if provider == "ip-api.com":
        if data.get("status") != "success":
            return None
        return {"country": data.get("country"), "country_code": data.get("countryCode"),
                "region": data.get("regionName"), "city": data.get("city"),
                "isp": data.get("isp"), "org": data.get("org"),
                "asn": data.get("as"), "as_name": data.get("asname"),
                "hosting": bool(data.get("hosting")), "proxy": bool(data.get("proxy"))}
    if provider == "ipapi.co":
        return {"country": data.get("country_name"), "country_code": data.get("country_code"),
                "region": data.get("region"), "city": data.get("city"),
                "isp": data.get("org"), "org": data.get("org"),
                "asn": None, "as_name": None,
                "hosting": bool(data.get("datacenter")), "proxy": False}
    # ipinfo.io
    return {"country": data.get("country"), "country_code": data.get("country"),
            "region": data.get("region"), "city": data.get("city"),
            "isp": data.get("org"), "org": data.get("org"),
            "asn": (data.get("org") or "").split()[0] if data.get("org") else None,
            "as_name": (data.get("org") or "").split(" ", 1)[-1] if data.get("org") else None,
            "hosting": bool(data.get("privacy")), "proxy": bool(data.get("privacy"))}


# ---------------- composite lookup ----------------
def lookup(ip: str, force=False):
    """Full intelligence payload for one IP. Never raises."""
    ip = (ip or "").strip()
    if not ip:
        return {"ip": ip, "scope": "unknown", "error": "no ip given"}
    scope = classify_scope(ip)
    base = {"ip": ip, "scope": scope, "sources": [], "missing": [],
            "rdns": "", "asn": "", "as_name": "", "prefix": "", "rir": "",
            "country": "", "country_source": "", "city": "", "org": "", "isp": "",
            "hosting_hint": False, "proxy_hint": False}

    if scope not in ("public", "cgnat"):
        base["sources"].append("scope")
        base["note"] = "Non-public address — no external enrichment performed."
        return base

    with _lock:
        ts = _cache["ts"].get(ip)
        payload = _cache["ip"].get(ip)
    fresh = payload and ts and (time.time() - ts) < 600
    if fresh and not force:
        out = dict(payload)
        out["_cached"] = True
        return out

    persisted = None if force else db.get_cached_intel(ip, max_age_s=ASN_TTL)
    if persisted:
        out = dict(persisted)
        out["_cached"] = True
        with _lock:
            _cache["ip"][ip] = out
            _cache["ts"][ip] = time.time()
        return out

    # 1. reverse DNS
    rdns = reverse_dns(ip)
    if rdns:
        base["rdns"] = rdns
        base["sources"].append("rdns")
    else:
        base["missing"].append("rdns")

    # 2. ASN / origin
    cym = cymru_origin(ip)
    if cym:
        base["asn"] = cym.get("asn", "")
        base["prefix"] = cym.get("prefix", "")
        base["country"] = cym.get("country", "") or base["country"]
        base["country_source"] = "rir" if base["country"] else ""
        base["rir"] = cym.get("rir", "")
        base["sources"].append("cymru")
        name = cymru_as_name(cym.get("asn", ""))
        if name:
            base["as_name"] = name
            base["org"] = name
    else:
        base["missing"].append("asn")

    # 3. optional geolocation
    if geo_enabled():
        geo = geo_lookup(ip)
        if geo:
            if geo.get("country"):
                base["country"] = geo.get("country")
                base["country_source"] = "geo"
            base["city"] = geo.get("city") or ""
            base["org"] = geo.get("org") or base["org"]
            base["isp"] = geo.get("isp") or ""
            base["as_name"] = geo.get("as_name") or base["as_name"]
            base["hosting_hint"] = bool(geo.get("hosting"))
            base["proxy_hint"] = bool(geo.get("proxy"))
            base["sources"].append("geo")
        else:
            base["missing"].append("geo")
    else:
        base["missing"].append("geo (disabled)")

    # 4. local reputation feeds
    try:
        import feeds
        match = feeds.match(ip)
        base["reputation"] = match
        if match.get("matched"):
            base["sources"].append("feeds")
        else:
            base["missing"].append("feeds")
    except Exception:
        base["reputation"] = {"matched": False, "lists": []}
        base["missing"].append("feeds")

    with _lock:
        _cache["ip"][ip] = dict(base)
        _cache["ts"][ip] = time.time()
    db.cache_intel(ip, base, source=",".join(base["sources"]) or "scope")
    return base


def lookup_many(ips, max_new=25):
    """Return intelligence for the given IPs using only what is already
    cached. Addresses that still need enrichment are queued for the
    background worker, so this call never blocks the request."""
    out = {}
    pending = []
    for ip in ips:
        if ip in out:
            continue
        cached = lookup_cached(ip)
        if cached:
            out[ip] = cached
        else:
            pending.append(ip)
            out[ip] = {"ip": ip, "scope": classify_scope(ip), "sources": [],
                       "missing": ["enrichment pending"],
                       "note": "Intelligence is being gathered in the background."}
    for ip in pending[:max_new]:
        enqueue(ip)
    return out


def lookup_cached(ip):
    """Cached intel for an IP, or None. Never performs network work."""
    with _lock:
        ts = _cache["ts"].get(ip)
        payload = _cache["ip"].get(ip)
    if payload and ts and (time.time() - ts) < 600:
        out = dict(payload)
        out["_cached"] = True
        return out
    persisted = db.get_cached_intel(ip, max_age_s=ASN_TTL)
    if persisted:
        with _lock:
            _cache["ip"][ip] = persisted
            _cache["ts"][ip] = time.time()
        out = dict(persisted)
        out["_cached"] = True
        return out
    return None


# ---------------- background enrichment worker ----------------
_queue = []
_q_lock = threading.Lock()
_worker = {"thread": None, "done": 0, "failed": 0, "last": ""}


def enqueue(ip):
    """Queue an address for background enrichment (deduplicated)."""
    ip = (ip or "").strip()
    if not ip or classify_scope(ip) not in ("public", "cgnat"):
        return
    with _q_lock:
        if ip in _queue or ip in _cache["ip"]:
            return
        if len(_queue) < 500:
            _queue.append(ip)
    _ensure_worker()


def _enrich_loop():
    while True:
        time.sleep(1.5)
        with _q_lock:
            ip = _queue.pop(0) if _queue else None
        if not ip:
            continue
        try:
            lookup(ip)
            _worker["done"] += 1
        except Exception:
            _worker["failed"] += 1
        _worker["last"] = ip


def _ensure_worker():
    if _worker["thread"] is None or not _worker["thread"].is_alive():
        t = threading.Thread(target=_enrich_loop, daemon=True,
                             name="cybershield-ip-enrich")
        t.start()
        _worker["thread"] = t


def worker_status():
    with _q_lock:
        pending = len(_queue)
    return {"queued": pending, "enriched": _worker["done"],
            "failed": _worker["failed"], "last": _worker["last"],
            "running": bool(_worker["thread"] and _worker["thread"].is_alive())}


def sources_status():
    """Which enrichers are enabled, so the UI can state it plainly."""
    return {
        "scope": True,
        "reverse_dns": True,
        "asn": {"enabled": True, "provider": "Team Cymru (DNS)",
                "external": False, "note": "DNS-only, no API key, no account."},
        "geo": {"enabled": geo_enabled(), "provider": geo_provider(),
                "external": True,
                "note": ("Geolocation sends the observed IP to a third-party resolver. "
                         "Enable with CYBERSHIELD_GEO=1 or leave off for local-only analysis.")},
        "reputation": {"enabled": True, "provider": "local feed files",
                       "external": False,
                       "note": "Matching happens locally against downloaded lists."},
        "privacy": ("Addresses and hostnames only. No packet payloads are read, "
                    "stored or sent by this module."),
        "worker": worker_status(),
    }
