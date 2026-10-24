"""Consented network-wide DNS telemetry from NextDNS.

A Wi-Fi client cannot see another client's traffic on a hotspot: the
hotspot forwards packets straight to the internet, and the Mac is just
another client. The honest way to add network-wide website visibility is
to have each participant explicitly point their device at a resolver whose
query log you can read. This module ingests a NextDNS profile's logs,
stores a bounded local history, and classifies lookups with conservative,
transparent indicators.

What this is not: page content, HTTPS URLs, passwords, messages, or a
silent capture of someone else's browsing. DNS logs also contain
background app, advertising and operating-system lookups, and a domain in
the log is not proof that someone opened that website.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import math
import os
import re
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter
from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

try:
    from . import database as db
    from .http_util import ssl_context
except ImportError:  # pragma: no cover - import-style fallback
    import database as db
    from http_util import ssl_context

SOURCE = "NextDNS"
FETCH_LIMIT = 500
CACHE_TTL = 12
CACHE_ERROR_TTL = 30
DEFAULT_RETENTION_DAYS = 30
MAX_RETENTION_DAYS = 3650
CONFIG_FILENAME = "nextdns.json"
DEFAULT_POLL_SECONDS = 60
MIN_POLL_SECONDS = 15
MAX_POLL_SECONDS = 3600

CONSENT_NOTE = (
    "This view only includes devices whose owners explicitly configured the "
    "CyberShield NextDNS profile. DNS logging shows lookups, not visits: "
    "background app traffic, ads, VPNs, encrypted DNS and cached answers all "
    "affect what appears here. A domain in this table does not prove that a "
    "person opened that website."
)

LIMITATIONS = [
    "DNS answers are not page views. Cached answers produce no new log entry.",
    "HTTPS page content, URLs after the domain, searches and passwords are never visible.",
    "A VPN, private DNS resolver or app with its own resolver bypasses this profile.",
    "NextDNS retains its own copy of the logs; clearing CyberShield history does not delete it.",
    "The dashboard reads the latest page of NextDNS logs; a very busy network can exceed one page between polls.",
]

# TLDs with well-documented abuse rates. This is an indicator, not a verdict:
# legitimate registrations exist on every one of these.
HIGH_ABUSE_TLDS = {
    "tk", "ml", "ga", "cf", "gq", "top", "click", "work", "zip", "mov",
    "buzz", "cam", "rest", "fit", "support", "surf", "bar", "loan", "win",
    "bid", "trade", "date", "faith", "party", "men", "cricket", "accountant",
    "webcam",
}

BLOCKLIST_WORDS = (
    "malware", "phishing", "spam", "botnet", "ransomware", "cryptomining",
    "cryptojacking", "command and control", "c2", "malicious", "threat",
)

INDICATOR_LABELS = {
    "raw-ip": "Domain is a raw IP address",
    "punycode": "Punycode / possible homograph",
    "deep-subdomain": "Unusually deep subdomain chain",
    "long-name": "Unusually long DNS name",
    "high-entropy": "High-entropy label (possible DGA or tunnelling)",
    "high-abuse-tld": "TLD with a high abuse rate",
    "onion": "Tor hidden-service address",
    "blocked-by-policy": "Blocked by the DNS profile",
    "blocklist-match": "Blocklist reason reported by NextDNS",
}

_cache = {"at": 0.0, "fingerprint": "", "result": {}}
_paused = False
_lock = threading.Lock()
_fetch_lock = threading.Lock()
_bg = {"thread": None, "stop": threading.Event(), "last": 0.0, "error": ""}
_bg_lock = threading.Lock()


class NextDNSNotConfigured(RuntimeError):
    pass


class NextDNSError(RuntimeError):
    pass


def _config_dir():
    override = os.getenv("CYBERSHIELD_CONFIG_DIR", "").strip()
    return override or os.path.join(os.path.expanduser("~"), ".cybershield")


def _config_path():
    return os.path.join(_config_dir(), CONFIG_FILENAME)


def _read_config_file():
    """Return locally stored credentials, or {} when absent or unreadable."""
    try:
        with open(_config_path(), "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return {}
    if not isinstance(data, dict):
        return {}
    key = str(data.get("api_key") or "").strip()
    profile = str(data.get("profile_id") or "").strip()
    if not key or not profile:
        return {}
    try:
        key, profile = _clean_credentials(key, profile)
    except ValueError:
        return {}
    return {"api_key": key, "profile_id": profile}


def _write_config(api_key, profile_id):
    """Store credentials for this user only. Never logs the key."""
    path = _config_path()
    tmp = f"{path}.{os.getpid()}.{threading.get_ident()}.tmp"
    try:
        os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
        try:
            os.chmod(os.path.dirname(path), 0o700)
        except OSError:
            pass
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump({"api_key": api_key, "profile_id": profile_id}, fh)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
    except OSError as exc:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise OSError("Could not save the local NextDNS configuration.") from exc


def _delete_config():
    try:
        os.unlink(_config_path())
    except FileNotFoundError:
        return False
    except OSError as exc:
        raise OSError("Could not remove the local NextDNS configuration.") from exc
    return True


def _env_credentials():
    key = os.getenv("NEXTDNS_API_KEY", "").strip()
    profile = os.getenv("NEXTDNS_PROFILE_ID", "").strip()
    if not key or not profile:
        return "", ""
    try:
        return _clean_credentials(key, profile)
    except ValueError:
        return "", ""


def config_source():
    if all(_env_credentials()):
        return "environment"
    if _read_config_file():
        return "file"
    return "none"


def _credentials():
    """Environment wins; otherwise use the owner-only local config file."""
    key, profile = _env_credentials()
    if key and profile:
        return key, profile
    stored = _read_config_file()
    return stored.get("api_key", ""), stored.get("profile_id", "")


def _is_local_request(request):
    host = (getattr(getattr(request, "client", None), "host", "") or "").strip().lower()
    if host == "localhost":
        return True
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        return False
    mapped = getattr(addr, "ipv4_mapped", None)
    return addr.is_loopback or bool(mapped and mapped.is_loopback)


def _base_url():
    return (os.getenv("NEXTDNS_BASE_URL", "").strip().rstrip("/")
            or "https://api.nextdns.io")


def retention_days():
    try:
        days = int(os.getenv("DNS_RETENTION_DAYS", DEFAULT_RETENTION_DAYS))
    except (TypeError, ValueError):
        days = DEFAULT_RETENTION_DAYS
    return max(1, min(days, MAX_RETENTION_DAYS))


def background_interval():
    try:
        seconds = int(os.getenv("NEXTDNS_POLL_SECONDS", DEFAULT_POLL_SECONDS))
    except (TypeError, ValueError):
        seconds = DEFAULT_POLL_SECONDS
    return max(MIN_POLL_SECONDS, min(seconds, MAX_POLL_SECONDS))


def _clean_credentials(api_key, profile_id):
    api_key = (api_key or "").strip()
    profile_id = (profile_id or "").strip()
    if not api_key or not profile_id:
        raise ValueError("Enter both the NextDNS API key and the profile ID.")
    if len(api_key) > 512 or any(ord(ch) < 33 or ord(ch) > 126 for ch in api_key):
        raise ValueError("That API key does not look valid.")
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", profile_id):
        raise ValueError("That profile ID does not look valid.")
    return api_key, profile_id


def _fingerprint(key, profile):
    # Enough to notice a credential change, not enough to recover the key.
    return hashlib.sha256(f"{profile}\x00{key}".encode("utf-8")).hexdigest()


def _entropy(text):
    if not text:
        return 0.0
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in Counter(text).values())


def _reason_texts(reasons):
    out = []
    for item in (reasons if isinstance(reasons, list) else [reasons]):
        if isinstance(item, dict):
            text = item.get("name") or item.get("id") or item.get("description")
        else:
            text = item
        if text:
            out.append(str(text)[:160])
    return out[:8]


def _epoch_dt(value):
    number = float(value)
    if abs(number) >= 1e11:
        number /= 1000.0
    return datetime.fromtimestamp(number, tz=timezone.utc)


def _iso_z(value):
    """Normalize NextDNS timestamps so SQLite text ordering matches time."""
    if not value:
        return ""
    try:
        if isinstance(value, (int, float)):
            dt = _epoch_dt(value)
        else:
            raw = str(value).strip()
            if re.fullmatch(r"\d{9,16}(\.\d+)?", raw):
                dt = _epoch_dt(raw)
            else:
                if raw.endswith("Z"):
                    raw = raw[:-1] + "+00:00"
                dt = datetime.fromisoformat(raw)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            dt = dt.astimezone(timezone.utc)
    except (OverflowError, OSError, ValueError, TypeError):
        return str(value)[:40]
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


def _root_domain(domain):
    name = (domain or "").strip().lower().rstrip(".")
    if not name:
        return ""
    try:
        ipaddress.ip_address(name)
        return name
    except ValueError:
        pass
    labels = [x for x in name.split(".") if x]
    if len(labels) <= 2:
        return ".".join(labels)
    return ".".join(labels[-2:])


def classify_domain(domain, status="", reasons=None):
    """Return (severity, indicator keys) for one lookup.

    Deliberately conservative: a single unusual label is an indicator, not
    an accusation. Only shapes that are hard to explain for a normal website
    (raw IP, punycode, long random labels) reach "suspicious".
    """
    name = (domain or "").strip().lower().rstrip(".")
    indicators = []
    if not name:
        return "normal", indicators

    try:
        ipaddress.ip_address(name)
        indicators.append("raw-ip")
        labels = []
    except ValueError:
        labels = [x for x in name.split(".") if x]

    if name.startswith("xn--") or any(x.startswith("xn--") for x in labels):
        indicators.append("punycode")
    if len(name) >= 80:
        indicators.append("long-name")
    if len(labels) >= 5 and len(name) >= 45:
        indicators.append("deep-subdomain")
    if labels:
        tld = labels[-1]
        if tld in HIGH_ABUSE_TLDS:
            indicators.append("high-abuse-tld")
        if tld == "onion":
            indicators.append("onion")
        candidates = [labels[0]]
        if len(labels) >= 2:
            candidates.append(labels[-2])
        for label in candidates:
            clean = label.replace("-", "")
            if len(clean) >= 14 and _entropy(clean) >= 3.7:
                indicators.append("high-entropy")
                break

    reason_text = " ".join(_reason_texts(reasons)).lower()
    blocked = str(status or "").lower() == "blocked"
    if blocked:
        indicators.append("blocked-by-policy")
    if any(word in reason_text for word in BLOCKLIST_WORDS):
        indicators.append("blocklist-match")

    # Keep the order stable and remove duplicates.
    indicators = list(dict.fromkeys(indicators))
    if "blocklist-match" in indicators:
        severity = "alert"
    elif any(x in indicators for x in ("raw-ip", "punycode", "high-entropy")):
        severity = "suspicious"
    elif indicators:
        severity = "watch"
    else:
        severity = "normal"
    return severity, indicators


def normalize_record(record):
    """Turn one NextDNS log record into the shape CyberShield stores."""
    if not isinstance(record, dict):
        return None
    domain = str(record.get("domain") or "").strip().lower().rstrip(".")[:253]
    if not domain:
        return None

    device_field = record.get("device")
    device_obj = device_field if isinstance(device_field, dict) else {}
    raw_device = (device_obj.get("name") or
                  (device_field if isinstance(device_field, str) else "") or
                  record.get("client") or "")
    device = str(raw_device).strip()[:120]
    status = str(record.get("status") or "").strip().lower()[:40]
    reasons = _reason_texts(record.get("reasons") or [])
    severity, indicator_keys = classify_domain(domain, status, reasons)
    root = record.get("root")
    if isinstance(root, dict):
        root = root.get("name") or root.get("domain")
    root = str(root or "").strip().lower().rstrip(".")[:253] or _root_domain(domain)

    return {
        "ts": _iso_z(record.get("timestamp")),
        "domain": domain,
        "root_domain": root,
        "device": device or "Unidentified device",
        "device_model": str(device_obj.get("model") or "").strip()[:80],
        "device_id": str(device_obj.get("id") or "").strip()[:120],
        "client_ip": str(record.get("clientIp") or record.get("client_ip") or "").strip()[:64],
        "protocol": str(record.get("protocol") or "").strip()[:32],
        "status": status or "unknown",
        "reasons": reasons,
        "severity": severity,
        "indicators": [{"key": k, "label": INDICATOR_LABELS.get(k, k)}
                       for k in indicator_keys],
        "source": SOURCE,
    }


def parse_logs(payload):
    """Normalize a logs API payload. Accepts {data: [...]} or a bare list."""
    if isinstance(payload, dict):
        records = payload.get("data")
        if records is None:
            records = []
        if not isinstance(records, list):
            raise NextDNSError("NextDNS returned an unexpected log payload.")
    elif isinstance(payload, list):
        records = payload
    else:
        records = []
    out = []
    seen = set()
    for record in records:
        event = normalize_record(record)
        if not event:
            continue
        key = (event["ts"], event["domain"], event["device"],
               event["client_ip"], event["status"])
        if key in seen:
            continue
        seen.add(key)
        out.append(event)
    return out


def _fetch_logs(key, profile, limit=FETCH_LIMIT):
    """Fetch with explicit credentials so a connection test can use them first."""
    try:
        key, profile = _clean_credentials(key, profile)
    except ValueError as exc:
        raise NextDNSError(str(exc)) from exc
    try:
        limit = int(limit or FETCH_LIMIT)
    except (TypeError, ValueError):
        limit = FETCH_LIMIT
    limit = max(10, min(limit, 1000))
    query = urllib.parse.urlencode({"limit": limit, "sort": "desc", "raw": "0"})
    url = (f"{_base_url()}/profiles/"
           f"{urllib.parse.quote(profile, safe='')}/logs?{query}")
    request = urllib.request.Request(url, headers={
        "X-Api-Key": key,
        "Accept": "application/json",
        "User-Agent": "CyberShield/2.0",
    })
    try:
        with urllib.request.urlopen(request, timeout=15,
                                    context=ssl_context()) as response:
            raw = response.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        if exc.code == 401:
            raise NextDNSError("NextDNS rejected the API key (HTTP 401).")
        if exc.code == 403:
            raise NextDNSError("This API key is not allowed to read that profile (HTTP 403).")
        if exc.code == 404:
            raise NextDNSError("NextDNS profile not found (HTTP 404). Check the profile ID.")
        if exc.code == 429:
            raise NextDNSError("NextDNS rate limit reached (HTTP 429). Try again shortly.")
        raise NextDNSError(f"NextDNS returned HTTP {exc.code}.")
    except urllib.error.URLError:
        raise NextDNSError("Unable to reach NextDNS. Check this machine's internet connection.")
    except OSError:
        raise NextDNSError("Unable to reach NextDNS. Check this machine's internet connection.")

    try:
        payload = json.loads(raw)
    except (ValueError, TypeError):
        raise NextDNSError("NextDNS returned a response that was not valid JSON.")
    if isinstance(payload, dict) and payload.get("errors"):
        raise NextDNSError("NextDNS reported an error for this profile.")
    return parse_logs(payload)


def fetch_logs(limit=FETCH_LIMIT):
    """Fetch the newest rows from the configured NextDNS profile.

    The API key stays in this process. Errors are mapped to short messages
    so a profile ID or key cannot end up in a dashboard response by accident.
    """
    key, profile = _credentials()
    if not key or not profile:
        raise NextDNSNotConfigured(
            "Connect a NextDNS profile in the DNS Activity tab, or set "
            "NEXTDNS_API_KEY and NEXTDNS_PROFILE_ID, then restart CyberShield."
        )
    return _fetch_logs(key, profile, limit)


def sync(force=False):
    """Fetch, store and prune one page of logs. Never raises for API errors."""
    global _paused
    key, profile = _credentials()
    if force:
        with _lock:
            _paused = False
    if not key or not profile:
        with _lock:
            _cache.update({"at": 0.0, "fingerprint": "", "result": {}})
        return {
            "ok": False, "configured": False, "events_added": 0,
            "fetched": 0,
            "error": "NextDNS is not configured. Connect a profile in the "
                     "DNS Activity tab, or set the environment variables.",
        }

    fingerprint = _fingerprint(key, profile)
    with _lock:
        now = time.time()
        if _paused:
            return {"ok": False, "configured": True, "paused": True,
                    "events_added": 0, "fetched": 0, "error": ""}
        cached = _cache.get("result") or {}
        ttl = CACHE_TTL if cached.get("ok") else CACHE_ERROR_TTL
        if (not force and cached.get("configured")
                and _cache.get("fingerprint") == fingerprint
                and now - float(_cache.get("at") or 0) < ttl):
            return {**cached, "cached": True}

    # Only one network fetch at a time. The dashboard can still read cached
    # rows and status while this runs.
    with _fetch_lock:
        with _lock:
            if _paused:
                return {"ok": False, "configured": True, "paused": True,
                        "events_added": 0, "fetched": 0, "error": ""}
            now = time.time()
            cached = _cache.get("result") or {}
            ttl = CACHE_TTL if cached.get("ok") else CACHE_ERROR_TTL
            if (not force and cached.get("configured")
                    and _cache.get("fingerprint") == fingerprint
                    and now - float(_cache.get("at") or 0) < ttl):
                return {**cached, "cached": True}

        try:
            events = fetch_logs()
            added = db.insert_dns_events(events)
            pruned = db.prune_dns_events(retention_days())
            result = {
                "ok": True, "configured": True, "events_added": added,
                "fetched": len(events), "events_pruned": pruned,
                "synced_at": db.now_iso(), "error": "",
            }
        except NextDNSNotConfigured as exc:
            result = {"ok": False, "configured": False, "events_added": 0,
                      "fetched": 0, "error": str(exc)}
        except NextDNSError as exc:
            result = {"ok": False, "configured": True, "events_added": 0,
                      "fetched": 0, "error": str(exc)}
        except Exception as exc:
            result = {"ok": False, "configured": True, "events_added": 0,
                      "fetched": 0,
                      "error": f"NextDNS sync failed ({exc.__class__.__name__})."}

        with _lock:
            _cache["at"] = time.time()
            _cache["fingerprint"] = fingerprint
            _cache["result"] = result
        return result


def connect(api_key, profile_id, request=None):
    """Verify credentials, then store them locally for this user only."""
    global _paused
    key, profile = _clean_credentials(api_key, profile_id)
    if config_source() == "environment":
        raise PermissionError(
            "NextDNS credentials are managed by environment variables. "
            "Update NEXTDNS_API_KEY and NEXTDNS_PROFILE_ID instead."
        )
    with _fetch_lock:
        events = _fetch_logs(key, profile, FETCH_LIMIT)
        _write_config(key, profile)
        added = db.insert_dns_events(events)
        pruned = db.prune_dns_events(retention_days())
        result = {
            "ok": True, "configured": True, "events_added": added,
            "fetched": len(events), "events_pruned": pruned,
            "synced_at": db.now_iso(), "error": "",
        }
        with _lock:
            _paused = False
            _cache["at"] = time.time()
            _cache["fingerprint"] = _fingerprint(key, profile)
            _cache["result"] = result
    return {
        "ok": True,
        "fetched": len(events),
        "events_added": added,
        "status": status_payload(request),
    }


def disconnect(request=None):
    """Forget locally stored credentials. Stored history is left untouched."""
    global _paused
    if config_source() == "environment":
        raise PermissionError(
            "NextDNS credentials are managed by environment variables. "
            "Unset NEXTDNS_API_KEY and NEXTDNS_PROFILE_ID instead."
        )
    with _fetch_lock:
        removed = _delete_config()
        with _lock:
            _paused = False
            _cache.update({"at": 0.0, "fingerprint": "", "result": {}})
    return {"ok": True, "removed": removed, "status": status_payload(request)}


def _background_loop():
    while not _bg["stop"].wait(background_interval()):
        key, profile = _credentials()
        if not key or not profile or _paused:
            continue
        try:
            result = sync()
            _bg["last"] = time.time()
            _bg["error"] = "" if result.get("ok") else result.get("error", "")
        except Exception as exc:
            _bg["error"] = exc.__class__.__name__
    with _bg_lock:
        if _bg["thread"] is threading.current_thread():
            _bg["thread"] = None


def background_running():
    thread = _bg.get("thread")
    return bool(thread and thread.is_alive())


def start_background():
    with _bg_lock:
        if background_running():
            return False
        _bg["stop"].clear()
        thread = threading.Thread(target=_background_loop, daemon=True,
                                  name="cybershield-dns-sync")
        _bg["thread"] = thread
        thread.start()
        return True


def stop_background():
    _bg["stop"].set()
    thread = _bg.get("thread")
    if thread and thread.is_alive() and thread is not threading.current_thread():
        thread.join(timeout=2)


def status_payload(request=None):
    key, profile = _credentials()
    with _lock:
        result = dict(_cache.get("result") or {})
        at = float(_cache.get("at") or 0)
        paused = _paused
    source = config_source()
    return {
        "source": SOURCE,
        "configured": bool(key and profile),
        "config_source": source,
        "can_configure": (source != "environment"
                          and (request is None or _is_local_request(request))),
        "ok": result.get("ok"),
        "last_sync": result.get("synced_at"),
        "last_error": result.get("error", ""),
        "events_added": result.get("events_added", 0),
        "fetched": result.get("fetched", 0),
        "paused": paused,
        "cache_age_s": int(time.time() - at) if at else None,
        "poll_interval_s": CACHE_TTL,
        "background_sync": (background_running() and bool(key and profile)
                            and not paused),
        "background_interval_s": background_interval(),
        "retention_days": retention_days(),
        "setup": {
            "env": ["NEXTDNS_API_KEY", "NEXTDNS_PROFILE_ID"],
            "private_dns": "<device-name>-<profile-id>.dns.nextdns.io",
            "local_config": "~/.cybershield/nextdns.json",
            "note": "Connect a profile from the dashboard, or add both environment "
                    "variables and restart. The API key is never returned by the API.",
        },
        "note": CONSENT_NOTE,
        "limitations": LIMITATIONS,
    }


def _clamp(value, default, low, high):
    try:
        value = int(value)
    except (TypeError, ValueError):
        value = default
    return max(low, min(value, high))


def overview(hours=24, limit=100, device="", query="", severity="", request=None):
    sync()
    window = _clamp(hours, 24, 0, 8760)
    limit = _clamp(limit, 100, 1, 500)
    device = (device or "").strip()[:120]
    query = (query or "").strip()[:120]
    severity = severity if severity in ("flagged", "normal", "watch",
                                        "suspicious", "alert") else ""
    return {
        "source": SOURCE,
        "window_hours": window,
        "filters": {"device": device, "query": query, "severity": severity},
        "stats": db.get_dns_stats(window),
        "devices": db.get_dns_devices(window),
        "domains": db.get_dns_domains(window, limit=12),
        "events": db.get_dns_events(limit=limit, device=device, query=query,
                                    severity=severity, hours=window),
        "status": status_payload(request),
        "note": CONSENT_NOTE,
        "limitations": LIMITATIONS,
    }


def device_detail(name, hours=24, limit=100):
    name = (name or "").strip()[:120]
    window = _clamp(hours, 24, 0, 8760)
    limit = _clamp(limit, 100, 1, 500)
    summary = next((d for d in db.get_dns_devices(window)
                    if d.get("device") == name), None)
    return {
        "device": name,
        "window_hours": window,
        "summary": summary,
        "events": db.get_dns_events(limit=limit, device=name, hours=window),
        "note": CONSENT_NOTE,
    }


def refresh(request=None):
    return {"sync": sync(force=True), "status": status_payload(request)}


def purge(request=None):
    global _paused
    with _fetch_lock:
        with _lock:
            _paused = True
            removed = db.clear_dns_events()
            _cache["at"] = 0.0
            _cache["fingerprint"] = ""
            _cache["result"] = {}
    return {
        "ok": True,
        "removed": removed,
        "paused": True,
        "status": status_payload(request),
        "message": "CyberShield's local DNS history was cleared and ingestion is "
                   "paused. NextDNS retains its own copy. Press Refresh to resume.",
    }


class NextDNSConfig(BaseModel):
    api_key: str = ""
    profile_id: str = ""


router = APIRouter(prefix="/api/network", tags=["network-intelligence"])


@router.get("/status")
def network_status(request: Request):
    return status_payload(request)


@router.get("/overview")
def network_overview(request: Request, limit: int = 100, hours: int = 24,
                     device: str = "", q: str = "", severity: str = ""):
    return overview(hours=hours, limit=limit, device=device, query=q,
                    severity=severity, request=request)


@router.get("/events")
def network_events(request: Request, limit: int = 100, hours: int = 24,
                   device: str = "", q: str = "", severity: str = ""):
    sync()
    window = _clamp(hours, 24, 0, 8760)
    return {
        "source": SOURCE,
        "window_hours": window,
        "events": db.get_dns_events(limit=_clamp(limit, 100, 1, 500),
                                    device=(device or "").strip()[:120],
                                    query=(q or "").strip()[:120],
                                    severity=severity if severity in
                                    ("flagged", "normal", "watch", "suspicious", "alert") else "",
                                    hours=window),
        "status": status_payload(request),
        "note": CONSENT_NOTE,
    }


@router.get("/nextdns/events")
def nextdns_events(request: Request, limit: int = 100, hours: int = 24,
                   device: str = "", q: str = "", severity: str = ""):
    """Compatibility alias for the endpoint named in the original design."""
    return network_events(request=request, limit=limit, hours=hours,
                          device=device, q=q, severity=severity)


@router.get("/devices")
def network_devices(request: Request, hours: int = 24):
    sync()
    window = _clamp(hours, 24, 0, 8760)
    return {"source": SOURCE, "window_hours": window,
            "devices": db.get_dns_devices(window),
            "status": status_payload(request), "note": CONSENT_NOTE}


@router.get("/device/{name}")
def network_device(name: str, hours: int = 24, limit: int = 100):
    sync()
    return device_detail(name, hours=hours, limit=limit)


@router.get("/domains")
def network_domains(request: Request, hours: int = 24, limit: int = 25):
    sync()
    window = _clamp(hours, 24, 0, 8760)
    return {"source": SOURCE, "window_hours": window,
            "domains": db.get_dns_domains(window,
                                          limit=_clamp(limit, 25, 1, 100)),
            "status": status_payload(request)}


@router.post("/connect")
def network_connect(payload: NextDNSConfig, request: Request):
    if not _is_local_request(request):
        raise HTTPException(
            status_code=403,
            detail="For safety, enter NextDNS credentials from the machine "
                   "running CyberShield, or configure the environment variables.",
        )
    try:
        return connect(payload.api_key, payload.profile_id, request)
    except PermissionError as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    except (ValueError, NextDNSError, NextDNSNotConfigured) as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except OSError:
        raise HTTPException(
            status_code=500,
            detail="Could not save the local NextDNS configuration.",
        )


@router.delete("/connect")
def network_disconnect(request: Request):
    if not _is_local_request(request):
        raise HTTPException(
            status_code=403,
            detail="For safety, disconnect NextDNS from the machine running CyberShield.",
        )
    try:
        return disconnect(request)
    except PermissionError as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    except OSError:
        raise HTTPException(
            status_code=500,
            detail="Could not remove the local NextDNS configuration.",
        )


@router.post("/refresh")
def network_refresh(request: Request):
    return refresh(request)


@router.delete("/history")
def network_purge(request: Request):
    return purge(request)
