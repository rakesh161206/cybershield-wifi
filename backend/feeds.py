"""Local reputation feeds — downloaded lists, matched entirely on-host.

Nothing about the host's traffic leaves the machine to be checked against a
feed: the lists are pulled down (one-way) and every match is computed
locally. A feed that cannot be downloaded is reported as unavailable
rather than silently treated as "clean".
"""
import ipaddress
import json
import os
import re
import tempfile
import threading
import time
import urllib.request

try:
    import database as db
except ImportError:  # pragma: no cover - import-style fallback
    from backend import database as db

FEED_DIR = os.path.join(tempfile.gettempdir(), "cybershield-feeds")
CONFIG_PATH = os.path.join(FEED_DIR, "feeds.json")

# Default sources. Edit feeds.json in the feed directory to change or add
# any of them; each entry is {"url": ..., "format": "cidr|lines", "type": ...}.
DEFAULT_FEEDS = [
    {"name": "tor-exit", "type": "tor", "format": "lines",
     "url": "https://check.torproject.org/torbulkexitlist"},
    {"name": "firehol-level1", "type": "malware", "format": "cidr",
     "url": "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset"},
    {"name": "firehol-anon", "type": "anonymiser", "format": "cidr",
     "url": "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_anonymous.netset"},
]

_lock = threading.Lock()
_state = {"lists": {}, "loaded_at": {}}
_last_error = ""
TTL = 6 * 3600


def _ensure_dir():
    try:
        os.makedirs(FEED_DIR, exist_ok=True)
    except Exception:
        pass


def _config():
    _ensure_dir()
    cfg = DEFAULT_FEEDS
    try:
        if os.path.isfile(CONFIG_PATH):
            with open(CONFIG_PATH, "r", encoding="utf-8") as f:
                user = json.load(f)
            if isinstance(user, list) and user:
                merged = {d["name"]: dict(d) for d in DEFAULT_FEEDS}
                for entry in user:
                    if isinstance(entry, dict) and entry.get("name"):
                        merged[entry["name"]] = {**merged.get(entry["name"], {}), **entry}
                cfg = list(merged.values())
    except Exception:
        cfg = DEFAULT_FEEDS
    return cfg


def _parse(text, fmt):
    nets = []
    for line in (text or "").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if fmt == "cidr":
            if "/" not in line:
                continue
            try:
                nets.append(ipaddress.ip_network(line, strict=False))
            except Exception:
                continue
        else:
            try:
                nets.append(ipaddress.ip_network(line + "/32", strict=False))
            except Exception:
                continue
    return nets


def _load_from_disk(name):
    path = os.path.join(FEED_DIR, f"{name}.txt")
    if not os.path.isfile(path):
        return None
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return f.read()
    except Exception:
        return None


def _download(url, timeout=25):
    global _last_error
    try:
        import http_util
        return http_util.fetch(url, timeout=timeout)
    except Exception as e:
        _last_error = f"{e.__class__.__name__}: {e}"
        return None


def refresh(name=None):
    """Download one or all configured feeds. Returns a status dict."""
    _ensure_dir()
    cfg = _config()
    results = []
    for entry in cfg:
        fname = entry.get("name")
        if not fname or (name and fname != name):
            continue
        url = entry.get("url", "")
        text = _download(url)
        if text is None:
            disk = _load_from_disk(fname)
            if disk is not None:
                with _lock:
                    _state["lists"][fname] = _parse(disk, entry.get("format", "cidr"))
                    _state["loaded_at"][fname] = time.time()
                db.set_feed_status(fname, url, len(_state["lists"][fname]),
                                   "stale (download failed, using local copy)")
                results.append({"name": fname, "ok": False,
                                "detail": "download failed — using local copy",
                                "error": _last_error})
                continue
            db.set_feed_status(fname, url, 0, "unavailable")
            results.append({"name": fname, "ok": False, "detail": "unavailable",
                            "error": _last_error})
            continue
        try:
            with open(os.path.join(FEED_DIR, f"{fname}.txt"), "w", encoding="utf-8") as f:
                f.write(text)
        except Exception:
            pass
        nets = _parse(text, entry.get("format", "cidr"))
        with _lock:
            _state["lists"][fname] = nets
            _state["loaded_at"][fname] = time.time()
        db.set_feed_status(fname, url, len(nets), "ok")
        results.append({"name": fname, "ok": True, "items": len(nets)})
    return {"results": results, "feed_dir": FEED_DIR}


def _ensure_loaded():
    now = time.time()
    with _lock:
        if _state["lists"]:
            fresh = all(now - v < TTL for v in _state["loaded_at"].values())
            if fresh:
                return
    for entry in _config():
        fname = entry.get("name")
        if not fname:
            continue
        disk = _load_from_disk(fname)
        if disk is not None:
            with _lock:
                _state["lists"][fname] = _parse(disk, entry.get("format", "cidr"))
                _state["loaded_at"][fname] = now
    if not _state["lists"]:
        refresh()


def match(ip):
    """Check one IP against the local lists. Never raises."""
    out = {"matched": False, "lists": [], "checked": []}
    try:
        addr = ipaddress.ip_address((ip or "").strip())
    except Exception:
        return out
    try:
        _ensure_loaded()
    except Exception:
        return out
    with _lock:
        lists = dict(_state["lists"])
        types = {e.get("name"): e.get("type", "") for e in _config()}
    for name, nets in lists.items():
        out["checked"].append(name)
        try:
            if any(addr in n for n in nets):
                out["matched"] = True
                out["lists"].append({"name": name, "type": types.get(name, "")})
        except Exception:
            continue
    return out


def status():
    """Feed freshness + counts for the dashboard."""
    rows = db.get_feed_status()
    known = {r["name"]: r for r in rows}
    out = []
    try:
        _ensure_loaded()
    except Exception:
        pass
    with _lock:
        lists = {k: len(v) for k, v in _state["lists"].items()}
        loaded = dict(_state["loaded_at"])
    for entry in _config():
        name = entry.get("name")
        row = known.get(name, {})
        out.append({
            "name": name,
            "type": entry.get("type", ""),
            "url": entry.get("url", ""),
            "items": lists.get(name, row.get("items", 0)),
            "status": row.get("status", "never refreshed"),
            "last_refresh": row.get("last_refresh", ""),
            "loaded": name in lists,
        })
    return {"feeds": out, "feed_dir": FEED_DIR,
            "note": "Feeds are downloaded one-way and matched locally. "
                    "A feed that cannot be fetched is reported as unavailable, "
                    "not treated as clean."}
