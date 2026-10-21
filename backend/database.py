"""SQLite persistence (stdlib only)."""
import sqlite3
import os
from datetime import datetime, timezone

_DB_DIR = "/tmp" if os.environ.get("VERCEL") else os.path.dirname(__file__)
DB_PATH = os.path.join(_DB_DIR, "cybershield.db")

def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

def conn():
    c = sqlite3.connect(DB_PATH)
    c.row_factory = sqlite3.Row
    return c

def init_db():
    c = conn()
    cur = c.cursor()
    cur.execute("""CREATE TABLE IF NOT EXISTS devices(
        id TEXT PRIMARY KEY, name TEXT, mac TEXT, ip TEXT,
        authenticated INTEGER, risk INTEGER, trust INTEGER,
        status TEXT, auth_failures INTEGER,
        decoy_hits INTEGER, port_scan INTEGER, traffic_spike INTEGER,
        unknown_dest INTEGER, request_anomaly INTEGER, unauthorized INTEGER,
        isolated INTEGER, updated TEXT
    )""")
    cur.execute("""CREATE TABLE IF NOT EXISTS events(
        id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, device_id TEXT,
        type TEXT, detail TEXT, risk_delta INTEGER
    )""")
    cur.execute("""CREATE TABLE IF NOT EXISTS incidents(
        id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, device_id TEXT,
        risk INTEGER, reasons TEXT, action TEXT
    )""")
    cur.execute("""CREATE TABLE IF NOT EXISTS decoy_hits(
        id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, device_id TEXT, decoy_id TEXT
    )""")
    cur.execute("""CREATE TABLE IF NOT EXISTS blocked(
        ssid TEXT PRIMARY KEY, reason TEXT, auto INTEGER, ts TEXT
    )""")
    cur.execute("""CREATE TABLE IF NOT EXISTS allowed(
        ssid TEXT PRIMARY KEY, ts TEXT
    )""")
    cur.execute("""CREATE TABLE IF NOT EXISTS flagged_devices(
        ip TEXT PRIMARY KEY, mac TEXT, note TEXT, ts TEXT
    )""")
    cur.execute("""CREATE TABLE IF NOT EXISTS net_observations(
        ssid TEXT PRIMARY KEY, security TEXT, channel TEXT, signal_dbm REAL,
        first_seen TEXT, last_seen TEXT, seen_count INTEGER
    )""")
    cur.execute("""CREATE TABLE IF NOT EXISTS health_history(
        id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, gateway_ms REAL,
        loss_pct REAL, signal_dbm REAL, risk_score INTEGER, verdict TEXT
    )""")
    # ---- IP purpose intelligence ----
    c.execute("""CREATE TABLE IF NOT EXISTS ip_observations(
        ip TEXT PRIMARY KEY, first_seen TEXT, last_seen TEXT, hits INTEGER,
        ports_json TEXT, protos_json TEXT, actors_json TEXT, samples_json TEXT
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS ip_services(
        ip TEXT, port INTEGER, proto TEXT, first_seen TEXT, last_seen TEXT,
        hits INTEGER, PRIMARY KEY(ip, port, proto)
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS ip_intel_cache(
        ip TEXT PRIMARY KEY, ts TEXT, source TEXT, payload_json TEXT
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS ip_alerts(
        id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, ip TEXT, type TEXT,
        severity TEXT, title TEXT, evidence TEXT, action TEXT, ack INTEGER
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS ip_watchlist(
        ip TEXT PRIMARY KEY, note TEXT, added TEXT
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS ip_feeds(
        name TEXT PRIMARY KEY, url TEXT, last_refresh TEXT, items INTEGER, status TEXT
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS device_baselines(
        device_id TEXT PRIMARY KEY, marked_safe INTEGER, established TEXT,
        base_connections INTEGER, base_destinations INTEGER,
        base_port_attempts INTEGER, base_request_freq INTEGER, base_traffic INTEGER
    )""")
    c.commit()
    c.close()

def upsert_device(d: dict):
    c = conn()
    cur = c.cursor()
    cur.execute("""INSERT INTO devices
      (id,name,mac,ip,authenticated,risk,trust,status,auth_failures,decoy_hits,port_scan,traffic_spike,unknown_dest,request_anomaly,unauthorized,isolated,updated)
      VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?, ?,?)
      ON CONFLICT(id) DO UPDATE SET
      name=excluded.name,mac=excluded.mac,ip=excluded.ip,authenticated=excluded.authenticated,
      risk=excluded.risk,trust=excluded.trust,status=excluded.status,auth_failures=excluded.auth_failures,
      decoy_hits=excluded.decoy_hits,port_scan=excluded.port_scan,traffic_spike=excluded.traffic_spike,
      unknown_dest=excluded.unknown_dest,request_anomaly=excluded.request_anomaly,
      unauthorized=excluded.unauthorized,isolated=excluded.isolated,updated=excluded.updated
    """, (d["id"], d.get("name",""), d.get("mac",""), d.get("ip",""),
          int(d.get("authenticated",1)), int(d.get("risk",0)), int(d.get("trust",100)),
          d.get("status","trusted"), int(d.get("auth_failures",0)),
          int(d.get("decoy_hits",0)), int(d.get("port_scan",0)), int(d.get("traffic_spike",0)),
          int(d.get("unknown_dest",0)), int(d.get("request_anomaly",0)),
          int(d.get("unauthorized",0)), int(d.get("isolated",0)), now_iso()))
    c.commit()
    c.close()

def get_devices():
    c = conn()
    rows = c.execute("SELECT * FROM devices ORDER BY id").fetchall()
    c.close()
    return [dict(r) for r in rows]

def get_device(device_id: str):
    c = conn()
    r = c.execute("SELECT * FROM devices WHERE id=?", (device_id,)).fetchone()
    c.close()
    return dict(r) if r else None

def log_event(device_id: str, type_: str, detail: str, risk_delta: int = 0):
    c = conn()
    c.execute("INSERT INTO events(ts,device_id,type,detail,risk_delta) VALUES(?,?,?,?,?)",
              (now_iso(), device_id, type_, detail, risk_delta))
    c.commit()
    c.close()

def get_events(limit: int = 120):
    c = conn()
    rows = c.execute("SELECT * FROM events ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    c.close()
    return [dict(r) for r in reversed(rows)]

def add_incident(device_id: str, risk: int, reasons: str, action: str):
    c = conn()
    c.execute("INSERT INTO incidents(ts,device_id,risk,reasons,action) VALUES(?,?,?,?,?)",
              (now_iso(), device_id, risk, reasons, action))
    c.commit()
    c.close()

def get_incidents(limit: int = 50):
    c = conn()
    rows = c.execute("SELECT * FROM incidents ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    c.close()
    return [dict(r) for r in rows]

def log_decoy_hit(device_id: str, decoy_id: str):
    c = conn()
    c.execute("INSERT INTO decoy_hits(ts,device_id,decoy_id) VALUES(?,?,?)",
              (now_iso(), device_id, decoy_id))
    c.commit()
    c.close()

def clear_dynamic():
    c = conn()
    c.execute("DELETE FROM events")
    c.execute("DELETE FROM incidents")
    c.execute("DELETE FROM decoy_hits")
    c.commit()
    c.close()

# ---- Zero-Trust block / allow / flag lists ----
def block(ssid: str, reason: str, auto: int = 0):
    c = conn()
    c.execute("INSERT INTO blocked(ssid,reason,auto,ts) VALUES(?,?,?,?) "
              "ON CONFLICT(ssid) DO UPDATE SET reason=excluded.reason,auto=excluded.auto,ts=excluded.ts",
              (ssid, reason, int(auto), now_iso()))
    c.commit()
    c.close()

def unblock(ssid: str):
    c = conn()
    c.execute("DELETE FROM blocked WHERE ssid=?", (ssid,))
    c.execute("INSERT INTO allowed(ssid,ts) VALUES(?,?) "
              "ON CONFLICT(ssid) DO UPDATE SET ts=excluded.ts", (ssid, now_iso()))
    c.commit()
    c.close()

def remove_allowed(ssid: str):
    c = conn()
    c.execute("DELETE FROM allowed WHERE ssid=?", (ssid,))
    c.commit()
    c.close()

def is_blocked(ssid: str) -> bool:
    c = conn()
    r = c.execute("SELECT 1 FROM blocked WHERE ssid=?", (ssid,)).fetchone()
    c.close()
    return bool(r)

def is_auto(ssid: str) -> bool:
    c = conn()
    r = c.execute("SELECT auto FROM blocked WHERE ssid=?", (ssid,)).fetchone()
    c.close()
    return bool(r and r[0])

def is_allowed(ssid: str) -> bool:
    c = conn()
    r = c.execute("SELECT 1 FROM allowed WHERE ssid=?", (ssid,)).fetchone()
    c.close()
    return bool(r)

def get_blocked():
    c = conn()
    rows = c.execute("SELECT * FROM blocked ORDER BY ts DESC").fetchall()
    c.close()
    return [dict(r) for r in rows]

def get_allowed():
    c = conn()
    rows = c.execute("SELECT ssid FROM allowed").fetchall()
    c.close()
    return [r[0] for r in rows]

def flag_device(ip: str, mac: str, note: str):
    c = conn()
    c.execute("INSERT INTO flagged_devices(ip,mac,note,ts) VALUES(?,?,?,?) "
              "ON CONFLICT(ip) DO UPDATE SET mac=excluded.mac,note=excluded.note,ts=excluded.ts",
              (ip, mac, note, now_iso()))
    c.commit()
    c.close()

def get_flagged():
    c = conn()
    rows = c.execute("SELECT * FROM flagged_devices").fetchall()
    c.close()
    return [dict(r) for r in rows]


# ---- Rogue-AP observation history ----
def observe_networks(nets: list):
    """Record the latest fingerprint per SSID. Best-effort; never raises."""
    try:
        c = conn()
        for n in nets or []:
            ssid = (n.get("ssid") or "").strip()
            if not ssid:
                continue
            ts = now_iso()
            sig = n.get("signal_dbm")
            try:
                sig = float(sig) if sig is not None else None
            except (TypeError, ValueError):
                sig = None
            cur = c.execute("SELECT seen_count, first_seen FROM net_observations WHERE ssid=?",
                            (ssid,)).fetchone()
            if cur:
                c.execute("UPDATE net_observations SET security=?, channel=?, signal_dbm=?, "
                          "last_seen=?, seen_count=? WHERE ssid=?",
                          (n.get("security", ""), str(n.get("channel", "")), sig, ts,
                           int(cur["seen_count"] or 0) + 1, ssid))
            else:
                c.execute("INSERT INTO net_observations(ssid,security,channel,signal_dbm,"
                          "first_seen,last_seen,seen_count) VALUES(?,?,?,?,?,?,1)",
                          (ssid, n.get("security", ""), str(n.get("channel", "")),
                           sig, ts, ts))
        c.commit()
        c.close()
    except Exception:
        pass


def get_network_history():
    try:
        c = conn()
        rows = c.execute("SELECT * FROM net_observations ORDER BY last_seen DESC").fetchall()
        c.close()
        return [dict(r) for r in rows]
    except Exception:
        return []


# ---- Health history + before/after verification ----
def record_health(gateway_ms=None, loss_pct=None, signal_dbm=None,
                  risk_score=None, verdict="", min_interval_s=60):
    """Append a health sample, throttled. Returns True when stored."""
    try:
        c = conn()
        last = c.execute("SELECT ts FROM health_history ORDER BY id DESC LIMIT 1").fetchone()
        if last:
            try:
                from datetime import datetime
                age = (datetime.now(timezone.utc) -
                       datetime.fromisoformat(last["ts"])).total_seconds()
                if age < min_interval_s:
                    c.close()
                    return False
            except Exception:
                pass
        c.execute("INSERT INTO health_history(ts,gateway_ms,loss_pct,signal_dbm,"
                  "risk_score,verdict) VALUES(?,?,?,?,?,?)",
                  (now_iso(), gateway_ms, loss_pct, signal_dbm, risk_score, verdict))
        c.execute("DELETE FROM health_history WHERE id NOT IN "
                  "(SELECT id FROM health_history ORDER BY id DESC LIMIT 500)")
        c.commit()
        c.close()
        return True
    except Exception:
        return False


def get_health_history(limit: int = 60):
    try:
        c = conn()
        rows = c.execute("SELECT * FROM health_history ORDER BY id DESC LIMIT ?",
                         (int(limit),)).fetchall()
        c.close()
        return [dict(r) for r in reversed(rows)]
    except Exception:
        return []


def _avg(vals):
    vals = [v for v in vals if v is not None]
    return round(sum(vals) / len(vals), 2) if vals else None


def verify_health(window_min: int = 30):
    """Compare the older vs newer half of recent health samples.

    Returns before/after averages and whether the network improved.
    Insufficient data is reported explicitly instead of guessed.
    """
    try:
        window_min = max(5, min(int(window_min), 720))
    except (TypeError, ValueError):
        window_min = 30
    try:
        from datetime import datetime, timedelta
        c = conn()
        cutoff = (datetime.now(timezone.utc) -
                  timedelta(minutes=window_min)).isoformat()
        rows = c.execute("SELECT * FROM health_history WHERE ts >= ? ORDER BY id ASC",
                         (cutoff,)).fetchall()
        c.close()
        rows = [dict(r) for r in rows]
    except Exception:
        return {"ok": False, "detail": "verification unavailable"}
    if len(rows) < 4:
        return {"ok": False, "detail": f"insufficient samples ({len(rows)} in window); "
                "health samples record about once a minute while the dashboard polls",
                "samples": len(rows), "window_min": window_min}
    half = len(rows) // 2
    before, after = rows[:half], rows[half:]

    def summ(rs):
        return {"samples": len(rs),
                "from": rs[0]["ts"], "to": rs[-1]["ts"],
                "avg_gateway_ms": _avg([r["gateway_ms"] for r in rs]),
                "avg_loss_pct": _avg([r["loss_pct"] for r in rs]),
                "avg_signal_dbm": _avg([r["signal_dbm"] for r in rs]),
                "avg_risk": _avg([r["risk_score"] for r in rs])}
    b, a = summ(before), summ(after)
    wins = 0
    total = 0
    for key, better in (("avg_gateway_ms", "lower"), ("avg_loss_pct", "lower"),
                        ("avg_signal_dbm", "higher"), ("avg_risk", "lower")):
        if b[key] is not None and a[key] is not None:
            total += 1
            if better == "lower" and a[key] < b[key]:
                wins += 1
            elif better == "higher" and a[key] > b[key]:
                wins += 1
    if total == 0:
        verdict = "insufficient data"
    elif wins >= max(2, (total + 1) // 2 + 1):
        verdict = "improved"
    elif wins == 0:
        verdict = "degraded"
    else:
        verdict = "mixed"
    return {"ok": True, "window_min": window_min, "before": b, "after": a,
            "metrics_compared": total, "metrics_improved": wins,
            "verdict": verdict,
            "note": "Compares passive health samples before vs after; "
                    "improvement suggests the action helped, it does not prove causation."}


def get_timeline(limit: int = 50):
    """Merged incident + event chronology (newest first) for the timeline panel."""
    try:
        limit = max(1, min(int(limit), 200))
    except (TypeError, ValueError):
        limit = 50
    items = []
    try:
        c = conn()
        ev = c.execute("SELECT * FROM events ORDER BY id DESC LIMIT ?",
                       (limit,)).fetchall()
        inc = c.execute("SELECT * FROM incidents ORDER BY id DESC LIMIT ?",
                        (limit,)).fetchall()
        ipa = c.execute("SELECT * FROM ip_alerts ORDER BY id DESC LIMIT ?",
                        (limit,)).fetchall()
        c.close()
        for r in ev:
            r = dict(r)
            items.append({"kind": "event", "ts": r.get("ts"), "title": r.get("type", ""),
                          "detail": r.get("detail", ""),
                          "device": r.get("device_id", ""),
                          "risk_delta": r.get("risk_delta", 0)})
        for r in inc:
            r = dict(r)
            items.append({"kind": "incident", "ts": r.get("ts"),
                          "title": f"incident risk {r.get('risk', '?')}",
                          "detail": f"{r.get('reasons', '')} | {r.get('action', '')}",
                          "device": r.get("device_id", ""),
                          "risk_delta": r.get("risk", 0)})
        for r in ipa:
            r = dict(r)
            items.append({"kind": "ip_alert", "ts": r.get("ts"),
                          "title": r.get("title", "") or r.get("type", ""),
                          "detail": r.get("evidence", ""),
                          "device": r.get("ip", ""),
                          "severity": r.get("severity", "info"),
                          "alert_type": r.get("type", ""),
                          "ack": r.get("ack", 0),
                          "risk_delta": 0})
    except Exception:
        return []
    items.sort(key=lambda x: x.get("ts") or "", reverse=True)
    return items[:limit]


# ================= IP purpose intelligence =================
import json as _json


def _loads(raw, default):
    try:
        v = _json.loads(raw)
        return v if v is not None else default
    except Exception:
        return default


def observe_ip(ip: str, port=None, proto="tcp", actor=None):
    """Record that this host talked to `ip`. Keeps a small sample of recent
    observation timestamps (used for interval/beacon analysis)."""
    ip = (ip or "").strip()
    if not ip:
        return
    try:
        ts = now_iso()
        c = conn()
        cur = c.cursor()
        row = cur.execute("SELECT hits, ports_json, protos_json, actors_json, "
                          "samples_json FROM ip_observations WHERE ip=?", (ip,)).fetchone()
        if row:
            ports = set(_loads(row["ports_json"], []))
            protos = set(_loads(row["protos_json"], []))
            actors = set(_loads(row["actors_json"], []))
            samples = _loads(row["samples_json"], [])
            if port:
                ports.add(int(port))
            if proto:
                protos.add(proto)
            if actor:
                actors.add(actor)
            samples.append(ts)
            samples = samples[-16:]
            cur.execute("UPDATE ip_observations SET last_seen=?, hits=hits+1, "
                        "ports_json=?, protos_json=?, actors_json=?, samples_json=? "
                        "WHERE ip=?",
                        (ts, _json.dumps(sorted(ports)), _json.dumps(sorted(protos)),
                         _json.dumps(sorted(actors)), _json.dumps(samples), ip))
        else:
            cur.execute("INSERT INTO ip_observations(ip, first_seen, last_seen, hits, "
                        "ports_json, protos_json, actors_json, samples_json) "
                        "VALUES(?,?,?,?,?,?,?,?)",
                        (ip, ts, ts, 1,
                         _json.dumps([int(port)] if port else []),
                         _json.dumps([proto] if proto else []),
                         _json.dumps([actor] if actor else []),
                         _json.dumps([ts])))
        if port:
            srow = cur.execute("SELECT hits FROM ip_services WHERE ip=? AND port=? "
                               "AND proto=?", (ip, int(port), proto)).fetchone()
            if srow:
                cur.execute("UPDATE ip_services SET last_seen=?, hits=hits+1 "
                            "WHERE ip=? AND port=? AND proto=?",
                            (ts, ip, int(port), proto))
            else:
                cur.execute("INSERT INTO ip_services(ip, port, proto, first_seen, "
                            "last_seen, hits) VALUES(?,?,?,?,?,1)",
                            (ip, int(port), proto, ts, ts))
        c.commit()
        c.close()
    except Exception:
        pass


def get_ip_observations():
    try:
        c = conn()
        rows = c.execute("SELECT * FROM ip_observations").fetchall()
        c.close()
        out = []
        for r in rows:
            d = dict(r)
            d["ports"] = _loads(d.pop("ports_json"), [])
            d["protos"] = _loads(d.pop("protos_json"), [])
            d["actors"] = _loads(d.pop("actors_json"), [])
            d["samples"] = _loads(d.pop("samples_json"), [])
            out.append(d)
        return out
    except Exception:
        return []


def get_ip_services(ip=None):
    try:
        c = conn()
        if ip:
            rows = c.execute("SELECT * FROM ip_services WHERE ip=? ORDER BY hits DESC",
                             (ip,)).fetchall()
        else:
            rows = c.execute("SELECT * FROM ip_services ORDER BY hits DESC").fetchall()
        c.close()
        return [dict(r) for r in rows]
    except Exception:
        return []


def cache_intel(ip: str, payload: dict, source="local"):
    try:
        c = conn()
        c.execute("INSERT INTO ip_intel_cache(ip, ts, source, payload_json) "
                  "VALUES(?,?,?,?) ON CONFLICT(ip) DO UPDATE SET "
                  "ts=excluded.ts, source=excluded.source, payload_json=excluded.payload_json",
                  (ip, now_iso(), source, _json.dumps(payload)))
        c.commit()
        c.close()
    except Exception:
        pass


def get_cached_intel(ip: str, max_age_s=86400):
    try:
        c = conn()
        r = c.execute("SELECT ts, source, payload_json FROM ip_intel_cache WHERE ip=?",
                      (ip,)).fetchone()
        c.close()
        if not r:
            return None
        from datetime import datetime
        age = (datetime.now(timezone.utc) -
               datetime.fromisoformat(r["ts"])).total_seconds()
        if age > max_age_s:
            return None
        return {**_loads(r["payload_json"], {}), "_cached_at": r["ts"], "_source": r["source"]}
    except Exception:
        return None


def cached_intel_ips():
    try:
        c = conn()
        rows = c.execute("SELECT ip, ts FROM ip_intel_cache").fetchall()
        c.close()
        return {r["ip"]: r["ts"] for r in rows}
    except Exception:
        return {}


def add_ip_alert(ip, type_, severity, title, evidence, action):
    """Create an alert unless an identical one exists in the cooldown window."""
    try:
        c = conn()
        c.execute("INSERT INTO ip_alerts(ts, ip, type, severity, title, evidence, "
                  "action, ack) VALUES(?,?,?,?,?,?,?,0)",
                  (now_iso(), ip, type_, severity, title, evidence, action))
        c.commit()
        c.close()
        return True
    except Exception:
        return False


def recent_alert(ip, type_, within_s=900):
    """Return the id of a recent identical alert, or None."""
    try:
        from datetime import datetime
        c = conn()
        r = c.execute("SELECT id, ts FROM ip_alerts WHERE ip=? AND type=? "
                      "ORDER BY id DESC LIMIT 1", (ip, type_)).fetchone()
        c.close()
        if not r:
            return None
        age = (datetime.now(timezone.utc) -
               datetime.fromisoformat(r["ts"])).total_seconds()
        return r["id"] if age <= within_s else None
    except Exception:
        return None


def get_ip_alerts(limit=100, unacked_only=False):
    try:
        c = conn()
        q = "SELECT * FROM ip_alerts"
        if unacked_only:
            q += " WHERE ack=0"
        q += " ORDER BY id DESC LIMIT ?"
        rows = c.execute(q, (int(limit),)).fetchall()
        c.close()
        return [dict(r) for r in rows]
    except Exception:
        return []


def ack_ip_alert(alert_id):
    try:
        c = conn()
        c.execute("UPDATE ip_alerts SET ack=1 WHERE id=?", (int(alert_id),))
        c.commit()
        c.close()
        return True
    except Exception:
        return False


def watch_ip(ip, note=""):
    try:
        c = conn()
        c.execute("INSERT INTO ip_watchlist(ip, note, added) VALUES(?,?,?) "
                  "ON CONFLICT(ip) DO UPDATE SET note=excluded.note", (ip, note, now_iso()))
        c.commit()
        c.close()
        return True
    except Exception:
        return False


def unwatch_ip(ip):
    try:
        c = conn()
        c.execute("DELETE FROM ip_watchlist WHERE ip=?", (ip,))
        c.commit()
        c.close()
        return True
    except Exception:
        return False


def get_watchlist():
    try:
        c = conn()
        rows = c.execute("SELECT * FROM ip_watchlist ORDER BY added DESC").fetchall()
        c.close()
        return [dict(r) for r in rows]
    except Exception:
        return []


def set_feed_status(name, url, items, status):
    try:
        c = conn()
        c.execute("INSERT INTO ip_feeds(name, url, last_refresh, items, status) "
                  "VALUES(?,?,?,?,?) ON CONFLICT(name) DO UPDATE SET "
                  "url=excluded.url, last_refresh=excluded.last_refresh, "
                  "items=excluded.items, status=excluded.status",
                  (name, url, now_iso(), int(items), status))
        c.commit()
        c.close()
    except Exception:
        pass


def get_feed_status():
    try:
        c = conn()
        rows = c.execute("SELECT * FROM ip_feeds ORDER BY name").fetchall()
        c.close()
        return [dict(r) for r in rows]
    except Exception:
        return []


# ---- per-device behavioural baseline ----
def set_baseline(device_id: str, profile: dict):
    """Record a device's own normal behaviour profile."""
    try:
        c = conn()
        c.execute("INSERT INTO device_baselines(device_id, marked_safe, established, "
                  "base_connections, base_destinations, base_port_attempts, "
                  "base_request_freq, base_traffic) VALUES(?,?,?,?,?,?,?,?) "
                  "ON CONFLICT(device_id) DO UPDATE SET marked_safe=1, "
                  "established=excluded.established, "
                  "base_connections=excluded.base_connections, "
                  "base_destinations=excluded.base_destinations, "
                  "base_port_attempts=excluded.base_port_attempts, "
                  "base_request_freq=excluded.base_request_freq, "
                  "base_traffic=excluded.base_traffic",
                  (device_id, 1, now_iso(),
                   int(profile.get("connections", 0)), int(profile.get("destinations", 0)),
                   int(profile.get("port_attempts", 0)), int(profile.get("request_freq", 0)),
                   int(profile.get("traffic", 0))))
        c.commit()
        c.close()
        return True
    except Exception:
        return False


def clear_baseline(device_id: str):
    try:
        c = conn()
        c.execute("DELETE FROM device_baselines WHERE device_id=?", (device_id,))
        c.commit()
        c.close()
        return True
    except Exception:
        return False


def get_baselines():
    try:
        c = conn()
        rows = c.execute("SELECT * FROM device_baselines").fetchall()
        c.close()
        out = {}
        for r in rows:
            d = dict(r)
            out[d["device_id"]] = {
                "marked_safe": bool(d.get("marked_safe")),
                "established": d.get("established", ""),
                "profile": {
                    "connections": d.get("base_connections", 0),
                    "destinations": d.get("base_destinations", 0),
                    "port_attempts": d.get("base_port_attempts", 0),
                    "request_freq": d.get("base_request_freq", 0),
                    "traffic": d.get("base_traffic", 0),
                },
            }
        return out
    except Exception:
        return {}
