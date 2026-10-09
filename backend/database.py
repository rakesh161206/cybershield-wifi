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
    except Exception:
        return []
    items.sort(key=lambda x: x.get("ts") or "", reverse=True)
    return items[:limit]
