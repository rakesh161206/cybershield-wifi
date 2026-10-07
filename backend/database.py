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
