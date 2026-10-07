"""CyberShield Wi-Fi — FastAPI backend.
Software-only prototype: simulated Wi-Fi telemetry + Zero-Trust + AI + decoys.
Same security engine can later connect to real AP/controller logs.
"""
from fastapi import FastAPI, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel
import os
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.risk_engine import calculate_risk, trust_from_risk, AUTO_ISOLATE_THRESHOLD
from backend.ai_detector import ai_score
from backend import ai_detector
from backend import database as db
from backend import real_net
from backend import threat_model
from backend.simulator import NORMAL_DEVICES, DECOYS, ALLOW_LIST, DENY_LIST, fresh_device_state, attack_sequence

app = FastAPI(title="CyberShield Wi-Fi")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

FRONTEND_DIR = os.path.join(os.path.dirname(__file__), "..", "frontend")

# ---- init ----
db.init_db()
if not db.get_devices():
    for d in NORMAL_DEVICES:
        db.upsert_device(fresh_device_state(d))
    db.log_event("SYSTEM", "boot", "CyberShield initialized. 4 devices authenticated. 4 decoys armed.", 0)

# ---- models ----
class AttackReq(BaseModel):
    device_id: str = "DEVICE-007"

class DecoyTouch(BaseModel):
    device_id: str = "DEVICE-007"
    decoy_id: str = "FAKE-ADMIN"

# ---- helpers ----
def apply_features_to_device(dev: dict, features: dict):
    """Merge new signals into stored counters, recompute risk, enforce auto-isolate."""
    if features.get("auth_failures"):
        dev["auth_failures"] = max(dev["auth_failures"], int(features["auth_failures"]))
    if features.get("port_scan"):
        dev["port_scan"] = 1
    if features.get("traffic_spike"):
        dev["traffic_spike"] = 1
    if features.get("unknown_destinations"):
        dev["unknown_dest"] = 1
    if features.get("request_rate_anomaly"):
        dev["request_anomaly"] = 1
    if features.get("unauthorized_attempts"):
        dev["unauthorized"] = int(features["unauthorized_attempts"])
    if features.get("decoy_interactions"):
        dev["decoy_hits"] += int(features["decoy_interactions"])

    risk_features = {
        "auth_failures": dev["auth_failures"],
        "unknown_destinations": bool(dev["unknown_dest"]),
        "port_scan": bool(dev["port_scan"]),
        "traffic_spike": bool(dev["traffic_spike"]),
        "request_rate_anomaly": bool(dev["request_anomaly"]),
        "decoy_interactions": dev["decoy_hits"],
        "unauthorized_attempts": dev["unauthorized"],
    }
    risk, reasons, level = calculate_risk(risk_features)

    # AI corroboration (does not override decoy signal, just logs)
    ai = ai_score({
        "connection_count": 30 + dev["port_scan"] * 120 + dev["traffic_spike"] * 80,
        "unique_destinations": 3 + dev["unknown_dest"] * 12,
        "port_attempts": 5 + dev["port_scan"] * 40,
        "request_freq": 30 + dev["request_anomaly"] * 200,
        "traffic_volume": 120 + dev["traffic_spike"] * 900,
    })

    dev["risk"] = risk
    dev["trust"] = trust_from_risk(risk)
    prev = dev["status"]
    dev["status"] = level
    if risk >= AUTO_ISOLATE_THRESHOLD:
        dev["isolated"] = 1
        dev["status"] = "critical"
    db.upsert_device(dev)
    return risk, reasons, level, ai, prev

def auto_respond_if_needed(dev: dict, reasons: list):
    if dev["risk"] >= AUTO_ISOLATE_THRESHOLD and dev["isolated"]:
        action = "AUTO-ISOLATE: access revoked, session terminated, future requests blocked"
        db.add_incident(dev["id"], dev["risk"], "; ".join(reasons), action)
        db.log_event(dev["id"], "isolate", f"🚨 {dev['id']} AUTOMATICALLY ISOLATED (risk {dev['risk']}/100)", dev["risk"])
        return True
    return False

# ---- API ----
@app.get("/api/devices")
def devices():
    out = []
    for d in db.get_devices():
        out.append({**d, "allowed": ALLOW_LIST.get(d["id"], ["internet", "dns"]),
                    "denied": DENY_LIST})
    return out

@app.get("/api/decoys")
def decoys():
    return DECOYS

@app.get("/api/incidents")
def incidents():
    return db.get_incidents()

@app.get("/api/events")
def events(limit: int = 120):
    return db.get_events(limit)

@app.get("/api/stats")
def stats():
    devs = db.get_devices()
    return {
        "total": len(devs),
        "trusted": sum(1 for d in devs if d["status"] == "trusted"),
        "suspicious": sum(1 for d in devs if d["status"] in ("suspicious", "high")),
        "critical": sum(1 for d in devs if d["status"] == "critical"),
        "isolated": sum(1 for d in devs if d["isolated"]),
        "incidents": len(db.get_incidents(1000)),
    }

@app.post("/api/simulate/attack")
def simulate_attack(req: AttackReq):
    dev = db.get_device(req.device_id)
    if not dev:
        return {"error": "unknown device"}
    steps = attack_sequence(req.device_id)
    # accumulate all features at once for decisive demo, but log each step
    merged = {}
    for s in steps:
        db.log_event(req.device_id, s["type"], s["detail"], 0)
        for k, v in s["features"].items():
            if isinstance(v, bool):
                merged[k] = True
            elif isinstance(v, int):
                merged[k] = max(merged.get(k, 0), v) if k in ("auth_failures", "decoy_interactions", "unauthorized_attempts") else v
            else:
                merged[k] = v
        if s["type"] == "decoy":
            db.log_decoy_hit(req.device_id, "FAKE-ADMIN")
            db.log_decoy_hit(req.device_id, "FAKE-NAS")
    risk, reasons, level, ai, prev = apply_features_to_device(dev, merged)
    isolated = auto_respond_if_needed(dev, reasons)
    return {"device": db.get_device(req.device_id), "risk": risk, "reasons": reasons,
            "level": level, "ai": ai, "isolated": isolated, "steps": steps}

@app.post("/api/simulate/normal")
def simulate_normal():
    db.clear_dynamic()
    for d in NORMAL_DEVICES:
        db.upsert_device(fresh_device_state(d))
    db.log_event("SYSTEM", "reset", "Returned to normal baseline. All devices trusted.", 0)
    return {"ok": True}

@app.post("/api/device/{device_id}/allow")
def allow(device_id: str):
    dev = db.get_device(device_id)
    if not dev:
        return {"error": "unknown device"}
    dev.update({"risk": 8, "trust": 92, "status": "trusted", "isolated": 0,
                "auth_failures": 0, "decoy_hits": 0, "port_scan": 0,
                "traffic_spike": 0, "unknown_dest": 0, "request_anomaly": 0, "unauthorized": 0})
    db.upsert_device(dev)
    db.log_event(device_id, "allow", f"{device_id} restored by admin, quarantine lifted", -80)
    return {"ok": True, "device": dev}

@app.post("/api/device/{device_id}/isolate")
def isolate(device_id: str):
    dev = db.get_device(device_id)
    if not dev:
        return {"error": "unknown device"}
    dev["isolated"] = 1
    dev["status"] = "critical"
    dev["risk"] = max(dev["risk"], 85)
    dev["trust"] = trust_from_risk(dev["risk"])
    db.upsert_device(dev)
    db.add_incident(device_id, dev["risk"], "Manual isolation by admin", "MANUAL-ISOLATE")
    db.log_event(device_id, "isolate", f"{device_id} manually isolated", 0)
    return {"ok": True, "device": dev}

@app.get("/api/decoy/{decoy_id}")
def decoy_hit(decoy_id: str, device_id: str = Query("DEVICE-007")):
    """Simulated decoy service. Any touch = high-confidence signal."""
    dev = db.get_device(device_id)
    if dev:
        db.log_decoy_hit(device_id, decoy_id.upper())
        db.log_event(device_id, "decoy", f"🍯 {device_id} touched {decoy_id.upper()}", 40)
        risk, reasons, level, ai, prev = apply_features_to_device(dev, {"decoy_interactions": 1})
        auto_respond_if_needed(dev, reasons)
    return {"decoy": decoy_id, "message": "This is a deception asset. Interaction logged.",
            "device": device_id}

# ---- LIVE host network (real Wi-Fi, not simulated) ----
@app.get("/api/real/status")
def real_status():
    return real_net.full_status()

@app.get("/api/real/networks")
def real_networks():
    st = real_net.full_status()
    ssid = (st.get("wifi") or {}).get("ssid", "")
    return real_net.get_nearby(ssid)

@app.get("/api/real/radar")
def real_radar():
    """Nearby networks + proximity + connect verdict + threat model."""
    import time
    st = real_net.full_status()
    ssid = (st.get("wifi") or {}).get("ssid", "")
    nets = threat_model.assess(real_net.get_nearby(ssid))
    counts = {"connect": 0, "caution": 0, "avoid": 0}
    for n in nets:
        counts[n["recommendation"]["verdict"]] += 1
    return {"scanned_at": time.time(), "count": len(nets),
            "current_ssid": ssid, "summary": counts, "networks": nets}

@app.get("/api/real/devices")
def real_devices(fresh: int = 0, mode: str = "fast"):
    mode = mode if mode in ("fast", "full") else "fast"
    return real_net.get_lan_devices(mode=mode, fresh=bool(fresh))

@app.post("/api/real/scan")
def real_scan():
    return real_net.get_lan_devices(mode="full", fresh=True)

@app.get("/api/real/ai")
def real_ai():
    """AI verdict on the CURRENT real environment + engine health."""
    st = real_net.full_status()
    ssid = (st.get("wifi") or {}).get("ssid", "")
    nets = real_net.get_nearby(ssid)
    lan = real_net.get_lan_devices(mode="fast")
    snapshot = {
        "nearby_count": len(nets),
        "open_count": sum(1 for n in nets if (n.get("security") or "").startswith("Open")),
        "lan_devices": len(lan.get("devices", [])),
        "gateway_ms": st.get("gateway_ms"),
        "dns_ms": st.get("dns_ms"),
        "signal_dbm": (st.get("wifi") or {}).get("signal_dbm"),
    }
    return {"snapshot": snapshot,
            "assessment": ai_detector.assess_live(snapshot),
            "status": ai_detector.engine_status(),
            "normal_ranges": ai_detector.NORMAL_RANGES}

# serve frontend
@app.get("/", include_in_schema=False)
def index():
    return FileResponse(os.path.join(FRONTEND_DIR, "index.html"))
