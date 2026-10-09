"""CyberShield Wi-Fi — FastAPI backend.
Software-only prototype: simulated Wi-Fi telemetry + Zero-Trust + AI + decoys.
Same security engine can later connect to real AP/controller logs.
"""
from fastapi import FastAPI, HTTPException, Query
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
from backend import policy
from backend import packet_monitor
from backend import rogue
from backend import diagnosis
from backend.simulator import NORMAL_DEVICES, DECOYS, ALLOW_LIST, DENY_LIST, fresh_device_state

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
    st = real_net.full_status()
    _record_health_sample(st)
    return st

@app.get("/api/real/networks")
def real_networks():
    st = real_net.full_status()
    ssid = (st.get("wifi") or {}).get("ssid", "")
    return real_net.get_nearby(ssid)

@app.get("/api/real/radar")
def real_radar():
    """Nearby networks + score + verdict + threats. Threats wait for your decision."""
    import time
    st = real_net.full_status()
    ssid = (st.get("wifi") or {}).get("ssid", "")
    nearby = real_net.get_nearby(ssid)
    warnings = rogue.detect(nearby, ssid)
    db.observe_networks(nearby)
    nets = threat_model.assess(nearby)
    pending = policy.evaluate_pending(nets)
    # refresh blocked flags after enforcement
    for n in nets:
        n["blocked"] = db.is_blocked(n.get("ssid") or "")
    counts = {"connect": 0, "caution": 0, "avoid": 0}
    for n in nets:
        counts[n["recommendation"]["verdict"]] += 1
    radar_summary = {"count": len(nets), "summary": counts}
    lan = real_net.get_lan_devices(mode="fast")
    snapshot = {
        "nearby_count": len(nearby),
        "open_count": sum(1 for n in nearby if (n.get("security") or "").startswith("Open")),
        "lan_devices": len(lan.get("devices", [])),
        "gateway_ms": st.get("gateway_ms"),
        "dns_ms": st.get("dns_ms"),
        "signal_dbm": (st.get("wifi") or {}).get("signal_dbm"),
    }
    snapshot.update(packet_monitor.packet_features())
    assessment = ai_detector.assess_live(snapshot)
    loss = packet_monitor.last_loss() or {}
    _record_health_sample(st)
    return {"scanned_at": time.time(), "count": len(nets),
            "current_ssid": ssid, "summary": counts, "networks": nets,
            "pending_blocks": pending, "policy": policy.policy_status(),
            "rogue_warnings": warnings,
            "diagnosis": diagnosis.classify(st, assessment, warnings, loss, radar_summary)}

class SsidReq(BaseModel):
    ssid: str = ""

class FlagReq(BaseModel):
    ip: str = ""
    mac: str = ""
    note: str = "flagged by admin"


class CaptureReq(BaseModel):
    interface: str = "en0"
    duration_s: int = 10
    max_packets: int = 500
    filter: str = ""


class ProbeReq(BaseModel):
    count: int = 5


def _live_snapshot():
    """Shared live-environment snapshot (non-blocking packet features)."""
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
    snapshot.update(packet_monitor.packet_features())
    return st, nets, lan, snapshot


def _record_health_sample(st):
    try:
        loss = packet_monitor.last_loss() or {}
        db.record_health(
            gateway_ms=st.get("gateway_ms"),
            loss_pct=loss.get("loss_pct"),
            signal_dbm=(st.get("wifi") or {}).get("signal_dbm"),
            risk_score=(st.get("risk") or {}).get("score"),
            verdict=(st.get("risk") or {}).get("level", ""))
    except Exception:
        pass

@app.post("/api/real/block")
def block_network(req: SsidReq):
    if not req.ssid:
        return {"error": "ssid required"}
    ok, detail = policy.forget_network(req.ssid)
    nets = threat_model.assess(real_net.get_nearby(""))
    rec = next((n["recommendation"] for n in nets if n.get("ssid") == req.ssid),
               {"score": 0, "reasons": ["manual block"]})
    db.block(req.ssid, "; ".join(rec.get("reasons", [])), auto=0)
    msg = f"BLOCKED “{req.ssid}” (risk {rec.get('score', '?')}/100): {detail}"
    db.add_incident("ADMIN", rec.get("score", 0) if isinstance(rec.get("score"), int) else 0,
                    "; ".join(rec.get("reasons", [])), msg)
    db.log_event("ADMIN", "block", msg, 0)
    return {"ok": True, "forgotten": ok, "detail": detail}

@app.post("/api/real/unblock")
def unblock_network(req: SsidReq):
    if not req.ssid:
        return {"error": "ssid required"}
    db.unblock(req.ssid)
    db.log_event("ADMIN", "allow", f"✅ “{req.ssid}” allowlisted — auto-protect will not touch it", 0)
    return {"ok": True}

@app.post("/api/real/disconnect")
def disconnect_now():
    ok, detail = policy.disconnect_wifi()
    db.log_event("ADMIN", "disconnect", f"Wi-Fi turned off by admin ({detail})", 0)
    return {"ok": ok, "detail": detail}

@app.get("/api/policy")
def get_policy():
    return policy.policy_status()

@app.get("/api/real/link")
def real_link():
    return real_net.link_stats()

@app.post("/api/real/speedtest")
def real_speedtest():
    mbps = real_net.speed_test()
    return {"speed_mbps": mbps, "ok": mbps is not None}

@app.post("/api/real/device/flag")
def flag_device(req: FlagReq):
    if not req.ip:
        return {"error": "ip required"}
    db.flag_device(req.ip, req.mac, req.note)
    db.log_event(req.ip, "flag", f"🚩 device {req.ip} ({req.mac}) flagged: {req.note}", 0)
    return {"ok": True, "note": "Flagged in CyberShield. To truly isolate it, block its MAC on your router."}

@app.get("/api/real/devices")
def real_devices(fresh: int = 0, mode: str = "fast"):
    mode = mode if mode in ("fast", "full") else "fast"
    r = real_net.get_lan_devices(mode=mode, fresh=bool(fresh))
    flagged = {f["ip"] for f in db.get_flagged()}
    for d in r.get("devices", []):
        d["flagged"] = d["ip"] in flagged
    r["gateway"] = real_net.get_ip_info().get("gateway", "")
    return r

@app.post("/api/real/scan")
def real_scan():
    return real_net.get_lan_devices(mode="full", fresh=True)

@app.get("/api/real/ai")
def real_ai():
    """AI verdict on the CURRENT real environment + engine health."""
    st, nets, lan, snapshot = _live_snapshot()
    return {"snapshot": snapshot,
            "assessment": ai_detector.assess_live(snapshot),
            "status": ai_detector.engine_status(),
            "normal_ranges": ai_detector.NORMAL_RANGES}


# ---- Packet / flow telemetry (privacy-preserving, headers only) ----
@app.get("/api/real/packet")
def packet_status(count: int = 5, fresh: int = 0):
    """Gateway loss probe + local flow metadata. Set fresh=1 to re-probe."""
    try:
        count = max(1, min(int(count), 10))
    except (TypeError, ValueError):
        count = 5
    st = real_net.full_status()
    gw = (st.get("ip") or {}).get("gateway", "")
    loss = packet_monitor.measure_loss(host=gw or None, count=count,
                                       force=bool(fresh))
    flow = packet_monitor.flow_stats(force=bool(fresh))
    return {"loss": loss, "flow": flow, "gateway": gw,
            "measured_at": loss.get("measured_at")}


@app.post("/api/real/packet/probe")
def packet_probe(req: ProbeReq):
    st = real_net.full_status()
    gw = (st.get("ip") or {}).get("gateway", "")
    try:
        count = max(1, min(int(req.count), 10))
    except (TypeError, ValueError):
        count = 5
    return packet_monitor.measure_all(gateway=gw or None, count=count)


# ---- Rogue-AP warnings + attack-vs-fault diagnosis ----
@app.get("/api/real/rogue")
def rogue_status():
    st = real_net.full_status()
    ssid = (st.get("wifi") or {}).get("ssid", "")
    nearby = real_net.get_nearby(ssid)
    warnings = rogue.detect(nearby, ssid)
    db.observe_networks(nearby)
    return {"current_ssid": ssid, "count": len(nearby),
            "warnings": warnings,
            "note": rogue.INDICATOR_NOTE}


@app.get("/api/real/diagnosis")
def diagnosis_status():
    st, nets, lan, snapshot = _live_snapshot()
    ssid = (st.get("wifi") or {}).get("ssid", "")
    warnings = rogue.detect(nets, ssid)
    db.observe_networks(nets)
    assessment = ai_detector.assess_live(snapshot)
    loss = packet_monitor.last_loss() or {}
    scored = threat_model.assess(nets)
    radar_summary = {"count": len(scored),
                     "summary": {"avoid": sum(1 for n in scored if n["recommendation"]["verdict"] == "avoid"),
                                 "caution": sum(1 for n in scored if n["recommendation"]["verdict"] == "caution"),
                                 "connect": sum(1 for n in scored if n["recommendation"]["verdict"] == "connect")}}
    result = diagnosis.classify(st, assessment, warnings, loss, radar_summary)
    result["rogue_warnings"] = warnings
    result["ai"] = assessment
    return result


# ---- Incident timeline + before/after verification ----
@app.get("/api/real/timeline")
def timeline(limit: int = 50):
    try:
        limit = max(1, min(int(limit), 200))
    except (TypeError, ValueError):
        limit = 50
    return {"timeline": db.get_timeline(limit),
            "health": db.get_health_history(min(limit, 60))}


@app.get("/api/real/health/history")
def health_history(limit: int = 60):
    try:
        limit = max(1, min(int(limit), 500))
    except (TypeError, ValueError):
        limit = 60
    return {"history": db.get_health_history(limit)}


@app.get("/api/real/verify")
def verify(window_min: int = 30):
    try:
        window_min = max(5, min(int(window_min), 720))
    except (TypeError, ValueError):
        window_min = 30
    return db.verify_health(window_min)


# ---- Bounded PCAP capture (tcpdump, optional, auto-expiring) ----
@app.get("/api/real/capture/status")
def capture_status():
    return packet_monitor.capture_status()


@app.post("/api/real/capture/start")
def capture_start(req: CaptureReq):
    res = packet_monitor.start_capture(interface=req.interface or "en0",
                                       duration_s=req.duration_s,
                                       max_packets=req.max_packets,
                                       pcap_filter=req.filter or "")
    if not res.get("ok"):
        raise HTTPException(status_code=400, detail=res.get("detail", "capture failed"))
    db.log_event("ADMIN", "capture-start",
                 f"Packet capture started on {req.interface} "
                 f"({req.duration_s}s, max {req.max_packets} pkts, headers only)", 0)
    return res


@app.post("/api/real/capture/stop")
def capture_stop():
    return packet_monitor.stop_capture()


@app.get("/api/real/capture/download")
def capture_download(file: str = Query("")):
    path = packet_monitor.resolve_capture(file)
    if not path:
        raise HTTPException(status_code=404, detail="capture not found or expired")
    return FileResponse(path, media_type="application/vnd.tcpdump.pcap",
                        filename=os.path.basename(path))

# serve frontend
@app.get("/", include_in_schema=False)
def index():
    return FileResponse(os.path.join(FRONTEND_DIR, "index.html"))
