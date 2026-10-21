"""CyberShield Wi-Fi — FastAPI backend.
Software-only prototype: simulated Wi-Fi telemetry + Zero-Trust + AI + decoys.
Same security engine can later connect to real AP/controller logs.
"""
from fastapi import FastAPI, HTTPException, Query
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, Response
from pydantic import BaseModel
import os
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from security import install_security
except ImportError:  # pragma: no cover - import-style fallback
    from backend.security import install_security

from backend.risk_engine import (calculate_risk, trust_from_risk,
                                 AUTO_ISOLATE_THRESHOLD, baseline_deviation)
from backend.ai_detector import ai_score
from backend import ai_detector
from backend import database as db
from backend import real_net
from backend import threat_model
from backend import policy
from backend import packet_monitor
from backend import rogue
from backend import diagnosis
from backend import ip_intel
from backend import ip_purpose
from backend import ip_alerts
from backend import ip_report
from backend import feeds
from backend.simulator import NORMAL_DEVICES, DECOYS, ALLOW_LIST, DENY_LIST, fresh_device_state

app = FastAPI(title="CyberShield Wi-Fi")

# Security: restricted CORS, Host allow-list (DNS-rebinding defence) and a
# session token on every state-changing request. See backend/security.py.
install_security(app)

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
def _device_features(dev: dict) -> dict:
    """The behavioural profile of a device, as the AI model sees it."""
    return {
        "connections": 30 + dev["port_scan"] * 120 + dev["traffic_spike"] * 80,
        "destinations": 3 + dev["unknown_dest"] * 12,
        "port_attempts": 5 + dev["port_scan"] * 40,
        "request_freq": 30 + dev["request_anomaly"] * 200,
        "traffic": 120 + dev["traffic_spike"] * 900,
    }


def apply_features_to_device(dev: dict, features: dict, defer_isolate: bool = False):
    """Merge new signals into stored counters, recompute risk, enforce auto-isolate.

    defer_isolate suppresses the automatic isolation so a scripted sequence
    can play out in full before the response is taken.
    """
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

    profile = _device_features(dev)
    baselines = db.get_baselines()
    base = baselines.get(dev["id"], {}).get("profile")
    deviated = baseline_deviation(profile, base or {})

    risk_features = {
        "auth_failures": dev["auth_failures"],
        "unknown_destinations": bool(dev["unknown_dest"]),
        "port_scan": bool(dev["port_scan"]),
        "traffic_spike": bool(dev["traffic_spike"]),
        "request_rate_anomaly": bool(dev["request_anomaly"]),
        "decoy_interactions": dev["decoy_hits"],
        "unauthorized_attempts": dev["unauthorized"],
        "baseline_deviation": deviated,
    }
    risk, reasons, level = calculate_risk(risk_features)

    # AI corroboration (does not override decoy signal, just logs)
    ai = ai_score({
        "connection_count": profile["connections"],
        "unique_destinations": profile["destinations"],
        "port_attempts": profile["port_attempts"],
        "request_freq": profile["request_freq"],
        "traffic_volume": profile["traffic"],
    })

    dev["risk"] = risk
    dev["trust"] = trust_from_risk(risk)
    prev = dev["status"]
    dev["status"] = level
    if risk >= AUTO_ISOLATE_THRESHOLD and not defer_isolate:
        dev["isolated"] = 1
        dev["status"] = "critical"
    db.upsert_device(dev)
    return risk, reasons, level, ai, prev

def auto_respond_if_needed(dev: dict, reasons: list):
    """Take the response once the risk is past the isolation threshold."""
    if dev["risk"] >= AUTO_ISOLATE_THRESHOLD:
        dev["isolated"] = 1
        dev["status"] = "critical"
        action = ("QUARANTINE (simulated mode): marked isolated in the device table "
                  "and its access revoked in the demo model. No real traffic is "
                  "blocked — isolating a real device needs a MAC block on your router.")
        db.upsert_device(dev)
        db.add_incident(dev["id"], dev["risk"], "; ".join(reasons), action)
        db.log_event(dev["id"], "isolate", f"🚨 {dev['id']} AUTOMATICALLY ISOLATED (risk {dev['risk']}/100)", dev["risk"])
        return True
    return False

# ---- API ----
@app.get("/api/devices")
def devices():
    baselines = db.get_baselines()
    out = []
    for d in db.get_devices():
        b = baselines.get(d["id"], {})
        out.append({**d, "allowed": ALLOW_LIST.get(d["id"], ["internet", "dns"]),
                    "denied": DENY_LIST,
                    "marked_safe": bool(b.get("marked_safe")),
                    "baseline_established": b.get("established", ""),
                    "baseline_profile": b.get("profile") or {},
                    "baseline_deviated": baseline_deviation(_device_features(d),
                                                             b.get("profile") or {})})
    return out


@app.post("/api/device/{device_id}/mark-safe")
def mark_safe(device_id: str):
    """Record this device's current behaviour as its normal baseline.

    From then on the device is judged against its own recorded profile, not
    only against global thresholds: a busy device that suddenly starts
    scanning is more interesting than a quiet device that never does
    anything. Marking safe also clears the current risk counters.
    """
    dev = db.get_device(device_id)
    if not dev:
        return {"error": "unknown device"}
    profile = _device_features(dev)
    db.set_baseline(device_id, profile)
    dev.update({"risk": 5, "trust": 95, "status": "trusted", "isolated": 0,
                "auth_failures": 0, "decoy_hits": 0, "port_scan": 0,
                "traffic_spike": 0, "unknown_dest": 0, "request_anomaly": 0,
                "unauthorized": 0})
    db.upsert_device(dev)
    db.log_event(device_id, "mark-safe",
                 f"✅ {device_id} marked safe — baseline recorded "
                 f"({profile['connections']} conn, {profile['destinations']} dest, "
                 f"{profile['traffic']} traffic)", 0)
    return {"ok": True, "device": dev, "baseline": profile}


@app.post("/api/device/{device_id}/unmark-safe")
def unmark_safe(device_id: str):
    db.clear_baseline(device_id)
    db.log_event(device_id, "unmark-safe", f"{device_id} baseline cleared", 0)
    return {"ok": True, "baselines": db.get_baselines()}

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


class AttackReq(BaseModel):
    device_id: str = "DEVICE-007"
    step: int | None = None


# The attack sequence, in the order the timeline shows it. The decoy touch
# is the final step: it is the strongest single signal, because a device
# that has no business talking to a fake admin portal has already lost the
# argument.
ATTACK_STEPS = [
    ("port_scan", "port_scan", "port scan against 20 hosts on the LAN"),
    ("traffic_spike", "traffic_spike", "sudden traffic volume spike"),
    ("unknown_destinations", "unknown_dest", "connections to unknown external destinations"),
    ("auth_failures", "auth_failures", "repeated authentication failures"),
    ("request_rate_anomaly", "request_anomaly", "abnormal request frequency"),
    ("unauthorized_attempts", "unauthorized", "unauthorized access attempts"),
]
LAST_STEP = len(ATTACK_STEPS)   # index of the decoy step


@app.post("/api/simulate/attack")
def simulate_attack(req: AttackReq):
    """Replay a scripted attack against one simulated device.

    This is demo scaffolding for the simulated mode. It writes synthetic
    counters into the device table so the rule engine, the incident log and
    the timeline can be demonstrated without a real attacker on the network.
    It never touches the real network.

    `step` applies only the first N stages, so the dashboard can show the
    risk score climbing one signal at a time. Omit it to run the whole
    sequence at once.
    """
    dev = db.get_device(req.device_id)
    if not dev:
        return {"error": f"unknown device {req.device_id}"}
    upto = LAST_STEP if req.step is None else max(0, min(int(req.step), LAST_STEP))
    steps = []
    reasons = []
    for i, (feature, field, label) in enumerate(ATTACK_STEPS):
        if i > upto:
            break
        if feature == "auth_failures":
            dev["auth_failures"] = max(dev["auth_failures"], 7)
        else:
            dev[field] = 1
        risk, reasons, level, ai, prev = apply_features_to_device(
            dev, {feature: 7 if feature == "auth_failures" else 1}, defer_isolate=True)
        db.log_event(req.device_id, feature, f"⚠️  simulated {label}", 0)
        steps.append({"step": feature, "label": label, "risk": risk, "level": level})
    if upto >= LAST_STEP:
        db.log_decoy_hit(req.device_id, "FAKE-ADMIN")
        db.log_event(req.device_id, "decoy",
                     f"🍯 {req.device_id} touched the Fake Admin Portal decoy", 40)
        risk, reasons, level, ai, prev = apply_features_to_device(
            dev, {"decoy_interactions": 1}, defer_isolate=True)
        steps.append({"step": "decoy", "label": "decoy touch", "risk": risk, "level": level})
        # Only now is the response taken.
        auto_respond_if_needed(dev, reasons)
    return {"ok": True, "device": db.get_device(req.device_id), "steps": steps,
            "complete": upto >= LAST_STEP,
            "note": "Simulated only — no real traffic was generated and nothing on "
                    "your network was touched."}

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
    interface: str = ""
    duration_s: int = 10
    max_packets: int = 500
    filter: str = ""


class ProbeReq(BaseModel):
    count: int = 5


class IPReq(BaseModel):
    ip: str = ""
    note: str = ""


# ---------- IP purpose intelligence ----------
def _observe_peers(force=False):
    """Read the local socket table, record what we talked to, and score it.

    Local signals only: addresses, ports, connection state and the name of
    the local program that owns each socket. No payloads are read.
    """
    try:
        flow = packet_monitor.flow_stats(force=force, with_peers=True)
    except Exception:
        return {"peers": [], "intel": {}, "assessed": [], "ok": False}
    peers = flow.get("peers") or []
    for p in peers:
        try:
            db.observe_ip(p.get("ip"), p.get("port"), p.get("proto", "tcp"),
                          (p.get("actors") or [None])[0])
        except Exception:
            pass
    ips = sorted({p.get("ip") for p in peers if p.get("ip")})
    try:
        intel_map = ip_intel.lookup_many(ips, max_new=20)
    except Exception:
        intel_map = {}
    obs = {o["ip"]: o for o in db.get_ip_observations()}
    try:
        assessed = ip_purpose.assess(peers, intel_map, obs)
    except Exception:
        assessed = []
    try:
        ip_alerts.evaluate(assessed, watchlist=db.get_watchlist())
    except Exception:
        pass
    return {"peers": peers, "intel": intel_map, "assessed": assessed,
            "flow": flow, "ok": True}


@app.get("/api/ip/observed")
def ip_observed(limit: int = 60, fresh: int = 0, filter: str = ""):
    """Every external address this host is talking to, with purpose and score."""
    res = _observe_peers(force=bool(fresh))
    rows = res["assessed"]
    if filter:
        f = filter.lower()
        rows = [r for r in rows
                if f in (r.get("ip") or "").lower()
                or f in (r.get("purpose") or "").lower()
                or f in (r.get("purpose_label", {}).get("label", "")).lower()
                or f in (r.get("intel", {}).get("org") or "").lower()
                or f in (r.get("intel", {}).get("as_name") or "").lower()]
    try:
        limit = max(1, min(int(limit), 500))
    except (TypeError, ValueError):
        limit = 60
    counts = {"avoid": 0, "caution": 0, "connect": 0}
    for r in res["assessed"]:
        counts[r["verdict"]] = counts.get(r["verdict"], 0) + 1
    return {"ok": res["ok"], "count": len(rows), "total": len(res["assessed"]),
            "summary": counts, "observed": rows[:limit],
            "alerts": ip_alerts.counts(),
            "sources": ip_intel.sources_status(),
            "watchlist": db.get_watchlist(),
            "note": ("Purpose and reputation are indicators derived from local signals. "
                     "Shared infrastructure (CDN, cloud) is never treated as hostile "
                     "on its own.")}


@app.get("/api/ip/lookup")
def ip_lookup(ip: str = Query(""), force: int = 0):
    """Full intelligence payload for one address."""
    ip = (ip or "").strip()
    if not ip:
        return {"error": "ip required"}
    try:
        return ip_intel.lookup(ip, force=bool(force))
    except Exception as e:
        return {"error": f"lookup failed: {e.__class__.__name__}"}


@app.get("/api/ip/alerts")
def ip_alert_list(limit: int = 100, unacked: int = 0):
    return {"alerts": ip_alerts.active(limit=limit),
            "counts": ip_alerts.counts(),
            "note": ip_alerts.DISCLAIMER}


@app.post("/api/ip/alerts/{alert_id}/ack")
def ip_alert_ack(alert_id: int):
    ok = db.ack_ip_alert(alert_id)
    db.log_event("ADMIN", "ip-alert-ack", f"acknowledged IP alert #{alert_id}", 0)
    return {"ok": ok}


@app.post("/api/ip/watch")
def ip_watch(req: IPReq):
    if not req.ip:
        return {"error": "ip required"}
    db.watch_ip(req.ip, req.note)
    db.log_event(req.ip, "ip-watch", f"added {req.ip} to the IP watchlist: {req.note}", 0)
    return {"ok": True, "watchlist": db.get_watchlist()}


@app.delete("/api/ip/watch/{ip}")
def ip_unwatch(ip: str):
    db.unwatch_ip(ip)
    db.log_event(ip, "ip-watch", f"removed {ip} from the IP watchlist", 0)
    return {"ok": True, "watchlist": db.get_watchlist()}


@app.get("/api/ip/watchlist")
def ip_watchlist():
    return {"watchlist": db.get_watchlist()}


@app.get("/api/ip/report")
def ip_report_endpoint(ip: str = Query(""), format: str = Query("md")):
    ip = (ip or "").strip()
    if not ip:
        return {"error": "ip required"}
    res = _observe_peers(force=False)
    intel = res["intel"].get(ip) or ip_intel.lookup(ip)
    assessed = next((a for a in res["assessed"] if a.get("ip") == ip), None)
    report = ip_report.build(ip, intel=intel, assessed=assessed)
    if format == "json":
        return report
    return {"ip": ip, "format": "markdown", "report": ip_report.render_markdown(report),
            "verdict": report["verdict"], "score": report["score"]}


@app.get("/api/ip/feeds/status")
def ip_feeds_status():
    return feeds.status()


@app.post("/api/ip/feeds/refresh")
def ip_feeds_refresh():
    res = feeds.refresh()
    db.log_event("SYSTEM", "ip-feeds", f"reputation feeds refreshed: {res['results']}", 0)
    return res


@app.get("/api/ip/sources")
def ip_sources():
    return ip_intel.sources_status()


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
    res = packet_monitor.start_capture(interface=req.interface or "",
                                       duration_s=req.duration_s,
                                       max_packets=req.max_packets,
                                       pcap_filter=req.filter or "")
    if not res.get("ok"):
        raise HTTPException(status_code=400, detail=res.get("detail", "capture failed"))
    iface = (res.get("capture") or {}).get("interface", req.interface or "auto")
    db.log_event("ADMIN", "capture-start",
                 f"Packet capture started on {iface} "
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
