"""Live host-network collectors (macOS, stdlib only, best-effort).

Sources: system_profiler (Wi-Fi link + nearby networks), ipconfig/route
(IP/gateway), scutil (DNS), ping + TCP + captive-portal check (health),
arp + ping sweep (LAN devices). Everything degrades gracefully to
'unavailable' when a source is missing (e.g. non-macOS, no Wi-Fi).
"""
import json
import re
import socket
import subprocess
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed

STATUS_TTL = 10          # seconds to cache /api/real/status
_devices_cache = {"ts": 0, "devices": [], "mode": ""}
_status_cache = {"ts": 0, "payload": None}


def _run(cmd, timeout=8):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.stdout.strip()
    except Exception:
        return ""


# ---------- Wi-Fi ----------
SEC_LABELS = [
    ("wpa3", "WPA3"),
    ("wpa2", "WPA2"),
    ("wpa", "WPA"),
    ("wep", "WEP"),
]

def _sec_label(raw: str) -> str:
    s = (raw or "").lower()
    if not s or "none" in s or s.endswith("_open") or "open" in s and "wpa" not in s:
        # profiler uses e.g. 'spairport_security_mode_none' for open
        if "wpa" in s or "wep" in s:
            pass
        else:
            return "Open"
    for key, label in SEC_LABELS:
        if key in s:
            suffix = " (Transition)" if "transition" in s else ""
            suffix += " (Enterprise)" if "enterprise" in s else " (Personal)" if "personal" in s else ""
            return label + suffix
    if "802.1x" in s or "enterprise" in s:
        return "WPA-Enterprise"
    return f"Unknown ({raw})" if raw else "Unknown"


_prof_cache = {"ts": 0, "data": {}}
PROF_TTL = 8  # profiler takes ~1s; share one snapshot across endpoints


def _profiler() -> dict:
    import time as _t
    now = _t.time()
    if _prof_cache["data"] and now - _prof_cache["ts"] < PROF_TTL:
        return _prof_cache["data"]
    out = _run(["system_profiler", "SPAirPortDataType", "-json"], timeout=15)
    iface = {}
    try:
        data = json.loads(out)
        ifs = data.get("SPAirPortDataType", [{}])[0].get("spairport_airport_interfaces", [])
        for i in ifs:
            if i.get("_name") == "en0":
                iface = i
                break
        else:
            iface = ifs[0] if ifs else {}
    except Exception:
        iface = {}
    _prof_cache["ts"] = now
    _prof_cache["data"] = iface
    return iface


def get_wifi() -> dict:
    info = _profiler()
    cur = info.get("spairport_current_network_information", {}) or {}
    ssid = cur.get("_name")
    if not ssid:
        return {"connected": False}
    sig_raw = cur.get("spairport_signal_noise", "")
    m = re.match(r"\s*(-?\d+)\s*dBm\s*/\s*(-?\d+)\s*dBm", sig_raw)
    signal = int(m.group(1)) if m else None
    noise = int(m.group(2)) if m else None
    chan_raw = cur.get("spairport_network_channel", "")
    chm = re.match(r"\s*(\d+)\s*\((\S+?)(?:,\s*([\d.]+MHz))?\)", chan_raw)
    sec_raw = cur.get("spairport_network_security_mode", "") or cur.get("spairport_security_mode", "")
    return {
        "connected": True,
        "ssid": ssid,
        "channel": chm.group(1) if chm else chan_raw,
        "band": chm.group(2) if chm and chm.group(2) else "",
        "width": chm.group(3) if chm and chm.group(3) else "",
        "phy": cur.get("spairport_network_phymode", ""),
        "rate_mbps": cur.get("spairport_network_rate"),
        "security_raw": sec_raw,
        "security": _sec_label(sec_raw),
        "signal_dbm": signal,
        "noise_dbm": noise,
        "snr_db": (signal - noise) if signal is not None and noise is not None else None,
        "mac": info.get("spairport_wireless_mac_address", ""),
        "country": cur.get("spairport_network_country_code", ""),
    }


def get_nearby(current_ssid="") -> list:
    info = _profiler()
    out = []
    for n in info.get("spairport_airport_other_local_wireless_networks", []) or []:
        ssid = n.get("_name", "")
        m = re.match(r"\s*(-?\d+)\s*dBm", n.get("spairport_signal_noise", ""))
        ch = re.match(r"\s*(\d+)", n.get("spairport_network_channel", ""))
        out.append({
            "ssid": ssid,
            "signal_dbm": int(m.group(1)) if m else None,
            "channel": ch.group(1) if ch else "",
            "phy": n.get("spairport_network_phymode", ""),
            "security": _sec_label(n.get("spairport_security_mode", "")),
            "is_current": bool(current_ssid and ssid == current_ssid),
        })
    out.sort(key=lambda x: (x["signal_dbm"] is None, -(x["signal_dbm"] or -999)))
    return out


# ---------- IP / gateway / DNS ----------
def get_ip_info() -> dict:
    ip = _run(["ipconfig", "getifaddr", "en0"], timeout=5)
    if not ip or "." not in ip:
        # fallback: first non-loopback IPv4
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(2)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
        except Exception:
            ip = ""
    gw = ""
    route = _run(["route", "-n", "get", "default"], timeout=5)
    mgw = re.search(r"gateway:\s*(\S+)", route)
    if mgw:
        gw = mgw.group(1)
    dns = []
    sc = _run(["scutil", "--dns"], timeout=5)
    for m in re.finditer(r"nameserver\[\d+\]\s*:\s*(\S+)", sc):
        if m.group(1) not in dns:
            dns.append(m.group(1))
    return {"ip": ip, "gateway": gw, "dns": dns[:4],
            "valid": bool(ip and not ip.startswith("169.254."))}


def ping_avg(host: str, count=2, timeout=3):
    out = _run(["ping", f"-c{count}", f"-t{timeout}", host], timeout=timeout + 4)
    m = re.search(r"min/avg/max.*=\s*[\d.]+/([\d.]+)/", out)
    if m:
        return float(m.group(1))
    if "1 packets received" in out or re.search(r"[1-9]\d* packets received", out):
        return 1.0
    return None


def check_dns_time(host="www.google.com", timeout=3) -> float | None:
    t0 = time.time()
    try:
        socket.setdefaulttimeout(timeout)
        socket.getaddrinfo(host, 443)
        return round((time.time() - t0) * 1000, 1)
    except Exception:
        return None
    finally:
        socket.setdefaulttimeout(None)


def check_internet(timeout=4) -> dict:
    t0 = time.time()
    try:
        s = socket.create_connection(("1.1.1.1", 443), timeout=timeout)
        ms = round((time.time() - t0) * 1000, 1)
        s.close()
        return {"reachable": True, "latency_ms": ms, "method": "TCP 1.1.1.1:443"}
    except Exception:
        pass
    try:
        req = urllib.request.Request("http://captive.apple.com/hotspot-detect.html",
                                     headers={"User-Agent": "CyberShield"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            body = r.read(200).decode(errors="ignore")
            if "Success" in body:
                return {"reachable": True, "latency_ms": None, "method": "HTTP via captive.apple.com"}
            return {"reachable": False, "latency_ms": None, "method": "captive portal login required"}
    except Exception as e:
        return {"reachable": False, "latency_ms": None, "method": f"unreachable ({e.__class__.__name__})"}


# ---------- LAN devices ----------
def _arp_table() -> dict:
    out = _run(["arp", "-a"], timeout=5)
    devs = {}
    for m in re.finditer(r"\(([\d.]+)\)\s+at\s+([0-9a-f:]+)", out, re.I):
        if m.group(2).lower() != "incomplete":
            devs[m.group(1)] = m.group(2).lower()
    return devs


def _sweep(prefix: str, self_ip: str, timeout=1) -> list:
    targets = [f"{prefix}.{i}" for i in range(1, 255) if f"{prefix}.{i}" != self_ip]

    def _one(ip):
        out = _run(["ping", "-c1", "-t1", ip], timeout=timeout + 1)
        if "1 packets received" in out:
            m = re.search(r"time=([\d.]+)\s*ms", out)
            return ip, float(m.group(1)) if m else 1.0
        return None

    alive = []
    with ThreadPoolExecutor(max_workers=64) as ex:
        futs = {ex.submit(_one, ip): ip for ip in targets}
        for f in as_completed(futs, timeout=40):
            try:
                r = f.result()
                if r:
                    alive.append(r)
            except Exception:
                pass
    return alive


def _hostname(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""


def get_lan_devices(mode="fast", fresh=False) -> dict:
    global _devices_cache
    t0 = time.time()
    if not fresh and _devices_cache["devices"] and (t0 - _devices_cache["ts"] < 60) \
            and _devices_cache["mode"] == mode:
        return {"devices": _devices_cache["devices"], "cached": True,
                "scan_ms": 0, "mode": mode}
    ipinfo = get_ip_info()
    self_ip, gw = ipinfo.get("ip", ""), ipinfo.get("gateway", "")
    prefix = ".".join(self_ip.split(".")[:3]) if self_ip.count(".") == 3 else ""
    arp = _arp_table()
    alive = {}
    if mode == "full" and prefix:
        for ip, ms in _sweep(prefix, self_ip):
            alive[ip] = ms
        arp = {**arp, **_arp_table()}  # keep earlier entries, add new MACs
    if self_ip and self_ip not in arp and self_ip not in alive:
        alive[self_ip] = None
    ips = sorted(set(list(arp.keys()) + list(alive.keys())),
                 key=lambda x: tuple(int(p) for p in x.split(".")))
    if prefix:  # keep only hosts on our own /24 (drop multicast etc.)
        ips = [ip for ip in ips if ip.startswith(prefix + ".")]
    names = {}
    with ThreadPoolExecutor(max_workers=16) as ex:
        futs = {ex.submit(_hostname, ip): ip for ip in ips}
        try:
            for f in as_completed(futs, timeout=4):
                names[futs[f]] = f.result()
        except Exception:
            pass
        for ip in ips:
            names.setdefault(ip, "")
    devices = [{"ip": ip,
                "mac": arp.get(ip, ""),
                "hostname": names.get(ip, ""),
                "latency_ms": alive.get(ip),
                "is_self": ip == self_ip,
                "is_gateway": bool(gw and ip == gw)} for ip in ips]
    _devices_cache = {"ts": time.time(), "devices": devices, "mode": mode}
    return {"devices": devices, "cached": False,
            "scan_ms": int((time.time() - t0) * 1000), "mode": mode}


# ---------- Security analysis ----------
PUBLIC_HINTS = ("free", "airport", "cafe", "coffee", "hotel", "guest",
                "public", "hotspot", "xfinitywifi", "station", "mall", "metro")

def signal_quality(dbm) -> tuple:
    if dbm is None:
        return "unknown", "Signal reading unavailable"
    if dbm >= -60:
        return "excellent", f"{dbm} dBm — excellent"
    if dbm >= -70:
        return "good", f"{dbm} dBm — good"
    if dbm >= -80:
        return "weak", f"{dbm} dBm — weak, may drop"
    return "very weak", f"{dbm} dBm — very weak"


def analyze() -> dict:
    wifi = get_wifi()
    ipinfo = get_ip_info()
    gw_ms = ping_avg(ipinfo["gateway"]) if ipinfo.get("gateway") else None
    dns_ms = check_dns_time()
    net = check_internet()
    checks, reasons, recs = [], [], []
    score = 0

    # 1 link
    if wifi.get("connected"):
        checks.append({"name": "Wi-Fi link", "status": "pass",
                       "detail": f"Connected to “{wifi['ssid']}”"})
    else:
        checks.append({"name": "Wi-Fi link", "status": "fail", "detail": "Not connected to Wi-Fi"})
        reasons.append("No Wi-Fi connection")

    # 2 security protocol
    sec = wifi.get("security", "Unknown")
    if sec == "Open":
        score += 35
        checks.append({"name": "Security protocol", "status": "fail",
                       "detail": "OPEN network — traffic can be sniffed"})
        reasons.append("Open network: no encryption (+35)")
        recs += ["Use a VPN on this network", "Avoid banking / logins",
                 "Forget this network after use"]
    elif sec == "WEP":
        score += 30
        checks.append({"name": "Security protocol", "status": "fail", "detail": "WEP — broken encryption"})
        reasons.append("WEP encryption is easily cracked (+30)")
        recs.append("Ask the owner to upgrade the router to WPA2/WPA3")
    elif sec.startswith("WPA3"):
        checks.append({"name": "Security protocol", "status": "pass", "detail": f"{sec} — strong"})
    elif sec.startswith("WPA2"):
        checks.append({"name": "Security protocol", "status": "pass", "detail": f"{sec} — good"})
        recs.append("Prefer WPA3 when the router offers it")
    elif sec.startswith("WPA"):
        score += 15
        checks.append({"name": "Security protocol", "status": "warn", "detail": f"{sec} — outdated"})
        reasons.append("WPA (v1) has known weaknesses (+15)")
    else:
        score += 15
        checks.append({"name": "Security protocol", "status": "warn", "detail": f"{sec} — could not verify"})
        reasons.append("Could not verify encryption (+15)")

    # public hotspot heuristic
    ssid = (wifi.get("ssid") or "").lower()
    if ssid and any(h in ssid for h in PUBLIC_HINTS):
        score += 15
        checks.append({"name": "Network identity", "status": "warn",
                       "detail": "Name looks like a public/shared hotspot"})
        reasons.append("Likely public/shared hotspot (+15)")
        recs += ["Confirm the exact SSID with staff (evil-twin risk)",
                 "Turn off auto-join for this network"]
    elif wifi.get("connected"):
        checks.append({"name": "Network identity", "status": "pass",
                       "detail": "Private-looking network name"})

    # 3 signal
    q, qd = signal_quality(wifi.get("signal_dbm"))
    st = "pass" if q in ("excellent", "good") else "warn" if q != "unknown" else "warn"
    checks.append({"name": "Signal quality", "status": st, "detail": qd})
    if q in ("weak", "very weak"):
        recs.append("Move closer to the router for a stable connection")

    # 4 IP
    if ipinfo.get("valid"):
        checks.append({"name": "IP / DHCP", "status": "pass",
                       "detail": f"IP {ipinfo['ip']} via DHCP"})
    else:
        score += 10
        checks.append({"name": "IP / DHCP", "status": "fail",
                       "detail": f"No valid IP ({ipinfo.get('ip') or 'none'})"})
        reasons.append("No valid DHCP lease (+10)")

    # 5 gateway
    if gw_ms is not None:
        st = "pass" if gw_ms < 100 else "warn"
        checks.append({"name": "Gateway", "status": st,
                       "detail": f"{ipinfo['gateway']} reachable, {gw_ms:.1f} ms"})
        if gw_ms >= 100:
            recs.append("High router latency — congestion or weak signal")
    else:
        score += 10
        checks.append({"name": "Gateway", "status": "fail",
                       "detail": f"{ipinfo.get('gateway') or 'unknown'} unreachable"})
        reasons.append("Router/gateway not responding (+10)")

    # 6 DNS
    if dns_ms is not None:
        srv = ", ".join(ipinfo.get("dns", [])[:2]) or "system default"
        checks.append({"name": "DNS", "status": "pass", "detail": f"{srv} — {dns_ms:.0f} ms"})
    else:
        score += 10
        checks.append({"name": "DNS", "status": "fail", "detail": "Name resolution failed"})
        reasons.append("DNS not working (+10)")

    # 7 internet
    if net["reachable"]:
        checks.append({"name": "Internet", "status": "pass", "detail": net["method"]})
    elif "captive" in net["method"]:
        checks.append({"name": "Internet", "status": "warn", "detail": net["method"]})
        recs.append("Complete the captive-portal login, then re-check")
    else:
        score += 5
        checks.append({"name": "Internet", "status": "fail", "detail": net["method"]})
        reasons.append("No internet path (+5)")

    recs += ["Verify HTTPS (🔒) before entering passwords", "Keep firewall enabled"]
    # dedupe, keep order
    recs = list(dict.fromkeys(recs))
    score = max(0, min(100, score))
    level = "low" if score <= 30 else "caution" if score <= 60 else "high" if score <= 80 else "danger"
    return {"wifi": wifi, "ip": ipinfo, "gateway_ms": gw_ms, "dns_ms": dns_ms,
            "internet": net, "checks": checks,
            "risk": {"score": score, "level": level, "reasons": reasons,
                     "recommendations": recs,
                     "verdict": "OK TO CONNECT" if level == "low" else
                                "CAUTION" if level == "caution" else "AVOID / FIX FIRST"}}


def full_status() -> dict:
    global _status_cache
    now = time.time()
    if _status_cache["payload"] and now - _status_cache["ts"] < STATUS_TTL:
        return _status_cache["payload"]
    try:
        payload = analyze()
        payload["live"] = True
    except Exception as e:
        payload = {"live": False, "error": str(e)}
    payload["nearby_count"] = len(get_nearby(payload.get("wifi", {}).get("ssid", ""))) \
        if payload.get("live") else 0
    _status_cache = {"ts": now, "payload": payload}
    return payload
