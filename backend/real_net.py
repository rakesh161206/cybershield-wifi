"""Live host-network collectors (Windows, macOS, and Linux; stdlib only).

Per-OS sources (all best-effort, first working source wins):
  macOS:   system_profiler (Wi-Fi link + nearby), ipconfig/route (IP/gateway),
           scutil (DNS), networksetup (preferred networks, in policy.py)
  Linux:   iw + nmcli (Wi-Fi link + nearby), ip route (gateway),
           /etc/resolv.conf (DNS)
  Windows: netsh wlan (Wi-Fi link + nearby), route print (gateway),
           ipconfig /all (DNS, DHCP lease)

Common: socket-based IP/DNS/TCP checks, ping + captive-portal health,
arp + ping sweep (LAN devices). Everything degrades gracefully to
'unavailable' when a source is missing (no Wi-Fi, missing tool, sandbox).
"""
import json
import platform
import re
import shutil
import socket
import subprocess
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed

IS_WIN = platform.system() == "Windows"
IS_MAC = platform.system() == "Darwin"
IS_LINUX = platform.system() == "Linux"

STATUS_TTL = 10          # seconds to cache /api/real/status
_devices_cache = {"ts": 0, "devices": [], "mode": ""}
_status_cache = {"ts": 0, "payload": None}


def _run(cmd, timeout=8):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.stdout.strip()
    except Exception:
        return ""


def _have(tool: str) -> bool:
    return bool(shutil.which(tool))


def _ping_cmd(host: str, count=2, timeout=3):
    """Platform-appropriate ping argv (no shell)."""
    count = max(1, int(count))
    if IS_WIN:
        return ["ping", "-n", str(count), "-w", str(int(timeout * 1000)), host]
    if IS_LINUX:
        return ["ping", "-c", str(count), "-W", str(max(1, int(timeout))), host]
    return ["ping", f"-c{count}", f"-t{int(timeout)}", host]


def _ping_timeout(count=2, timeout=3):
    return int(count) * (int(timeout) if not IS_WIN else max(1, int(timeout))) + 8


# ---------- Wi-Fi ----------
SEC_LABELS = [
    ("wpa3", "WPA3"),
    ("wpa2", "WPA2"),
    ("wpa", "WPA"),
    ("wep", "WEP"),
]

def _sec_label(raw: str) -> str:
    s = (raw or "").lower()
    if not s or not s.strip("- ") or "none" in s or s.endswith("_open") or "open" in s and "wpa" not in s:
        # profiler uses e.g. 'spairport_security_mode_none' for open;
        # nmcli shows '--'/empty for open networks
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
    iface = {}
    if IS_MAC:
        out = _run(["system_profiler", "SPAirPortDataType", "-json"], timeout=15)
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


# ---------- cross-platform Wi-Fi (Linux iw/nmcli, Windows netsh) ----------
def _pct_to_dbm(pct) -> int | None:
    try:
        return int(float(pct) / 2) - 100
    except (TypeError, ValueError):
        return None


def _sort_nets(out: list) -> list:
    out.sort(key=lambda x: (x["signal_dbm"] is None, -(x["signal_dbm"] or -999)))
    return out


def _nmcli_split(line: str) -> list:
    return [p.replace("\\:", ":") for p in re.split(r"(?<!\\):", line.rstrip("\n"))]


def _parse_iw_link(text: str) -> dict:
    """Parse `iw dev <iface> link` output. Pure function (unit-testable)."""
    m = re.search(r"^\s*SSID:\s*(.+?)\s*$", text, re.M)
    if not m:
        return {"connected": False}
    out = {"connected": True, "ssid": m.group(1)}
    m = re.search(r"signal:\s*(-?\d+)\s*dBm", text)
    out["signal_dbm"] = int(m.group(1)) if m else None
    m = re.search(r"tx bitrate:\s*([\d.]+)", text)
    out["rate_mbps"] = float(m.group(1)) if m else None
    m = re.search(r"freq:\s*(\d+)", text)
    freq = int(m.group(1)) if m else 0
    out["band"] = "2.4GHz" if freq and freq < 3000 else ("5GHz" if freq else "")
    return out


def _parse_nmcli_scan(text: str) -> list:
    """Parse `nmcli -t -f IN-USE,SSID,SIGNAL,CHAN,SECURITY dev wifi list`.

    Returns [{ssid, in_use, signal_dbm, channel, security_raw}] (pure function).
    """
    rows = []
    for line in (text or "").splitlines():
        if not line.strip():
            continue
        parts = _nmcli_split(line)
        if len(parts) < 5:
            continue
        in_use = parts[0].strip()
        sec = parts[-1].strip()
        chan = parts[-2].strip()
        sig = parts[-3].strip()
        ssid = ":".join(parts[1:-3]).strip()
        if not ssid:
            continue
        rows.append({"ssid": ssid, "in_use": in_use == "*",
                     "signal_dbm": _pct_to_dbm(sig),
                     "channel": chan if chan.isdigit() else "",
                     "security_raw": sec})
    return rows


def _linux_wifi_iface() -> str:
    out = _run(["iw", "dev"], timeout=5)
    m = re.search(r"Interface\s+(\S+)", out)
    if m:
        return m.group(1)
    out = _run(["nmcli", "-t", "-f", "DEVICE,TYPE", "device", "status"], timeout=8)
    for line in out.splitlines():
        parts = _nmcli_split(line)
        if len(parts) >= 2 and parts[1].strip() == "wifi" and parts[0].strip() not in ("lo", ""):
            return parts[0].strip()
    return ""


def _linux_wifi() -> dict:
    iface = _linux_wifi_iface()
    if not iface:
        return {"connected": False}
    link = _parse_iw_link(_run(["iw", "dev", iface, "link"], timeout=6))
    if not link.get("connected"):
        return {"connected": False}
    scan = _run(["nmcli", "-t", "-f", "IN-USE,SSID,SIGNAL,CHAN,SECURITY",
                 "device", "wifi", "list", "--rescan", "no"], timeout=15)
    row = next((r for r in _parse_nmcli_scan(scan) if r["ssid"] == link["ssid"] and r["in_use"]),
               next((r for r in _parse_nmcli_scan(scan) if r["ssid"] == link["ssid"]), None))
    mac = ""
    try:
        with open(f"/sys/class/net/{iface}/address") as f:
            mac = f.read().strip()
    except Exception:
        pass
    sec_raw = (row or {}).get("security_raw", "")
    return {
        "connected": True, "ssid": link["ssid"],
        "channel": (row or {}).get("channel", ""),
        "band": link.get("band", ""), "width": "", "phy": "",
        "rate_mbps": link.get("rate_mbps"),
        "security_raw": sec_raw, "security": _sec_label(sec_raw),
        "signal_dbm": link.get("signal_dbm"),
        "noise_dbm": None, "snr_db": None,
        "mac": mac, "country": "",
    }


def _linux_nearby(current_ssid="") -> list:
    scan = _run(["nmcli", "-t", "-f", "IN-USE,SSID,SIGNAL,CHAN,SECURITY",
                 "device", "wifi", "list", "--rescan", "no"], timeout=15)
    rows = _parse_nmcli_scan(scan)
    if not rows:
        return []
    return _sort_nets([{
        "ssid": r["ssid"], "signal_dbm": r["signal_dbm"],
        "channel": r["channel"], "phy": "",
        "security": _sec_label(r["security_raw"]),
        "is_current": bool(current_ssid and r["ssid"] == current_ssid),
    } for r in rows])


def _parse_netsh_kv(text: str) -> dict:
    """Parse `netsh wlan show interfaces` flat `Key : Value` output."""
    kv = {}
    for line in (text or "").splitlines():
        m = re.match(r"^\s*([^:]+?)\s*:\s*(.*?)\s*$", line)
        if m:
            kv[m.group(1).strip().lower()] = m.group(2).strip()
    return kv


def _parse_netsh_networks(text: str) -> list:
    """Parse `netsh wlan show networks mode=bssid` output (pure function)."""
    nets, cur = [], None
    for line in (text or "").splitlines():
        m = re.match(r"^SSID \d+ : (.*)$", line)
        if m:
            if cur and cur.get("ssid"):
                nets.append(cur)
            cur = {"ssid": m.group(1).strip(), "signal_dbm": None,
                   "channel": "", "phy": "", "security_raw": ""}
            continue
        if cur is None:
            continue
        m = re.match(r"^\s*Authentication\s*:\s*(.+?)\s*$", line)
        if m:
            cur["security_raw"] = m.group(1)
            continue
        m = re.match(r"^\s*Signal\s*:\s*(\d+)\s*%?\s*$", line)
        if m and (cur["signal_dbm"] is None or _pct_to_dbm(m.group(1)) > cur["signal_dbm"]):
            cur["signal_dbm"] = _pct_to_dbm(m.group(1))
            continue
        m = re.match(r"^\s*Channel\s*:\s*(\d+)", line)
        if m and not cur["channel"]:
            cur["channel"] = m.group(1)
            continue
        m = re.match(r"^\s*Radio type\s*:\s*(.+?)\s*$", line)
        if m and not cur["phy"]:
            cur["phy"] = m.group(1)
    if cur and cur.get("ssid"):
        nets.append(cur)
    return [n for n in nets if n["ssid"]]


def _win_wifi() -> dict:
    kv = _parse_netsh_kv(_run(["netsh", "wlan", "show", "interfaces"], timeout=10))
    ssid = kv.get("ssid", "")
    if not ssid or kv.get("state", "").lower() != "connected":
        return {"connected": False}
    auth = kv.get("authentication", "")
    rate = None
    m = re.search(r"([\d.]+)", kv.get("transmit rate (mbps)", "") or kv.get("receive rate (mbps)", ""))
    if m:
        try:
            rate = float(m.group(1))
        except ValueError:
            rate = None
    return {
        "connected": True, "ssid": ssid,
        "channel": kv.get("channel", ""), "band": "",
        "width": "", "phy": kv.get("radio type", ""),
        "rate_mbps": rate,
        "security_raw": auth, "security": _sec_label(auth),
        "signal_dbm": _pct_to_dbm(re.search(r"(\d+)", kv.get("signal", "")).group(1)) if re.search(r"(\d+)", kv.get("signal", "")) else None,
        "noise_dbm": None, "snr_db": None,
        "mac": kv.get("physical address", ""), "country": "",
        "bssid": kv.get("bssid", ""),
    }


def _win_nearby(current_ssid="") -> list:
    nets = _parse_netsh_networks(_run(["netsh", "wlan", "show", "networks", "mode=bssid"], timeout=20))
    if not nets:
        return []
    return _sort_nets([{
        "ssid": n["ssid"], "signal_dbm": n["signal_dbm"],
        "channel": n["channel"], "phy": n.get("phy", ""),
        "security": _sec_label(n["security_raw"]),
        "is_current": bool(current_ssid and n["ssid"] == current_ssid),
    } for n in nets])


def get_wifi() -> dict:
    if IS_LINUX:
        w = _linux_wifi()
        if w.get("connected"):
            return w
    elif IS_WIN:
        w = _win_wifi()
        if w.get("connected"):
            return w
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
    if IS_LINUX:
        nets = _linux_nearby(current_ssid)
        if nets:
            return nets
    elif IS_WIN:
        nets = _win_nearby(current_ssid)
        if nets:
            return nets
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
def _parse_ip_route(text: str) -> str:
    """Gateway from Linux `ip route show default` (pure function)."""
    m = re.search(r"^default\s+via\s+(\S+)", text or "", re.M)
    return m.group(1) if m else ""


def _parse_route_n(text: str) -> str:
    """Gateway from BSD/Linux `route -n` / `netstat -rn` tables (pure function)."""
    for line in (text or "").splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[0] in ("0.0.0.0", "default"):
            if re.match(r"^\d+\.\d+\.\d+\.\d+$", parts[1]):
                return parts[1]
    return ""


def _parse_route_print(text: str) -> str:
    """Gateway from Windows `route print -4` (pure function)."""
    for line in (text or "").splitlines():
        parts = line.split()
        if len(parts) >= 3 and parts[0] == "0.0.0.0" and re.match(r"^\d+\.\d+\.\d+\.\d+$", parts[2]):
            return parts[2]
    return ""


def _parse_resolv_conf(text: str) -> list:
    dns = []
    for line in (text or "").splitlines():
        m = re.match(r"^\s*nameserver\s+(\S+)", line)
        if m and m.group(1) not in dns and not m.group(1).startswith("127."):
            dns.append(m.group(1))
    return dns


def _parse_ipconfig_dns(text: str) -> list:
    """DNS servers from Windows `ipconfig /all` (handles continuation lines)."""
    dns, capture = [], False
    for line in (text or "").splitlines():
        m = re.search(r"DNS Servers[^:]*:\s*(\S+)?", line)
        if m:
            capture = True
            if m.group(1) and re.match(r"^[\d.:a-fA-F]+$", m.group(1)):
                if m.group(1) not in dns:
                    dns.append(m.group(1))
            continue
        if capture:
            m = re.match(r"^\s+([\d.:a-fA-F]+)\s*$", line)
            if m:
                if m.group(1) not in dns:
                    dns.append(m.group(1))
            elif line.strip():
                capture = False
    return dns


def _local_ip() -> str:
    """First non-loopback IPv4 via a UDP socket trick (works on every OS)."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(2)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return ""


def _gateway() -> str:
    if IS_MAC:
        route = _run(["route", "-n", "get", "default"], timeout=5)
        m = re.search(r"gateway:\s*(\S+)", route)
        if m:
            return m.group(1)
    elif IS_LINUX:
        gw = _parse_ip_route(_run(["ip", "route", "show", "default"], timeout=5))
        if gw:
            return gw
        gw = _parse_route_n(_run(["route", "-n"], timeout=5))
        if gw:
            return gw
    elif IS_WIN:
        gw = _parse_route_print(_run(["route", "print", "-4"], timeout=8))
        if gw:
            return gw
    return ""


def _dns_servers() -> list:
    dns = []
    if IS_MAC:
        sc = _run(["scutil", "--dns"], timeout=5)
        for m in re.finditer(r"nameserver\[\d+\]\s*:\s*(\S+)", sc):
            if m.group(1) not in dns:
                dns.append(m.group(1))
    elif IS_WIN:
        dns = _parse_ipconfig_dns(_run(["ipconfig", "/all"], timeout=8))
    if not dns and not IS_WIN:
        try:
            with open("/etc/resolv.conf") as f:
                dns = _parse_resolv_conf(f.read())
        except Exception:
            pass
    return dns[:4]


def get_ip_info() -> dict:
    ip = ""
    if IS_MAC:
        ip = _run(["ipconfig", "getifaddr", "en0"], timeout=5)
    if not ip or "." not in ip:
        ip = _local_ip()
    gw = _gateway()
    return {"ip": ip, "gateway": gw, "dns": _dns_servers(),
            "valid": bool(ip and not ip.startswith("169.254."))}


def ping_avg(host: str, count=2, timeout=3):
    out = _run(_ping_cmd(host, count, timeout), timeout=_ping_timeout(count, timeout))
    m = re.search(r"min/avg/max.*=\s*[\d.]+/([\d.]+)/", out)
    if m:
        return float(m.group(1))
    m = re.search(r"Average\s*=\s*(\d+)\s*ms", out)  # Windows
    if m:
        return float(m.group(1))
    if "1 packets received" in out or re.search(r"[1-9]\d* packets received", out):
        return 1.0
    if re.search(r"Received\s*=\s*[1-9]", out):  # Windows, sub-ms replies
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


# ---------- link vitals: lease (connection time) + speed ----------
def _parse_lease(text: str, pattern: str) -> float | None:
    m = re.search(pattern, text or "")
    if not m:
        return None
    try:
        a, b, y, hh, mm, ss = map(int, m.groups())
        # disambiguate d/m vs m/d: month can never exceed 12
        mon, day = (b, a) if a > 12 else (a, b)
        from datetime import datetime
        return datetime(y, mon, day, hh, mm, ss).timestamp()
    except Exception:
        return None


def get_lease_start() -> float | None:
    """Epoch of DHCP lease start ≈ time this connection came up."""
    if IS_MAC:
        out = _run(["ipconfig", "getsummary", "en0"], timeout=5)
        return _parse_lease(out, r"LeaseStartTime\s*:\s*(\d{1,2})/(\d{1,2})/(\d{4})\s+(\d{1,2}):(\d{2}):(\d{2})")
    if IS_WIN:
        out = _run(["ipconfig", "/all"], timeout=8)
        # e.g. "Lease Obtained. . . . : Saturday, October 10, 2026 8:00:00 AM"
        m = re.search(r"Lease Obtained[^:]*:\s*(.+)", out)
        if m:
            from datetime import datetime
            for fmt in ("%A, %B %d, %Y %I:%M:%S %p", "%d %B %Y %H:%M:%S",
                        "%m/%d/%Y %I:%M:%S %p"):
                try:
                    return datetime.strptime(m.group(1).strip(), fmt).timestamp()
                except Exception:
                    continue
        return None
    return None


_speed_cache = {"ts": 0, "mbps": None}


def speed_test(mb: int = 10, timeout: int = 30) -> float | None:
    """Download N MB from Cloudflare edge, return Mbps. Cached result served by link()."""
    global _speed_cache
    url = f"https://speed.cloudflare.com/__down?bytes={mb * 1000 * 1000}"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "CyberShield"})
        t0 = time.time()
        total = 0
        with urllib.request.urlopen(req, timeout=timeout) as r:
            while True:
                chunk = r.read(256 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if time.time() - t0 > timeout:
                    break
        dt = time.time() - t0
        if dt <= 0 or total == 0:
            return None
        mbps = round((total * 8) / dt / 1_000_000, 1)
        _speed_cache = {"ts": time.time(), "mbps": mbps}
        return mbps
    except Exception:
        return None


def link_stats() -> dict:
    """Cheap snapshot for the header tiles (no speed download)."""
    info = get_ip_info()
    gw = ping_avg(info["gateway"]) if info.get("gateway") else None
    dns = check_dns_time()
    net = check_internet()
    lease = get_lease_start()
    return {"speed_mbps": _speed_cache["mbps"], "speed_at": _speed_cache["ts"],
            "gateway_ms": gw, "dns_ms": dns,
            "internet_ms": net.get("latency_ms"),
            "internet_ok": net.get("reachable", False),
            "lease_start": lease,
            "connected_for_s": int(time.time() - lease) if lease else None}


# ---------- LAN devices ----------
def _parse_arp(text: str) -> dict:
    """Parse BSD/macOS/Linux `arp -a` plus Windows `arp -a` output (pure)."""
    devs = {}
    for m in re.finditer(r"\(([\d.]+)\)\s+at\s+([0-9a-f:-]+)", text or "", re.I):
        if m.group(2).lower() != "incomplete":
            devs[m.group(1)] = m.group(2).lower().replace("-", ":")
    for line in (text or "").splitlines():
        m = re.match(r"^\s*([\d.]+)\s+([0-9a-fA-F-]{17})\s+\w+", line)
        if m:
            devs[m.group(1)] = m.group(2).lower().replace("-", ":")
    return devs


def _arp_table() -> dict:
    return _parse_arp(_run(["arp", "-a"], timeout=5))


def _ping_alive(out: str) -> tuple:
    """(alive, latency_ms|None) from BSD/Linux/Windows ping output."""
    m = re.search(r"time[=<]([\d.]+)\s*ms", out)
    ms = float(m.group(1)) if m else None
    if re.search(r"[1-9]\d* packets received", out):
        return True, ms if ms is not None else 1.0
    if "1 packets received" in out:
        return True, ms if ms is not None else 1.0
    m = re.search(r"Received\s*=\s*(\d+)", out)  # Windows
    if m and int(m.group(1)) > 0:
        m2 = re.search(r"Average\s*=\s*(\d+)\s*ms", out)
        return True, float(m2.group(1)) if m2 else (ms if ms is not None else 1.0)
    return False, None


def _sweep(prefix: str, self_ip: str, timeout=1) -> list:
    targets = [f"{prefix}.{i}" for i in range(1, 255) if f"{prefix}.{i}" != self_ip]

    def _one(ip):
        out = _run(_ping_cmd(ip, 1, timeout), timeout=timeout + 3)
        alive, ms = _ping_alive(out)
        return (ip, ms) if alive else None

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
