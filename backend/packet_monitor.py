"""Privacy-preserving packet and flow monitoring (stdlib only, best-effort).

What this module does:
  - Measures packet loss and latency against the local default gateway
    using ordinary ICMP probes (no elevated privileges).
  - Derives flow metadata from local socket/interface counters
    (connection counts, destination diversity, packet rate, TCP
    retransmission counters). Headers and counters only, never payloads.
  - Offers bounded, header-truncated PCAP captures via tcpdump when the
    tool is present. Captures are truncated to 128 bytes (headers only),
    size/time/packet bounded, and automatically expired.

What it deliberately does NOT do:
  - No promiscuous capture of other hosts' traffic, no payload storage,
    no long-term retention. See capture bounds and RETENTION_S below.
"""

import os
import platform
import re
import shlex
import shutil
import subprocess
import tempfile
import time

IS_WIN = platform.system() == "Windows"
IS_MAC = platform.system() == "Darwin"
IS_LINUX = platform.system() == "Linux"

# ---------------- tuning ----------------
LOSS_TTL = 60          # seconds to reuse a gateway loss probe
FLOW_TTL = 15          # seconds to reuse flow/interface counters
CAPTURE_DIR = os.path.join(tempfile.gettempdir(), "cybershield-captures")
MAX_DURATION_S = 30    # hard cap per capture
MAX_PACKETS = 2000     # hard cap per capture
DEFAULT_DURATION_S = 10
DEFAULT_PACKETS = 500
SNAPLEN = 128          # header-truncated: link + network + transport headers only
MAX_FILE_BYTES = 5 * 1024 * 1024
RETENTION_S = 900      # auto-expire captures after 15 minutes
MAX_FILES = 5

_loss_cache = {"ts": 0, "payload": None}
_flow_cache = {"ts": 0, "payload": None}
_rate_state = {"ts": 0, "total": 0}
_capture = {"proc": None, "meta": None}


def _run(cmd, timeout=10):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.stdout.strip()
    except Exception:
        return ""


def _default_gateway():
    """Best-effort default gateway without importing real_net (avoids cycles)."""
    if IS_MAC:
        out = _run(["route", "-n", "get", "default"], timeout=5)
        m = re.search(r"gateway:\s*(\S+)", out)
        if m:
            return m.group(1)
    elif IS_LINUX:
        out = _run(["ip", "route", "show", "default"], timeout=5)
        m = re.search(r"^default\s+via\s+(\S+)", out, re.M)
        if m:
            return m.group(1)
        out = _run(["route", "-n"], timeout=5)
        for line in out.splitlines():
            parts = line.split()
            if len(parts) >= 2 and parts[0] in ("0.0.0.0", "default") \
                    and re.match(r"^\d+\.\d+\.\d+\.\d+$", parts[1]):
                return parts[1]
    elif IS_WIN:
        out = _run(["route", "print", "-4"], timeout=8)
        for line in out.splitlines():
            parts = line.split()
            if len(parts) >= 3 and parts[0] == "0.0.0.0" \
                    and re.match(r"^\d+\.\d+\.\d+\.\d+$", parts[2]):
                return parts[2]
    return ""


def _ping_cmd(target: str, count: int):
    count = max(1, min(int(count or 5), 10))
    if IS_WIN:
        return ["ping", "-n", str(count), "-w", "2000", target]
    if IS_LINUX:
        return ["ping", "-c", str(count), "-W", "2", target]
    return ["ping", f"-c{count}", target]


def _default_iface() -> str:
    """Primary wireless interface name for captures (best-effort)."""
    if IS_MAC:
        return "en0"
    if IS_LINUX:
        out = _run(["iw", "dev"], timeout=5)
        m = re.search(r"Interface\s+(\S+)", out)
        if m:
            return m.group(1)
        out = _run(["ip", "route", "show", "default"], timeout=5)
        m = re.search(r"\bdev\s+(\S+)", out)
        if m:
            return m.group(1)
        return "wlan0"
    if IS_WIN:
        return "Wi-Fi"
    return "en0"


# ---------------- loss probe ----------------
def _parse_ping(out):
    """Parse BSD, Linux, and Windows ping summaries.

    Returns (sent, received, loss, avg, min, max).
    """
    sent = received = None
    loss = None
    m = re.search(r"(\d+)\s+packets transmitted[^\n]*?(\d+)\s*(?:packets? received|received)", out)
    if m:
        sent, received = int(m.group(1)), int(m.group(2))
    m = re.search(r"Packets:\s*Sent\s*=\s*(\d+),\s*Received\s*=\s*(\d+),\s*Lost\s*=\s*\d+\s*\((\d+(?:\.\d+)?)% loss\)", out)  # Windows
    if m:
        sent, received, loss = int(m.group(1)), int(m.group(2)), float(m.group(3))
    m = re.search(r"(\d+(?:\.\d+)?)\s*%\s*packet loss", out)
    if m:
        loss = float(m.group(1))
    avg = mn = mx = None
    m = re.search(r"(?:round-trip|rtt)[^\n=]*=\s*([\d.]+)/([\d.]+)/([\d.]+)", out)
    if m:
        mn, avg, mx = float(m.group(1)), float(m.group(2)), float(m.group(3))
    m = re.search(r"Minimum\s*=\s*(\d+)\s*ms,\s*Maximum\s*=\s*(\d+)\s*ms,\s*Average\s*=\s*(\d+)\s*ms", out)  # Windows
    if m:
        mn, mx, avg = float(m.group(1)), float(m.group(2)), float(m.group(3))
    if sent is not None and received is not None and loss is None:
        loss = round((sent - received) * 100.0 / sent, 1) if sent else 0.0
    return sent, received, loss, avg, mn, mx


def measure_loss(host=None, count=5, force=False):
    """Probe the gateway with a small ICMP burst. Cached for LOSS_TTL.

    Returns a dict with sent/received/loss_pct/avg_ms plus target and age.
    Never raises; unavailable environments yield ok=False with None fields.
    """
    now = time.time()
    if not force and _loss_cache["payload"] and now - _loss_cache["ts"] < LOSS_TTL:
        p = dict(_loss_cache["payload"])
        p["cached"] = True
        p["age_s"] = round(now - _loss_cache["ts"], 1)
        return p
    target = host or _default_gateway()
    if not target:
        return {"target": "", "sent": 0, "received": 0, "loss_pct": None,
                "avg_ms": None, "min_ms": None, "max_ms": None,
                "ok": False, "detail": "no default gateway found",
                "measured_at": now, "cached": False, "age_s": 0}
    count = max(1, min(int(count or 5), 10))
    out = _run(_ping_cmd(target, count), timeout=count * 3 + 8)
    sent, received, loss, avg, mn, mx = _parse_ping(out)
    if sent is None:
        payload = {"target": target, "sent": 0, "received": 0, "loss_pct": None,
                   "avg_ms": None, "min_ms": None, "max_ms": None,
                   "ok": False, "detail": "probe failed or ping unavailable",
                   "measured_at": now, "cached": False, "age_s": 0}
    else:
        payload = {"target": target, "sent": sent, "received": received,
                   "loss_pct": loss, "avg_ms": avg, "min_ms": mn, "max_ms": mx,
                   "ok": True, "detail": f"{received}/{sent} replies",
                   "measured_at": now, "cached": False, "age_s": 0}
    _loss_cache.update({"ts": now, "payload": payload})
    return dict(payload)


def last_loss():
    """Non-blocking read of the cached loss probe (None until first probe)."""
    p = _loss_cache["payload"]
    if not p:
        return None
    out = dict(p)
    out["age_s"] = round(time.time() - _loss_cache["ts"], 1)
    return out


# ---------------- flow metadata (headers/counters only) ----------------
def _tcp_table():
    if IS_WIN:
        cmds = (["netstat", "-an", "-p", "TCP"], ["netstat", "-an"])
    else:
        cmds = (["netstat", "-an", "-p", "tcp"], ["netstat", "-an", "-t"], ["ss", "-tan"])
    for cmd in cmds:
        out = _run(cmd, timeout=6)
        if out and ("ESTABLISHED" in out or "ESTAB" in out or "tcp" in out.lower()):
            return out
    return ""


def _peer_ip(token: str) -> str:
    """Strip the port from a local/foreign address token (v4, v6, Win/Mac)."""
    ip, _ = _peer_addr(token)
    return ip


def _strip_scope(s: str) -> str:
    """Drop an IPv6 zone/scope suffix (fe80::1%en0 -> fe80::1)."""
    return (s or "").split("%")[0]


def normalize_ip(s: str) -> str:
    """Canonicalise an address.

    BSD netstat prints IPv6 in a legacy notation that drops trailing zero
    groups without using '::' (2404:6800:4007:8). That form is not a valid
    RFC 5952 address, so it is re-expanded to a canonical string.
    """
    s = _strip_scope(s or "").strip().strip("[]")
    if not s:
        return ""
    import ipaddress
    try:
        return str(ipaddress.ip_address(s))
    except Exception:
        pass
    if ":" in s and "::" not in s:
        groups = s.split(":")
        if 0 < len(groups) < 8:
            try:
                return str(ipaddress.ip_address(":".join(groups + ["0"] * (8 - len(groups)))))
            except Exception:
                pass
    return s


def _is_ip(s: str) -> bool:
    import ipaddress
    try:
        ipaddress.ip_address(_strip_scope(s))
        return True
    except Exception:
        return False


def _peer_addr(token: str):
    """Split an address token into (canonical ip, port).

    Handles the layouts the supported platforms emit:
      BSD/macOS  1.2.3.4.443        2606:4700::1.443   fe80::1%en0.49152
      Windows    1.2.3.4:443        [2606:4700::1]:443
      ss/linux   1.2.3.4:443        [2606:4700::1]:443
    A bare address with no port is returned unchanged.
    """
    t = (token or "").strip()
    if not t or t in ("*:*", "*") or "*" in t:
        return "", None
    port = None
    m = re.match(r"^\[(.+)\](?::(\d+))?$", t)   # bracketed IPv6
    if m:
        t = m.group(1)
        port = int(m.group(2)) if m.group(2) else None
    else:
        # BSD form: <addr>[%scope].<port>
        md = re.search(r"\.(\d{1,5})$", t)
        if md:
            prefix = t[: md.start()]
            if ":" in prefix or _is_ip(prefix):
                t, port = prefix, int(md.group(1))
        else:
            mc = re.search(r":(\d{1,5})$", t)
            if mc and _is_ip(t[: mc.start()]):
                t, port = t[: mc.start()], int(mc.group(1))
    t = normalize_ip(t)
    if not t or not t.strip(":"):
        return "", None
    return t, port


_TCP_STATES = ("ESTABLISHED", "ESTAB", "LISTEN", "SYN_SENT", "SYN_RECV",
               "CLOSE_WAIT", "TIME_WAIT", "CLOSE", "FIN_WAIT_1", "FIN_WAIT_2",
               "LAST_ACK", "CLOSING", "NONE")


def _state_of(parts):
    for p in parts:
        up = p.upper()
        for st in _TCP_STATES:
            if up == st:
                return st
        if up.startswith("ESTAB"):
            return "ESTABLISHED"
    return "OTHER"


def _flow_rows(table: str):
    """Parse netstat/ss output into structured socket rows.

    Yields dicts: {ip, port, state, proto}. Handles the three common
    layouts:
      BSD  netstat -an -p tcp : tcp4 0 0 local.50000 remote.443 ESTABLISHED
      ss   -tan                 : ESTAB 0 0 local:50000 remote:443
      Win  netstat -an -p TCP   : TCP local:50000 remote:443 ESTABLISHED
    """
    rows = []
    for line in (table or "").splitlines():
        parts = line.split()
        if len(parts) < 3:
            continue
        proto = parts[0].upper()
        if not proto.startswith("TCP"):
            continue
        if len(parts) >= 6 and parts[0].startswith("TCP"):
            # BSD: tcp4  Recv-Q Send-Q local foreign state
            local, foreign = parts[3], parts[4]
        elif len(parts) >= 4 and parts[0] == "TCP":
            # Windows: Proto local foreign state [pid]
            local, foreign = parts[1], parts[2]
        elif len(parts) >= 5:
            # ss: State Recv-Q Send-Q local peer
            local, foreign = parts[3], parts[4]
        else:
            continue
        ip, port = _peer_addr(foreign)
        if not ip:
            continue
        rows.append({"ip": ip, "port": port, "state": _state_of(parts),
                     "proto": "tcp", "local": _peer_addr(local)[0]})
    return rows


def _flow_counts():
    table = _tcp_table()
    est = 0
    remotes = set()
    udp = 0
    peers = []
    if table:
        for line in table.splitlines():
            up = line.upper()
            parts = line.split()
            if not parts:
                continue
            proto = parts[0].upper()
            if proto.startswith("UDP"):
                udp += 1
                continue
            if not proto.startswith("TCP"):
                continue
            if "ESTABLISHED" in up or "ESTAB" in up:
                est += 1
            # Unix has 6+ cols (foreign at [4]); Windows has 4 (foreign at [2])
            foreign = parts[4] if len(parts) >= 5 else (parts[2] if len(parts) >= 3 else "")
            peer = _peer_ip(foreign)
            if peer:
                remotes.add(peer)
        for r in _flow_rows(table):
            peers.append(r)
    return est, udp, remotes, peers


# ---------------- local process attribution ----------------
# Which process on THIS host owns the connection. Best-effort: lsof on
# macOS/Linux, netstat+tasklist on Windows. Names only, no arguments.

_BROWSER = ("chrome", "firefox", "safari", "msedge", "edge", "brave", "opera",
            "vivaldi", "chromium", "arc", "waterfox")
_UPDATER = ("softwareupdated", "updater", "update", "wuauserv", "backgroundtask",
            "mdworker", "com.apple", "googleupdate", "teams", "onedrive",
            "dropbox", "steamservice", "epson", "adobe")
_MAIL = ("mail", "outlook", "thunderbird", "postfix", "imap", "dovecot")
_SYSTEM = ("launchd", "kernel_task", "systemd", "system", "svchost", "services",
           "init", "rsyslogd", "dbus", "cfprefsd", "configd", "mDNSResponder",
           "wireguard", "tailscaled", "sshd", "ntpd")


def _classify_actor(name: str) -> str:
    n = (name or "").lower()
    if not n:
        return "unknown"
    if "cybershield" in n or "uvicorn" in n:
        return "cybershield"
    if any(k in n for k in _BROWSER):
        return "browser"
    if any(k in n for k in _UPDATER):
        return "updater"
    if any(k in n for k in _MAIL):
        return "mail"
    if any(k in n for k in _SYSTEM):
        return "system"
    if any(k in n for k in ("python", "node", "java", "docker", "vpn", "openvpn",
                            "tor", "squid", "privoxy", "proxy")):
        return "tool"
    return "application"


_actor_cache = {"ts": 0, "map": {}}


def _local_actors():
    """Map remote IP -> [actor names] for open sockets. Cached, never raises."""
    now = time.time()
    if now - _actor_cache["ts"] < 20 and _actor_cache["map"]:
        return _actor_cache["map"]
    mapping = {}
    if IS_WIN:
        out = _run(["netstat", "-ano"], timeout=8)
        pids = {}
        tl = _run(["tasklist"], timeout=8)
        for line in tl.splitlines()[1:]:
            bits = line.split()
            if len(bits) >= 2 and bits[1].isdigit():
                pids[bits[1]] = bits[0]
        for line in out.splitlines():
            parts = line.split()
            if len(parts) < 4 or parts[0].upper() != "TCP":
                continue
            ip, _ = _peer_addr(parts[2])
            pid = parts[-1]
            if not ip or not pid.isdigit():
                continue
            name = pids.get(pid, "pid-" + pid)
            mapping.setdefault(ip, []).append(name)
    else:
        out = _run(["lsof", "-nP", "-iTCP", "-sTCP:ESTABLISHED"], timeout=8)
        if not out:
            out = _run(["lsof", "-nP", "-i"], timeout=8)
        for line in out.splitlines()[1:]:
            parts = line.split()
            if len(parts) < 9:
                continue
            cmd = parts[0]
            node = parts[-1]
            if "->" not in node:
                continue
            ip, _ = _peer_addr(node.split("->")[1].strip())
            if not ip:
                continue
            mapping.setdefault(ip, []).append(cmd)
    _actor_cache.update({"ts": now, "map": mapping})
    return mapping


def _iface_totals():
    """Total packets in+out for the primary interface. Returns (total, iface)."""
    # BSD/macOS path
    out = _run(["netstat", "-ib"], timeout=6)
    if out:
        best = None
        for line in out.splitlines():
            parts = line.split()
            if len(parts) < 8 or parts[0].startswith("Name"):
                continue
            name = parts[0]
            if name.startswith("lo"):
                continue
            try:
                ipack = int(parts[6]) if parts[6].isdigit() else None
                opack = int(parts[9]) if len(parts) > 9 and parts[9].isdigit() else None
            except (ValueError, IndexError):
                continue
            if ipack is None:
                continue
            total = ipack + (opack or 0)
            if best is None or (name == "en0") or total > best[0]:
                best = (total, name)
            if name == "en0":
                break
        if best:
            return best[0], best[1]
    # Linux path
    try:
        with open("/proc/net/dev") as f:
            best = None
            for line in f:
                if ":" not in line:
                    continue
                name, rest = line.split(":", 1)
                name = name.strip()
                if name == "lo":
                    continue
                nums = rest.split()
                if len(nums) < 10:
                    continue
                total = int(nums[1]) + int(nums[9])
                if best is None or total > best[0]:
                    best = (total, name)
            if best:
                return best
    except Exception:
        pass
    return None, ""


def _tcp_retrans():
    for cmd in (["netstat", "-s", "-p", "tcp"], ["netstat", "-s", "-t"]):
        out = _run(cmd, timeout=6)
        if not out:
            continue
        m = re.search(r"(\d[\d,]*)\s+(?:segments? )?retransmit", out, re.I)
        if m:
            try:
                return int(m.group(1).replace(",", ""))
            except ValueError:
                pass
        m = re.search(r"retransmit\w*\s*[:=]?\s*(\d[\d,]*)", out, re.I)
        if m:
            try:
                return int(m.group(1).replace(",", ""))
            except ValueError:
                pass
    try:
        with open("/proc/net/netstat") as f:
            txt = f.read()
        m = re.search(r"Tcp:\s*([^\n]+)\nTcp:\s*([^\n]+)", txt)
        if m:
            keys, vals = m.group(1).split(), m.group(2).split()
            if "RetransSegs" in keys:
                return int(vals[keys.index("RetransSegs")])
    except Exception:
        pass
    return None


def flow_stats(force=False, with_peers=False):
    """Local flow metadata snapshot. Cached for FLOW_TTL. Never raises.

    with_peers=True additionally returns the observed remote endpoints
    (ip, port, state) and the local process that owns each connection.
    Addresses and process names only - never payloads.
    """
    now = time.time()
    if not force and _flow_cache["payload"] and now - _flow_cache["ts"] < FLOW_TTL:
        p = dict(_flow_cache["payload"])
        p["cached"] = True
        if not with_peers or "peers" in p:
            return p
        # cache was built without peer detail -> fall through and rebuild
    est, udp, remotes, rows = _flow_counts()
    total, iface = _iface_totals()
    retrans = _tcp_retrans()
    rate = None
    if total is not None:
        prev_ts, prev_total = _rate_state["ts"], _rate_state["total"]
        dt = now - prev_ts
        if prev_ts and 1 <= dt <= 300 and total >= prev_total:
            rate = round((total - prev_total) / dt, 1)
        _rate_state.update({"ts": now, "total": total})
    payload = {"tcp_connections": est, "udp_entries": udp,
               "unique_remote_ips": len(remotes),
               "dest_diversity": len(remotes),
               "packet_rate_pps": rate, "rate_iface": iface,
               "tcp_retrans": retrans, "ok": True,
               "measured_at": now, "cached": False}
    if with_peers:
        actors = _local_actors()
        seen = set()
        peers = []
        for r in rows:
            key = (r["ip"], r["port"], r["state"])
            if key in seen:
                continue
            seen.add(key)
            names = actors.get(r["ip"]) or []
            peers.append({**r,
                          "actors": names,
                          "actor_class": _classify_actor(names[0]) if names else "unknown"})
        payload["peers"] = peers
        payload["actor_note"] = ("Local process names are read from the OS socket table; "
                                 "no arguments, no payloads.")
    _flow_cache.update({"ts": now, "payload": payload})
    return dict(payload)


def packet_features():
    """Non-blocking feature dict for the AI snapshot (None when unknown)."""
    loss = last_loss()
    flow = flow_stats()
    return {
        "packet_loss_pct": (loss or {}).get("loss_pct"),
        "packet_rate_pps": flow.get("packet_rate_pps"),
        "tcp_retrans": flow.get("tcp_retrans"),
        "tcp_connections": flow.get("tcp_connections"),
        "dest_diversity": flow.get("dest_diversity"),
    }


def measure_all(gateway=None, count=5):
    """Blocking combined probe for the packet endpoint (loss + flow)."""
    loss = measure_loss(host=gateway, count=count, force=True)
    flow = flow_stats(force=True, with_peers=True)
    return {"loss": loss, "flow": flow, "measured_at": time.time()}


# ---------------- bounded PCAP capture (tcpdump, optional) ----------------
def tcpdump_available():
    return bool(shutil.which("tcpdump"))


def _ensure_dir():
    try:
        os.makedirs(CAPTURE_DIR, exist_ok=True)
    except Exception:
        pass


def _capture_files():
    _ensure_dir()
    try:
        names = [n for n in os.listdir(CAPTURE_DIR) if n.endswith(".pcap")]
    except Exception:
        return []
    rows = []
    for n in names:
        p = os.path.join(CAPTURE_DIR, n)
        try:
            st = os.stat(p)
            rows.append({"file": n, "size": st.st_size,
                         "created": st.st_mtime,
                         "age_s": round(time.time() - st.st_mtime, 1),
                         "expires_in_s": max(0, int(RETENTION_S - (time.time() - st.st_mtime)))})
        except Exception:
            continue
    rows.sort(key=lambda r: r["created"], reverse=True)
    return rows


def _expire_captures():
    now = time.time()
    for row in _capture_files():
        p = os.path.join(CAPTURE_DIR, row["file"])
        try:
            if now - row["created"] > RETENTION_S or os.path.getsize(p) > MAX_FILE_BYTES:
                os.remove(p)
        except Exception:
            pass
    rows = _capture_files()
    for row in rows[MAX_FILES:]:
        try:
            os.remove(os.path.join(CAPTURE_DIR, row["file"]))
        except Exception:
            pass


def _proc_alive():
    proc = _capture["proc"]
    return proc is not None and proc.poll() is None


def capture_status():
    """Current capture state plus retained file list (metadata only)."""
    _expire_captures()
    active = _proc_alive()
    meta = dict(_capture["meta"]) if _capture["meta"] else None
    if meta:
        meta["elapsed_s"] = round(time.time() - meta.get("started_at", time.time()), 1)
        meta["active"] = active
        fp = os.path.join(CAPTURE_DIR, meta.get("file", ""))
        try:
            meta["size"] = os.path.getsize(fp)
        except Exception:
            meta["size"] = 0
    if not active and _capture["proc"] is not None:
        _capture["proc"] = None
    return {"tcpdump_available": tcpdump_available(),
            "capture_dir": CAPTURE_DIR,
            "active": active,
            "capture": meta,
            "captures": _capture_files(),
            "bounds": {"max_duration_s": MAX_DURATION_S, "max_packets": MAX_PACKETS,
                       "snaplen": SNAPLEN, "max_bytes": MAX_FILE_BYTES,
                       "retention_s": RETENTION_S, "max_files": MAX_FILES},
            "privacy": ("Header-truncated captures only "
                        f"(snaplen {SNAPLEN}); payloads discarded. "
                        f"Files auto-expire after {RETENTION_S // 60} minutes.")}


def _valid_iface(iface):
    return bool(re.fullmatch(r"[A-Za-z0-9._-]{1,32}", iface or ""))


def _valid_filter(f):
    if not f:
        return True
    if len(f) > 200 or re.search(r"[;&|`$!\\\n]", f):
        return False
    return True


def start_capture(interface="", duration_s=DEFAULT_DURATION_S,
                  max_packets=DEFAULT_PACKETS, pcap_filter=""):
    _expire_captures()
    if not tcpdump_available():
        return {"ok": False,
                "detail": "tcpdump is not installed (macOS: brew install tcpdump; "
                          "Debian/Ubuntu: sudo apt install tcpdump; "
                          "Windows: Npcap plus WinDump or Wireshark's tshark). "
                          "Loss and flow metrics still work without it."}
    interface = interface or _default_iface()
    if not _valid_iface(interface):
        return {"ok": False, "detail": "invalid interface name"}
    if not _valid_filter(pcap_filter or ""):
        return {"ok": False, "detail": "filter contains disallowed characters"}
    try:
        duration_s = max(1, min(int(duration_s), MAX_DURATION_S))
        max_packets = max(1, min(int(max_packets), MAX_PACKETS))
    except (TypeError, ValueError):
        return {"ok": False, "detail": "duration and max_packets must be integers"}
    if _proc_alive():
        stop_capture()
    _ensure_dir()
    fname = f"capture-{int(time.time())}.pcap"
    path = os.path.join(CAPTURE_DIR, fname)
    cmd = ["tcpdump", "-i", interface, "-s", str(SNAPLEN),
           "-c", str(max_packets), "-G", str(duration_s), "-W", "1",
           "-w", path]
    if pcap_filter:
        cmd += shlex.split(pcap_filter)
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL)
    except PermissionError:
        return {"ok": False,
                "detail": "tcpdump needs packet-capture permission "
                          "(Linux: sudo or CAP_NET_RAW; macOS: sudo or a developer-tools "
                          "prompt; Windows: Npcap installed with WinPcap-compatible mode)."}
    except Exception as e:
        return {"ok": False, "detail": f"could not start tcpdump: {e.__class__.__name__}"}
    time.sleep(0.4)
    if proc.poll() not in (None,):
        return {"ok": False,
                "detail": "tcpdump exited immediately; check interface name and permissions."}
    _capture["proc"] = proc
    _capture["meta"] = {"file": fname, "interface": interface,
                        "started_at": time.time(), "duration_s": duration_s,
                        "max_packets": max_packets, "filter": pcap_filter or "",
                        "snaplen": SNAPLEN, "pid": proc.pid}
    return {"ok": True, "capture": capture_status()["capture"]}


def stop_capture():
    proc = _capture["proc"]
    if proc is None or proc.poll() is not None:
        _capture["proc"] = None
        return {"ok": True, "detail": "no active capture"}
    try:
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except Exception:
            proc.kill()
    except Exception:
        pass
    _capture["proc"] = None
    return {"ok": True, "detail": "capture stopped"}


def resolve_capture(name):
    """Validate a download name and return its absolute path, or None."""
    if not name or "/" in name or "\\" in name or not name.endswith(".pcap"):
        return None
    if not re.fullmatch(r"[A-Za-z0-9._-]{1,64}", name):
        return None
    _expire_captures()
    path = os.path.join(CAPTURE_DIR, name)
    try:
        if os.path.isfile(path) and os.path.getsize(path) <= MAX_FILE_BYTES:
            return path
    except Exception:
        pass
    return None
