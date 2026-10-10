"""Zero-Trust enforcement: score networks, block threats for real.

Per-OS actions (no elevated privileges needed for the common cases):
  macOS:   block = networksetup removes SSID from preferred list
  Linux:   block = nmcli deletes the saved connection
  Windows: block = netsh deletes the saved profile
In every case the Mac/PC will not auto-join the network again, and the
SSID is recorded in the blocklist. Unblock = allowlist it (auto-protect
will not touch it again). Disconnect = turn Wi-Fi off (manual +
confirmed only, never automatic). Where the platform tool is missing,
actions report honestly instead of pretending to act.

Forgetting never drops the current connection — it only stops
future auto-joins. LAN devices cannot be truly blocked from the host;
flagging records them and points at the router for MAC filtering.
"""
import platform
import re
import shutil
import subprocess
import time
from real_net import _run
import database as db

IS_WIN = platform.system() == "Windows"
IS_MAC = platform.system() == "Darwin"
IS_LINUX = platform.system() == "Linux"


def _have(tool: str) -> bool:
    return bool(shutil.which(tool))

SEC_BASE = {"open": 85, "wep": 92, "wpa": 75, "unknown": 60,
            "wpa2": 15, "wpa3": 5}


def _sec_class(security: str) -> str:
    s = (security or "").lower()
    if s.startswith("open"):
        return "open"
    if "wep" in s:
        return "wep"
    if "wpa3" in s:
        return "wpa3"
    if "wpa2" in s:
        return "wpa2"
    if "wpa" in s:
        return "wpa"
    return "unknown"


def score_network(net: dict, ssid_variants: dict, public_hint: bool) -> tuple:
    """Return (score 0-100, verdict, reasons)."""
    cls = _sec_class(net.get("security", ""))
    score = SEC_BASE[cls]
    reasons = []
    if cls == "open":
        reasons.append("No encryption (+85)")
    elif cls == "wep":
        reasons.append("Broken WEP (+92)")
    elif cls == "wpa":
        reasons.append("Outdated WPA (+75)")
    elif cls == "unknown":
        reasons.append("Unverified encryption (+60)")
    else:
        reasons.append(f"{net.get('security')} baseline (+{score})")
    ssid = net.get("ssid") or ""
    if public_hint and cls in ("wpa2", "wpa3"):
        score = max(score, 45)
        reasons.append("Public/shared hotspot (+45 floor)")
    if len(ssid_variants.get(ssid, set())) > 1:
        score = min(95, score + 15)
        reasons.append("Possible twin: same name, different settings (+15)")
    if (net.get("signal_dbm") or 0) < -78:
        score = min(100, score + 5)
        reasons.append("Very weak signal (+5)")
    score = max(0, min(100, score))
    verdict = "avoid" if score >= 65 else "caution" if score >= 35 else "connect"
    return score, verdict, reasons


# ---------- OS actions ----------
def preferred_networks() -> list:
    if IS_MAC:
        out = _run(["networksetup", "-listpreferredwirelessnetworks", "en0"], timeout=8)
        return [l.strip() for l in out.splitlines()[1:] if l.strip()]
    if IS_LINUX and _have("nmcli"):
        out = _run(["nmcli", "-t", "-f", "NAME,TYPE", "connection", "show"], timeout=8)
        names = []
        for line in out.splitlines():
            parts = line.split(":", 1)
            if len(parts) == 2 and parts[1].strip() == "802-11-wireless" and parts[0].strip():
                names.append(parts[0].strip())
        return names
    if IS_WIN:
        out = _run(["netsh", "wlan", "show", "profiles"], timeout=8)
        return [m.group(1).strip() for m in
                re.finditer(r"All User Profile\s*:\s*(.+)", out)]
    return []


def forget_network(ssid: str) -> tuple:
    if IS_MAC:
        out = _run(["networksetup", "-removepreferredwirelessnetwork", "en0", ssid], timeout=10)
        if "was not found" in out:
            return False, "not in preferred list (already forgotten or never joined)"
        return True, out or "removed from preferred networks"
    if IS_LINUX:
        if not _have("nmcli"):
            return False, ("nmcli not found: forget is unsupported here — "
                           "remove the network in your Wi-Fi settings instead")
        out = _run(["nmcli", "connection", "delete", ssid], timeout=10)
        if "successfully deleted" in out.lower() or "no such" in out.lower():
            return True, out or "saved connection deleted"
        return False, out or "nmcli could not delete the connection"
    if IS_WIN:
        out = _run(["netsh", "wlan", "delete", "profile", f"name={ssid}"], timeout=10)
        if "is deleted" in out:
            return True, out.splitlines()[0] if out else "profile deleted"
        return False, out or "netsh could not delete the profile"
    return False, "forget is not supported on this OS"


def disconnect_wifi() -> tuple:
    if IS_MAC:
        out = _run(["networksetup", "-setairportpower", "en0", "off"], timeout=10)
        return True, out or "Wi-Fi turned off"
    if IS_LINUX and _have("nmcli"):
        out = _run(["nmcli", "radio", "wifi", "off"], timeout=10)
        return True, out or "Wi-Fi turned off"
    if IS_WIN:
        for name in ("Wi-Fi", "Wireless Network Connection"):
            out = _run(["netsh", "interface", "set", "interface",
                        f"name={name}", "admin=disable"], timeout=10)
            if out == "" or "Ok." in out:
                return True, f"Interface {name} disabled"
        return False, ("could not disable Wi-Fi (Windows may need the exact "
                       "interface name or administrator rights)")
    return False, "disconnect is not supported on this OS"


# ---------- ask-first protection ----------
def evaluate_pending(scored: list) -> list:
    """`avoid` networks waiting for the user's decision.
    Nothing is forgotten automatically — the dashboard shows
    Block / Allow for each one."""
    try:
        preferred = set(preferred_networks())
    except Exception:
        preferred = set()
    pending = []
    for n in scored:
        ssid = n.get("ssid") or ""
        if not ssid or n.get("recommendation", {}).get("verdict") != "avoid":
            continue
        if db.is_blocked(ssid) or db.is_allowed(ssid):
            continue
        pending.append({"ssid": ssid, "score": n.get("score"),
                        "reasons": n["recommendation"]["reasons"],
                        "preferred": ssid in preferred})
    return pending


def policy_status() -> dict:
    return {"auto_protect": True,
            "blocked": db.get_blocked(),
            "allowed": db.get_allowed(),
            "flagged_devices": db.get_flagged(),
            "note": "Protection is ask-first: risky networks are listed "
                    "for your decision, nothing is forgotten until you confirm."}
