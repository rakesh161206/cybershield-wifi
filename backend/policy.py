"""Zero-Trust enforcement: score networks, auto-block threats for real.

Real actions on macOS (no sudo needed):
  block   = remove SSID from preferred list -> Mac will not auto-join it
  unblock = allowlist it (auto-protect will not touch it again)
  disconnect = turn Wi-Fi off (manual + confirmed only, never automatic)

Auto-protect runs on every radar scan: any `avoid` network found in the
preferred list is forgotten + recorded, unless you allowlisted it.
Forgetting never drops the current connection — it only stops
future auto-joins. LAN devices cannot be truly blocked from the Mac;
flagging records them and points at the router for MAC filtering.
"""
import subprocess
import time
from real_net import _run
import database as db

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


# ---------- macOS actions ----------
def preferred_networks() -> list:
    out = _run(["networksetup", "-listpreferredwirelessnetworks", "en0"], timeout=8)
    return [l.strip() for l in out.splitlines()[1:] if l.strip()]


def forget_network(ssid: str) -> tuple:
    out = _run(["networksetup", "-removepreferredwirelessnetwork", "en0", ssid], timeout=10)
    if "was not found" in out:
        return False, "not in preferred list (already forgotten or never joined)"
    return True, out or "removed from preferred networks"


def disconnect_wifi() -> tuple:
    out = _run(["networksetup", "-setairportpower", "en0", "off"], timeout=10)
    return True, out or "Wi-Fi turned off"


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
