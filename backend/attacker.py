"""Virtual attacker for stage demos (100% simulated, zero real packets).

Persona: ROGUE-TWIN-01 — an attacker sitting in the same hall with a
laptop radio, running an evil-twin of a real nearby network.

Kill chain (auto-advances by elapsed time):
  recon   (t+0s)  attacker fingerprints the target SSID/channel
  twin    (t+10s) rogue AP appears: same SSID, OPEN, stronger signal
  lure    (t+25s) victims nudged onto the twin (fake deauth + auto-join)
  capture (t+40s) fake portal harvests credentials -> CRITICAL

The twin is injected into /api/real/radar as a virtual network while
active, so the real scoring + block flow reacts to it. Blocking the
twin neutralizes the scenario (it is virtual — nothing is forgotten
on the Mac).
"""
import time

PROFILE = {
    "id": "ROGUE-TWIN-01",
    "name": "Evil-Twin Attacker",
    "operator": "External — someone in the same hall with a laptop radio",
    "capabilities": ["Monitor-mode radio on 2.4/5 GHz", "SSID clone + fake captive portal kit",
                     "Deauth nudges", "Credential harvester"],
    "motive": "Steal logins and session cookies from auto-joining devices",
}

STEPS = [
    {"key": "recon", "at": 0, "title": "Recon",
     "detail": "Attacker fingerprints the target: SSID, channel, security, client MACs."},
    {"key": "twin", "at": 10, "title": "Twin online",
     "detail": "Rogue AP up with the SAME name, OPEN auth and a stronger signal."},
    {"key": "lure", "at": 25, "title": "Lure",
     "detail": "Victims nudged off the real AP; phones auto-join the louder twin."},
    {"key": "capture", "at": 40, "title": "Capture",
     "detail": "Fake login portal harvests credentials. Treat as CRITICAL — block it."},
]

_state = {"active": False, "target": "", "started_at": 0, "blocked": False}


def start(target_ssid: str) -> dict:
    _state.update({"active": True, "target": target_ssid,
                   "started_at": time.time(), "blocked": False})
    return status()


def stop(reason: str = "neutralized") -> dict:
    _state.update({"active": False, "blocked": (reason == "blocked")})
    return {"ok": True, "reason": reason}


def elapsed() -> float:
    return time.time() - _state["started_at"] if _state["active"] else 0


def status() -> dict:
    if not _state["active"]:
        return {"active": False, "profile": PROFILE}
    e = elapsed()
    done = [s for s in STEPS if e >= s["at"]]
    nxt = next((s for s in STEPS if e < s["at"]), None)
    return {"active": True, "profile": PROFILE, "target": _state["target"],
            "elapsed_s": round(e, 1), "steps_done": done, "timeline": STEPS,
            "next_up": nxt, "critical": any(s["key"] == "capture" for s in done)}


def virtual_network(real_nets: list) -> dict | None:
    """Rogue twin of the target (or strongest real net). None before `twin` step."""
    if not _state["active"]:
        return None
    if elapsed() < 10:
        return None  # still in recon — nothing visible yet
    target = _state["target"]
    real = next((n for n in real_nets if n.get("ssid") == target), None)
    if real is None:
        real = max(real_nets, key=lambda n: n.get("signal_dbm") or -999, default=None)
    if real is None:
        return None
    sig = min(-28, (real.get("signal_dbm") or -60) + 15)  # louder than the real one
    return {"ssid": real.get("ssid") or target or "Free_WiFi",
            "signal_dbm": sig, "channel": real.get("channel", ""),
            "band": real.get("band", ""), "phy": real.get("phy", ""),
            "security": "Open", "is_current": False, "virtual": True,
            "attacker_id": PROFILE["id"]}
