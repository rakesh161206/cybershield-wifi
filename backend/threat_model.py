"""Per-network threat model (educational / defensive).

For each visible Wi-Fi network we produce:
  proximity      — rough distance zone from RSSI (NOT a precise location;
                   that needs measurements from 3+ points)
  recommendation — connect / caution / avoid + reasons
  threats        — what attacks that network type is exposed to, described
                   as defender-facing awareness (how it works at a high
                   level, what parameters an attacker would need, how to
                   stay safe). No operational tooling/commands.
"""
from real_net import PUBLIC_HINTS

# ---------------- threat catalog (defensive awareness) ----------------
OPEN_THREATS = [
    {"name": "Passive traffic sniffing", "severity": "high",
     "how": ["Radio tunes to the same channel as the open network",
             "Unencrypted frames (HTTP, DNS, metadata) are readable by anyone in range"],
     "params": ["Attacker radio in range", "Same channel", "No encryption to break"],
     "defense": ["Use a VPN", "Only visit HTTPS sites", "Avoid logins/banking"]},
    {"name": "Evil-twin + fake login page", "severity": "high",
     "how": ["Attacker clones the SSID with a stronger signal",
             "Victims auto-join the twin and are shown a fake captive-portal login",
             "Typed credentials go straight to the attacker"],
     "params": ["Same SSID", "Stronger signal than the real AP", "Fake login page"],
     "defense": ["Confirm exact SSID with staff", "Disable auto-join", "Never enter passwords on portal pages you did not expect"]},
    {"name": "Man-in-the-middle (ARP spoofing)", "severity": "medium",
     "how": ["Attacker poisons ARP tables so traffic flows through them",
             "Unencrypted sessions can be read or modified in transit"],
     "params": ["Victim + gateway IP on same LAN", "ARP replies accepted by clients"],
     "defense": ["VPN", "HTTPS everywhere", "Prefer mobile hotspot for sensitive tasks"]},
]

WEP_THREATS = [
    {"name": "WEP key recovery", "severity": "high",
     "how": ["Attacker collects a large number of encrypted frames (IVs)",
             "Statistical analysis recovers the static WEP key",
             "Network then behaves like an open network (see above)"],
     "params": ["Network BSSID + channel", "Enough passing traffic to collect frames"],
     "defense": ["Ask the owner to switch the router to WPA2/WPA3", "Do not rely on WEP at all"]},
]

WPA_THREATS = [
    {"name": "Handshake capture + offline guessing", "severity": "medium",
     "how": ["Attacker records the WPA handshake when a device connects",
             "Weak passphrases are guessed offline with wordlists"],
     "params": ["Handshake capture", "Weak/short passphrase", "Wordlist"],
     "defense": ["Use a long random passphrase", "Upgrade router to WPA2/WPA3"]},
]

WPA2_THREATS = [
    {"name": "PMKID / handshake capture + offline guessing", "severity": "medium",
     "how": ["Attacker grabs the PMKID or 4-way handshake (sometimes without any client)",
             "Weak passphrases are guessed offline — the AP itself is never touched again"],
     "params": ["AP BSSID + channel", "Captured PMKID/handshake", "Weak passphrase + wordlist"],
     "defense": ["Long random Wi-Fi password", "WPA3 where available", "Watch for unknown deauth disconnects"]},
    {"name": "Evil twin (credential + traffic capture)", "severity": "medium",
     "how": ["Twin AP copies the SSID; devices may join it after a forced disconnect",
             "Attacker relays or observes the session"],
     "params": ["Same SSID", "Victim disconnect from real AP", "User ignores certificate/name warnings"],
     "defense": ["Verify SSID with staff on public networks", "Disable auto-join", "Use VPN"]},
    {"name": "Forced disconnect (deauth) nuisance", "severity": "low",
     "how": ["Unprotected management frames let anyone spoof 'disconnect' messages",
             "Devices drop and reconnect — mostly an annoyance, sometimes step one of the above"],
     "params": ["Same channel", "Router without protected management frames (802.11w)"],
     "defense": ["Enable 802.11w/PMF on the router if offered", "Nothing sensitive depends on staying connected"]},
]

WPA3_THREATS = [
    {"name": "Downgrade to WPA2 (transition mode)", "severity": "low",
     "how": ["On WPA3-transition networks an attacker advertises WPA2-only",
             "Clients fall back to WPA2, re-exposing WPA2-class attacks"],
     "params": ["Transition-mode AP", "Client accepts the downgrade"],
     "defense": ["Use WPA3-only mode on your own router", "Keep devices updated"]},
    {"name": "Side-channel research attacks (Dragonblood class)", "severity": "low",
     "how": ["Academic timing/power analysis against early SAE implementations",
             "Patched on updated devices; no mass exploitation seen"],
     "params": ["Old unpatched client/AP firmware", "Physical proximity + long observation"],
     "defense": ["Keep router + phone/laptop firmware updated"]},
]

UNKNOWN_THREATS = [
    {"name": "Unverified encryption", "severity": "medium",
     "how": ["Security type could not be read — treat as untrusted",
             "Same risks as open networks until proven otherwise"],
     "params": ["Unknown AP configuration"],
     "defense": ["Verify with the network owner", "Use VPN + HTTPS"]},
]


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


CATALOG = {"open": OPEN_THREATS, "wep": WEP_THREATS, "wpa": WPA_THREATS,
           "wpa2": WPA2_THREATS, "wpa3": WPA3_THREATS, "unknown": UNKNOWN_THREATS}


def proximity(dbm) -> dict:
    if dbm is None:
        return {"zone": "unknown", "detail": "No signal reading"}
    if dbm >= -50:
        return {"zone": "same room", "detail": f"{dbm} dBm — likely the same room"}
    if dbm >= -65:
        return {"zone": "nearby", "detail": f"{dbm} dBm — nearby (next room / close)"}
    if dbm >= -80:
        return {"zone": "far", "detail": f"{dbm} dBm — far (same building)"}
    return {"zone": "edge of range", "detail": f"{dbm} dBm — barely reachable"}


def recommend(net: dict, ssid_variants: dict) -> dict:
    """verdict: connect | caution | avoid"""
    sec = _sec_class(net.get("security", ""))
    ssid = (net.get("ssid") or "")
    low = ssid.lower()
    reasons = []
    cls = sec
    if cls == "open":
        verdict = "avoid"
        reasons.append("No encryption — anyone nearby can read unencrypted traffic")
    elif cls == "wep":
        verdict = "avoid"
        reasons.append("WEP encryption is broken and quickly recoverable")
    elif cls == "wpa":
        verdict = "avoid"
        reasons.append("WPA (v1) is outdated with known weaknesses")
    elif cls == "wpa3":
        verdict = "connect"
        reasons.append("Strong WPA3 encryption")
    elif cls == "wpa2":
        verdict = "connect"
        reasons.append("Good WPA2 encryption")
    else:
        verdict = "caution"
        reasons.append("Encryption type could not be verified")
    if verdict == "connect":
        if any(h in low for h in PUBLIC_HINTS):
            verdict = "caution"
            reasons.append("Looks like a public/shared hotspot — verify the exact name")
        variants = ssid_variants.get(ssid, set())
        if len(variants) > 1:
            verdict = "caution"
            reasons.append("Same name seen with different settings — possible twin, verify with owner")
        if (net.get("signal_dbm") or 0) < -78:
            reasons.append("Very weak signal — connection may be unstable")
    if net.get("is_current") and verdict == "connect":
        reasons.append("This is the network you are on now")
    return {"verdict": verdict, "reasons": reasons}


def assess(networks: list) -> list:
    variants = {}
    for n in networks:
        if n.get("ssid"):
            variants.setdefault(n["ssid"], set()).add(
                (n.get("channel", ""), n.get("security", "")))
    out = []
    for n in networks:
        cls = _sec_class(n.get("security", ""))
        out.append({**n,
                    "proximity": proximity(n.get("signal_dbm")),
                    "recommendation": recommend(n, variants),
                    "threats": CATALOG[cls]})
    return out
