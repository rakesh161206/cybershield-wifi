"""Rogue access-point change warnings (risk indicators, not proof).

Compares the current scan against previously observed SSID fingerprints
(security class + channel) stored in SQLite. Any difference is reported
as an indicator that deserves attention, never as a confirmed attack:
identical SSIDs with different settings also occur after legitimate
router replacements, firmware changes, or band-steering quirks.
"""

INDICATOR_NOTE = ("Risk indicator only: confirm with the network owner "
                  "before treating any entry as malicious.")

SEV_RANK = {"high": 0, "medium": 1, "low": 2}


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


def detect(nearby, current_ssid=""):
    """Return a list of warning dicts for this scan. Never raises."""
    try:
        from backend import database as db
    except ImportError:
        import database as db
    try:
        nets = [n for n in (nearby or []) if n.get("ssid")]
    except Exception:
        return []
    try:
        history = {h["ssid"]: h for h in db.get_network_history()}
    except Exception:
        history = {}

    variants = {}
    for n in nets:
        variants.setdefault(n.get("ssid"), set()).add(
            (str(n.get("channel", "")), _sec_class(n.get("security", ""))))
    warned_variant = set()
    warnings = []

    for n in nets:
        ssid = n.get("ssid") or ""
        sec = n.get("security", "") or "Unknown"
        cls = _sec_class(sec)
        sig = n.get("signal_dbm")
        is_cur = bool(current_ssid and ssid == current_ssid)

        if len(variants.get(ssid, set())) > 1 and ssid not in warned_variant:
            warned_variant.add(ssid)
            warnings.append({
                "type": "possible_twin",
                "ssid": ssid, "severity": "medium",
                "detail": (f"'{ssid}' appears with {len(variants[ssid])} different "
                           "channel/security combinations in this scan."),
                "evidence": sorted([f"ch {c or '?'} / {s}" for c, s in variants[ssid]]),
                "recommendation": "Confirm the legitimate AP settings with the owner; "
                                  "avoid joining until the duplicate is explained.",
                "note": INDICATOR_NOTE,
            })
        prev = history.get(ssid)
        if prev is None:
            if not is_cur:
                warnings.append({
                    "type": "new_network",
                    "ssid": ssid, "severity": "low",
                    "detail": f"'{ssid}' was not seen in earlier scans.",
                    "evidence": [f"security {sec}", f"signal {sig} dBm" if sig is not None else "signal unknown"],
                    "recommendation": "Treat first sightings as unverified; check the name with staff on public networks.",
                    "note": INDICATOR_NOTE,
                })
        else:
            prev_cls = _sec_class(prev.get("security", ""))
            if prev_cls != cls:
                warnings.append({
                    "type": "security_mismatch",
                    "ssid": ssid, "severity": "high" if is_cur or cls == "open" else "medium",
                    "detail": (f"'{ssid}' changed security from "
                               f"{prev.get('security') or prev_cls} to {sec}."),
                    "evidence": [f"previously: {prev.get('security') or prev_cls}",
                                 f"now: {sec}",
                                 "current network" if is_cur else "nearby network"],
                    "recommendation": ("Stop using it and verify with the owner; a downgrade "
                                       "to Open/WEP on a known name is the classic evil-twin pattern."),
                    "note": INDICATOR_NOTE,
                })
        if is_cur and cls in ("open", "wep", "wpa", "unknown"):
            warnings.append({
                "type": "current_on_weak",
                "ssid": ssid, "severity": "high" if cls in ("open", "wep") else "medium",
                "detail": f"You are connected to '{ssid}' using {sec}.",
                "evidence": [f"security {sec}"],
                "recommendation": "Prefer a WPA2/WPA3 network; use a VPN and avoid logins on this connection.",
                "note": INDICATOR_NOTE,
            })
        if cls == "open" and isinstance(sig, (int, float)) and sig >= -60 and not is_cur:
            warnings.append({
                "type": "strong_open",
                "ssid": ssid, "severity": "medium",
                "detail": f"Strong open network '{ssid}' ({sig} dBm) nearby.",
                "evidence": [f"signal {sig} dBm", "no encryption"],
                "recommendation": "Do not join without verifying the operator; strong open signals attract auto-joins.",
                "note": INDICATOR_NOTE,
            })

    warnings.sort(key=lambda w: (SEV_RANK.get(w["severity"], 9), w["ssid"]))
    return warnings[:20]
