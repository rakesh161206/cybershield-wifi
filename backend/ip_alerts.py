"""Real-time alerting for IP-level findings.

Alerts are *indicators surfaced for the operator*, never autonomous actions.
The host cannot block an external address, so the recommended action is
always something a person can do: stop the app, watch the address, add it
to the watchlist, verify with the network owner.

Every alert cites the exact observations that produced it and carries a
dedup cooldown so one persistent condition yields one alert, not hundreds.
"""
import time
from datetime import datetime, timezone

try:
    import database as db
    import ip_purpose
except ImportError:  # pragma: no cover - import-style fallback
    from backend import database as db
    from backend import ip_purpose

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

DISCLAIMER = ("Heuristic indicator based on host-visible signals; "
              "treat as triage guidance, not proof of malicious activity.")


def _now_iso():
    return datetime.now(timezone.utc).isoformat()


def _recent(ip, type_, within):
    try:
        return db.recent_alert(ip, type_, within_s=within)
    except Exception:
        return None


def _raise(ip, type_, severity, title, evidence, action, within=900):
    """Create an alert unless the same condition was already reported."""
    if _recent(ip, type_, within):
        return None
    ok = db.add_ip_alert(ip, type_, severity, title, evidence, action)
    if ok:
        db.log_event(ip, f"ip-alert-{type_}",
                     f"{severity.upper()}: {title} — {evidence}", 0)
    return ok


def evaluate(assessed, watchlist=None, allow_alerts=True):
    """Turn assessed peers into alerts. `assessed` comes from ip_purpose.assess."""
    raised = []
    watch = {w["ip"]: w for w in (watchlist or [])}
    for a in assessed or []:
        ip = a.get("ip")
        if not ip:
            continue
        purpose = a.get("purpose")
        score = a.get("score", 0)
        ports = a.get("ports") or []
        actor = a.get("actor_class", "unknown")
        rep = (a.get("intel") or {}).get("reputation") or {}
        scope = (a.get("intel") or {}).get("scope")
        # Only a remote peer can be scanned or abused. Local addresses
        # (loopback, LAN, gateway) speak many ports by nature.
        remote = scope in ("public", "cgnat") or (not scope and a.get("purpose")
                                                  not in ("loopback", "lan-peer", "gateway"))

        # 1. Tor exit
        if purpose == "tor-exit":
            raised.append(_raise(
                ip, "tor_exit_contact", "high",
                "Traffic reached a Tor exit node",
                f"Address is listed as a Tor exit node and this host connected to it "
                f"on port {', '.join(str(p) for p in ports) or 'unknown'}. "
                f"Local program: {actor}.",
                "Confirm the program was expected to use Tor. If not, stop it and "
                "check what it was reaching.",
                within=1800))

        # 2. Bulletproof hosting
        if purpose == "bulletproof-hosting":
            raised.append(_raise(
                ip, "bulletproof_host", "critical",
                "Connection to a bulletproof hosting provider",
                f"Address belongs to hosting advertised as tolerant of abuse. "
                f"Connected on port {', '.join(str(p) for p in ports) or 'unknown'}.",
                "Treat as hostile until proven otherwise: terminate the connection, "
                "block the address in the router, and review what initiated it.",
                within=1800))

        # 3. Malware / botnet feed hit
        for lst in rep.get("lists") or []:
            if (lst.get("type") or "").lower() == "malware":
                raised.append(_raise(
                    ip, "reputation_malware", "high",
                    "Address matched a malware or botnet feed",
                    f"Matched list '{lst.get('name')}'. Local program: {actor}.",
                    "Disconnect, block at the router, and check the host for malware.",
                    within=3600))
                break

        # 4. Scanning shape
        if remote and len(set(ports)) >= 5:
            raised.append(_raise(
                ip, "scan_shape", "high",
                "One address contacted across many ports",
                f"{len(set(ports))} distinct ports contacted on {ip}: "
                f"{', '.join(str(p) for p in sorted(set(ports))[:20])}. "
                f"Local program: {actor}.",
                "This is a scanning shape. Identify the program and stop it.",
                within=1800))

        # 5. Unexpected programme talking to hosting infrastructure
        if purpose in ip_purpose.HIGH_RISK_PURPOSES and \
                actor in ip_purpose.UNKNOWN_ACTORS:
            raised.append(_raise(
                ip, "unexpected_hosting", "medium",
                "Unrecognised program contacted hosting infrastructure",
                f"Program '{actor}' connected to a {purpose} address on port "
                f"{', '.join(str(p) for p in ports) or 'unknown'}. "
                f"{a.get('purpose_evidence', [''])[0] if a.get('purpose_evidence') else ''}",
                "Confirm the program is expected to do this. Background apps talking "
                "to rented infrastructure is the classic pattern to rule out.",
                within=3600))

        # 6. Beaconing shape
        reasons_text = " ".join(a.get("reasons") or [])
        if "beaconing shape" in reasons_text:
            raised.append(_raise(
                ip, "beaconing", "high",
                "Regular interval connection pattern",
                reasons_text,
                "A fixed-interval connection to the same address is a command-and-control "
                "shape. Verify the destination; if unknown, isolate the host.",
                within=3600))

        # 7. Watchlisted address contacted
        if ip in watch:
            raised.append(_raise(
                ip, "watchlist_hit", "medium",
                "Watched address contacted",
                f"{ip} is on your watchlist ({watch[ip].get('note') or 'no note'}) "
                f"and this host connected to it.",
                "Review as intended — or clear the watchlist entry if it is expected.",
                within=1800))

        # 8. Newly seen external peer
        if remote and a.get("hits", 0) <= 1 and \
                (a.get("intel") or {}).get("scope") == "public":
            raised.append(_raise(
                ip, "new_external_ip", "info",
                "First contact with a new external address",
                f"First seen at {a.get('first_seen') or _now_iso()} on port "
                f"{', '.join(str(p) for p in ports) or 'unknown'}. "
                f"Purpose: {a.get('purpose_label', {}).get('label', 'unknown')}. "
                f"Score {score}/100.",
                "Usually normal browsing. Keep it if the destination is expected.",
                within=3600))

    return [r for r in raised if r]


def active(limit=100):
    """Current alerts, newest first, unacknowledged first."""
    rows = db.get_ip_alerts(limit=limit)
    for r in rows:
        r["note"] = DISCLAIMER
    rows.sort(key=lambda r: (r.get("ack", 0), SEV_ORDER.get(r.get("severity", "info"), 9),
                              r.get("ts", "")), reverse=False)
    return rows


def counts():
    rows = db.get_ip_alerts(limit=500)
    out = {"total": len(rows), "unacked": 0, "critical": 0, "high": 0,
           "medium": 0, "low": 0, "info": 0}
    for r in rows:
        if not r.get("ack"):
            out["unacked"] += 1
        sev = r.get("severity", "info")
        if sev in out:
            out[sev] += 1
    return out
