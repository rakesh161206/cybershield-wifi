"""Attack-versus-network-fault classification.

Separates two explanations for bad connectivity that need different
responses:

  - network_fault: congestion, weak signal, DHCP/DNS or upstream issues.
  - suspected_attack: evil-twin indicators, weak/changed security,
    anomalous environment signals.

Outputs are probabilistic indicators with cited evidence, never
definitive attributions. When both evidence families are present the
verdict is `mixed`.
"""

DISCLAIMER = ("Heuristic classification based on host-visible signals; "
              "treat as triage guidance, not proof of attack or of safety.")


def _num(v):
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def classify(status=None, ai=None, rogue_warnings=None, loss=None, radar=None):
    status = status or {}
    ai = ai or {}
    rogue_warnings = rogue_warnings or []
    loss = loss or {}
    wifi = status.get("wifi") or {}
    risk = status.get("risk") or {}
    outside = set(ai.get("outside_features") or [])

    fault_evidence = []
    attack_evidence = []
    fault_score = 0
    attack_score = 0

    sig = _num(wifi.get("signal_dbm"))
    if sig is not None and sig <= -75:
        fault_score += 2
        fault_evidence.append(f"Weak signal ({wifi.get('signal_dbm')} dBm): drops and slowness are expected at this range.")
    gw = _num(status.get("gateway_ms"))
    if gw is not None and gw >= 100:
        fault_score += 2
        fault_evidence.append(f"High gateway latency ({gw:.0f} ms): points to congestion or a weak router link.")
    lp = _num(loss.get("loss_pct"))
    if lp is not None and lp >= 5:
        fault_score += 2
        fault_evidence.append(f"Packet loss {lp}% to the gateway: retransmissions will feel like slowness, not necessarily an attack.")
    elif lp is not None and lp >= 2:
        fault_score += 1
        fault_evidence.append(f"Mild packet loss ({lp}%) to the gateway.")

    checks = {(c.get("name"), c.get("status")) for c in (status.get("checks") or [])}
    names = {c.get("name"): c for c in (status.get("checks") or [])}
    for key in ("IP / DHCP", "DNS", "Internet"):
        c = names.get(key)
        if c and c.get("status") == "fail" and "Security protocol" not in str(risk.get("reasons")):
            fault_score += 1
            fault_evidence.append(f"{key} check failing ({c.get('detail', '')}).")

    sec = wifi.get("security", "Unknown") if wifi.get("connected") else ""
    slow = _sec_class(sec)
    if wifi.get("connected"):
        if slow == "open":
            attack_score += 3
            attack_evidence.append("Current network is open: all nearby traffic is observable.")
        elif slow == "wep":
            attack_score += 3
            attack_evidence.append("Current network uses broken WEP encryption.")
        elif slow == "wpa":
            attack_score += 2
            attack_evidence.append("Current network uses outdated WPA (v1).")
        elif slow == "unknown":
            attack_score += 1
            attack_evidence.append("Current network encryption could not be verified.")

    for w in rogue_warnings:
        t = w.get("type")
        if t == "security_mismatch":
            attack_score += 3 if w.get("severity") == "high" else 2
            attack_evidence.append(f"Security change on '{w.get('ssid')}': {w.get('detail')}")
        elif t == "possible_twin":
            attack_score += 2
            attack_evidence.append(f"Duplicate AP settings for '{w.get('ssid')}'.")
        elif t == "current_on_weak":
            attack_score += 2
            attack_evidence.append(w.get("detail", ""))
        elif t == "strong_open":
            attack_score += 1
            attack_evidence.append(w.get("detail", ""))

    if ai.get("anomaly"):
        security_outside = outside & {"open_count", "lan_devices", "nearby_count", "dest_diversity", "tcp_connections"}
        if security_outside:
            attack_score += 2
            attack_evidence.append(f"AI anomaly with unusual environment signals ({', '.join(sorted(security_outside))}).")
        else:
            fault_score += 1
            fault_evidence.append("AI anomaly confined to latency/signal features; resembles congestion more than attack behavior.")

    if isinstance(radar, dict):
        avoid = (radar.get("summary") or {}).get("avoid", 0)
        if avoid >= 2:
            attack_score += 1
            attack_evidence.append(f"{avoid} nearby networks score 'avoid'.")

    if attack_score >= 4 and fault_score >= 3:
        verdict = "mixed"
        explanation = ("Both fault signals (latency/loss/signal) and attack indicators "
                       "(security/twin/anomaly) are present. Fix the connection quality first, "
                       "but treat the security findings as unresolved.")
        action = "Move closer to the router or switch to a verified WPA2/WPA3 network; do not enter credentials on the current one until the security indicators are explained."
        confidence = 0.65
    elif attack_score >= 3:
        verdict = "suspected_attack"
        explanation = "Security indicators outweigh pure fault signals."
        action = "Switch to a verified network, use a VPN, disable auto-join for the flagged SSID, and block it after confirmation."
        confidence = min(0.85, 0.5 + 0.1 * (attack_score - fault_score))
    elif fault_score >= 2:
        verdict = "network_fault"
        explanation = "Latency, loss, or signal evidence explains the symptoms without attack indicators."
        action = "Move closer to the access point, reduce congestion (pause bulk transfers), restart the router if loss persists."
        confidence = min(0.85, 0.5 + 0.1 * (fault_score - attack_score))
    elif (risk.get("score") or 0) <= 30 and not ai.get("anomaly"):
        verdict = "healthy"
        explanation = "No significant fault or attack evidence."
        action = "No action needed; keep auto-join limited to known networks."
        confidence = 0.6
    else:
        verdict = "degraded_unknown"
        explanation = "Some degradation without a clear fault or attack pattern."
        action = "Re-scan in a minute; if it persists, compare the incident timeline before/after."
        confidence = 0.45

    return {"verdict": verdict, "confidence": round(confidence, 2),
            "fault_score": fault_score, "attack_score": attack_score,
            "fault_evidence": fault_evidence, "attack_evidence": attack_evidence,
            "explanation": explanation, "recommended_action": action,
            "note": DISCLAIMER}


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
