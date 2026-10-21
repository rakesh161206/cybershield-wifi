"""Risk engine: behavior-based scoring + Zero-Trust levels."""
from typing import Dict, List, Tuple

def calculate_risk(features: Dict) -> Tuple[int, List[str], str]:
    risk = 0
    reasons = []

    auth_failures = int(features.get("auth_failures", 0))
    if auth_failures > 5:
        risk += 20
        reasons.append(f"Repeated authentication failures ({auth_failures})")

    if features.get("unknown_destinations"):
        risk += 20
        reasons.append("Communication with unknown destinations")

    if features.get("port_scan"):
        risk += 30
        reasons.append("Port scanning detected")

    if features.get("traffic_spike"):
        risk += 15
        reasons.append("Sudden traffic volume spike")

    if features.get("request_rate_anomaly"):
        risk += 15
        reasons.append("Abnormal request frequency")

    decoy_hits = int(features.get("decoy_interactions", 0))
    if decoy_hits > 0:
        # Per hit: a device that touches three decoys has said more than one
        # that touches one. Capped with everything else at 100.
        risk += 40 * decoy_hits
        reasons.append(f"Decoy interaction x{decoy_hits} (honeypot touched): +{40 * decoy_hits}")

    if int(features.get("unauthorized_attempts", 0)) > 0:
        risk += 20
        reasons.append("Unauthorized access attempts")

    if features.get("baseline_deviation"):
        risk += 15
        reasons.append("Behaviour deviates from this device's own recorded baseline")

    risk = max(0, min(100, risk))

    if risk <= 30:
        level = "trusted"
    elif risk <= 60:
        level = "suspicious"
    elif risk <= 80:
        level = "high"
    else:
        level = "critical"

    return risk, reasons, level


def trust_from_risk(risk: int) -> int:
    return max(0, 100 - risk)


LEVEL_META = {
    "trusted": {"label": "TRUSTED", "color": "green", "emoji": "🟢"},
    "suspicious": {"label": "SUSPICIOUS", "color": "yellow", "emoji": "🟡"},
    "high": {"label": "HIGH RISK", "color": "orange", "emoji": "🟠"},
    "critical": {"label": "CRITICAL", "color": "red", "emoji": "🔴"},
}

AUTO_ISOLATE_THRESHOLD = 80

# Per-device baseline: how far a device may drift from its own recorded
# normal behaviour before it counts as a deviation. Multipliers, not
# absolutes, so a busy device is not punished for being busy.
BASELINE_FACTORS = {"connections": 2.0, "destinations": 3.0, "port_attempts": 3.0,
                    "request_freq": 2.5, "traffic": 2.5}


def baseline_deviation(current: dict, baseline: dict) -> bool:
    """True when the device has drifted from its own recorded normal profile.

    `current` and `baseline` hold the same keys:
    connections, destinations, port_attempts, request_freq, traffic.
    """
    if not baseline:
        return False
    for key, factor in BASELINE_FACTORS.items():
        cur = float(current.get(key, 0) or 0)
        base = float(baseline.get(key, 0) or 0)
        if cur > max(base * factor, base + 5):
            return True
    return False
