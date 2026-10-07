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
        risk += 40
        reasons.append(f"Decoy interaction x{decoy_hits} (honeypot touched)")

    if int(features.get("unauthorized_attempts", 0)) > 0:
        risk += 20
        reasons.append("Unauthorized access attempts")

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
