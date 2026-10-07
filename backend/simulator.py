"""Device + traffic simulator (software-only Wi-Fi telemetry)."""

NORMAL_DEVICES = [
    {"id": "DEVICE-001", "name": "Laptop-01", "mac": "AA:BB:CC:11:22:01", "ip": "192.168.1.101"},
    {"id": "DEVICE-002", "name": "Phone-02", "mac": "AA:BB:CC:11:22:02", "ip": "192.168.1.102"},
    {"id": "DEVICE-003", "name": "Tablet-03", "mac": "AA:BB:CC:11:22:03", "ip": "192.168.1.103"},
    {"id": "DEVICE-007", "name": "Laptop-07 (demo target)", "mac": "AA:BB:CC:11:22:07", "ip": "192.168.1.107"},
]

DECOYS = [
    {"id": "FAKE-NAS", "name": "Fake NAS Storage", "endpoint": "/api/decoy/fake-nas", "desc": "SMB-like file share that no legit user was told about"},
    {"id": "FAKE-PRINTER", "name": "Fake Printer", "endpoint": "/api/decoy/fake-printer", "desc": "IPP printer decoy"},
    {"id": "FAKE-ADMIN", "name": "Fake Admin Portal", "endpoint": "/api/decoy/fake-admin", "desc": "Router admin login decoy"},
    {"id": "FAKE-SSH", "name": "Fake SSH Server", "endpoint": "/api/decoy/fake-ssh", "desc": "SSH banner decoy on port 22"},
]

# Zero-Trust authorization matrix
ALLOW_LIST = {
    "DEVICE-001": ["internet", "dns", "approved-services"],
    "DEVICE-002": ["internet", "dns", "approved-services"],
    "DEVICE-003": ["internet", "dns"],
    "DEVICE-007": ["internet", "dns", "approved-services"],
}
DENY_LIST = ["admin-panel", "other-clients", "security-config", "decoys"]


def fresh_device_state(dev: dict) -> dict:
    return {
        "id": dev["id"], "name": dev["name"], "mac": dev["mac"], "ip": dev["ip"],
        "authenticated": 1, "risk": 5 if dev["id"] != "DEVICE-007" else 8,
        "trust": 95 if dev["id"] != "DEVICE-007" else 92,
        "status": "trusted", "auth_failures": 0,
        "decoy_hits": 0, "port_scan": 0, "traffic_spike": 0,
        "unknown_dest": 0, "request_anomaly": 0, "unauthorized": 0,
        "isolated": 0,
    }


def attack_sequence(device_id: str = "DEVICE-007"):
    """Ordered steps shown in demo timeline."""
    return [
        {"type": "recon", "detail": f"{device_id}: scanning 24 ports...", "features": {"port_scan": True}},
        {"type": "traffic", "detail": f"{device_id}: traffic spike 12x baseline", "features": {"traffic_spike": True, "request_rate_anomaly": True}},
        {"type": "c2", "detail": f"{device_id}: connection to unknown external IP 185.220.x.x", "features": {"unknown_destinations": True}},
        {"type": "auth", "detail": f"{device_id}: 7 failed logins to admin panel", "features": {"auth_failures": 7, "unauthorized_attempts": 3}},
        {"type": "decoy", "detail": f"{device_id}: touched FAKE-ADMIN + FAKE-NAS 🍯", "features": {"decoy_interactions": 2}},
    ]
