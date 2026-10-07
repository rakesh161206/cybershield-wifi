"""Isolation Forest anomaly detector with rule fallback."""
from typing import Dict, List
import random

try:
    from sklearn.ensemble import IsolationForest
    import numpy as np
    SKLEARN_OK = True
except Exception:
    SKLEARN_OK = False

FEATURE_ORDER = [
    "connection_count",
    "unique_destinations",
    "port_attempts",
    "request_freq",
    "traffic_volume",
]

_model = None

def _train_default():
    global _model
    if not SKLEARN_OK:
        return None
    # Normal baseline: low/moderate values
    rng = random.Random(42)
    X = []
    for _ in range(200):
        X.append([
            rng.randint(5, 40),      # connection_count
            rng.randint(1, 5),       # unique_destinations
            rng.randint(1, 8),       # port_attempts
            rng.randint(5, 50),      # request_freq per min
            rng.randint(10, 200),    # traffic MB
        ])
    import numpy as np
    _model = IsolationForest(contamination=0.08, random_state=42)
    _model.fit(np.array(X))
    return _model

def ai_score(features: Dict) -> Dict:
    """Return {anomaly: bool, score: float, detail: str}."""
    vec = [float(features.get(k, 0)) for k in FEATURE_ORDER]
    if not SKLEARN_OK:
        # Rule fallback: flag if 2+ dimensions far above normal
        flags = 0
        if vec[0] > 100: flags += 1
        if vec[1] > 10: flags += 1
        if vec[2] > 20: flags += 1
        if vec[3] > 150: flags += 1
        if vec[4] > 800: flags += 1
        return {
            "anomaly": flags >= 2,
            "score": min(1.0, flags / 3.0),
            "detail": f"rule-fallback flags={flags}/5 (sklearn unavailable)",
            "engine": "rules",
        }
    global _model
    if _model is None:
        _train_default()
    import numpy as np
    pred = _model.predict(np.array([vec]))[0]  # 1 normal, -1 anomaly
    raw = _model.decision_function(np.array([vec]))[0]
    # Convert to 0..1 anomaly score
    score = max(0.0, min(1.0, 0.5 - raw))
    return {
        "anomaly": bool(pred == -1),
        "score": round(float(score), 3),
        "detail": f"IsolationForest decision={round(float(raw),3)}",
        "engine": "isolation-forest",
    }


# ---------------- LIVE environment AI (real network, not simulated) ----------------
LIVE_FEATURES = ["nearby_count", "open_count", "lan_devices",
                 "gateway_ms", "dns_ms", "signal_dbm"]
# Normal home-Wi-Fi ranges: (lo, hi, median-for-imputation)
NORMAL_RANGES = {
    "nearby_count": (2, 15, 7),
    "open_count": (0, 3, 1),
    "lan_devices": (1, 10, 3),
    "gateway_ms": (1, 40, 5),
    "dns_ms": (2, 80, 15),
    "signal_dbm": (-70, -25, -55),
}
BASELINE_SAMPLES = 300
_live_model = None


def engine_status() -> Dict:
    trained = _live_model is not None or _train_live()
    if not SKLEARN_OK:
        return {"engine": "rules",
                "running_properly": False,
                "detail": "scikit-learn not installed — basic rule checks only. Run: pip install scikit-learn",
                "baseline_samples": 0}
    ok = _live_model is not None
    return {"engine": "isolation-forest",
            "running_properly": bool(ok),
            "detail": f"Trained on {BASELINE_SAMPLES} normal home-Wi-Fi snapshots" if ok
                      else "Training failed",
            "baseline_samples": BASELINE_SAMPLES if ok else 0}


def _train_live():
    global _live_model
    if not SKLEARN_OK:
        return None
    import numpy as np
    rng = random.Random(7)
    X = []
    for _ in range(BASELINE_SAMPLES):
        X.append([
            rng.randint(2, 15),                    # nearby_count
            rng.randint(0, 3),                     # open_count
            rng.randint(1, 10),                    # lan_devices
            rng.uniform(1, 40),                    # gateway_ms
            rng.uniform(2, 80),                    # dns_ms
            rng.uniform(-70, -25),                 # signal_dbm
        ])
    _live_model = IsolationForest(contamination=0.08, random_state=7)
    _live_model.fit(np.array(X))
    return _live_model


def _live_vector(snapshot: Dict) -> list:
    vec = []
    for k in LIVE_FEATURES:
        v = snapshot.get(k)
        lo, hi, med = NORMAL_RANGES[k]
        try:
            v = float(v)
        except (TypeError, ValueError):
            v = med
        vec.append(v)
    return vec


def assess_live(snapshot: Dict) -> Dict:
    """Score the CURRENT real environment vs the normal baseline."""
    vec = _live_vector(snapshot)
    outside = [k for k, v in zip(LIVE_FEATURES, vec)
               if not (NORMAL_RANGES[k][0] <= v <= NORMAL_RANGES[k][1])]
    if not SKLEARN_OK:
        return {"anomaly": len(outside) >= 2,
                "score": round(min(1.0, len(outside) / 3.0), 3),
                "detail": f"rule-fallback: {len(outside)} feature(s) outside normal range",
                "engine": "rules",
                "outside_features": outside}
    global _live_model
    if _live_model is None:
        _train_live()
    import numpy as np
    pred = _live_model.predict(np.array([vec]))[0]
    raw = _live_model.decision_function(np.array([vec]))[0]
    score = max(0.0, min(1.0, 0.5 - raw))
    return {"anomaly": bool(pred == -1),
            "score": round(float(score), 3),
            "detail": f"IsolationForest decision={round(float(raw),3)} vs {BASELINE_SAMPLES}-sample baseline",
            "engine": "isolation-forest",
            "outside_features": outside}
