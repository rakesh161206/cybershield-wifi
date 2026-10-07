# 🔐 CyberShield Wi-Fi — AI-Powered Zero-Trust Wi-Fi Security

> A Wi-Fi device is not permanently trusted just because it authenticated.

Software-only prototype. Simulates Wi-Fi device telemetry + decoy network, evaluates risk continuously, auto-isolates malicious devices.

## Four pillars
Authenticate → Authorize → Detect → Respond

## Quick run (npm)
```bash
cd cybershield-wifi
npm install
npm start
# laptop: http://127.0.0.1:8000
# phone (same Wi-Fi): http://<your-mac-ip>:8000  (shown at the top of the page as "📱 Phone view")
# dev with reload: npm run dev
```
The page is responsive — tables collapse into cards under 640px and radar blips get bigger touch targets.

## Quick run (python only)
```bash
cd cybershield-wifi/backend
pip install -r requirements.txt
uvicorn main:app --reload --port 8000
# open http://127.0.0.1:8000
```

## Demo (2–3 min)
1. Show dashboard: all TRUSTED, trust ~92.
2. Click **SIMULATE WI-FI ATTACK** (target DEVICE-007).
3. Watch timeline: port scan → traffic spike → unknown IP → auth failures → 🍯 decoy touch.
4. Risk → 90+/100  CRITICAL → banner `AUTOMATICALLY ISOLATED` + incident with reasons + actions.
5. Click Restore, or show manual Isolate.

## API (simulated Zero-Trust demo)- `GET /api/devices /api/stats /api/events /api/incidents /api/decoys`
- `POST /api/simulate/attack {"device_id":"DEVICE-007"}`
- `POST /api/simulate/normal`
- `POST /api/device/{id}/allow | /isolate`
- `GET /api/decoy/{decoy_id}?device_id=DEVICE-007` (touching a decoy logs a high-confidence signal)

## API (live — your real Wi-Fi, macOS)
- `GET /api/real/status` — current SSID, security, signal, IP/gateway/DNS, 7 protocol checks, risk 0–100 + verdict + recommendations
- `GET /api/real/networks` — nearby available networks with signal + security (open ones flagged)
- `GET /api/real/devices?mode=fast` — devices on your LAN via ARP (instant)
- `POST /api/real/scan` — deep ping-sweep of your /24 (~10s)
- `GET /api/real/radar` — nearby networks + proximity zone + connect verdict + threat model (powers the 📡 WI-FI RADAR popup)

## Risk engine
auth_failures>5 +20 · unknown_dest +20 · port_scan +30 · traffic_spike +15 · request_anomaly +15 · decoy_hit +40 · unauthorized +20. Cap 100. 0–30 trusted, 31–60 suspicious, 61–80 high, 81–100 critical. Auto-isolate >80.

## AI
IsolationForest on [connections, unique_dests, port_attempts, request_freq, traffic]. Falls back to rules if sklearn missing. Decoy signal always counts (high confidence even if ML misses).

