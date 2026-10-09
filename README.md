# CyberShield Wi-Fi: Zero-Trust Wireless Security with Rule-Based Risk Scoring and Anomaly Detection

## Abstract

CyberShield Wi-Fi is a host-based wireless security system that applies the Zero-Trust principle "connected does not imply trusted" to Wi-Fi networks. It continuously collects live link state, nearby network advertisements, LAN membership, latency signals, and packet/flow telemetry on the host, scores each network with a deterministic risk model, flags rogue access-point indicators, classifies degradation as fault or suspected attack, corroborates the environment with an Isolation Forest anomaly detector, and enforces an ask-first blocking policy. Packet evidence is restricted to headers and flow counters, with bounded, auto-expiring captures. The system consists of a FastAPI backend, a SQLite persistence layer, and a single-page dashboard. This document describes the threat model, scoring methodology, detection method, enforcement semantics, API surface, and reproduction steps.

## 1. Problem Statement

Standard Wi-Fi clients trust a network after authentication and rarely re-evaluate that decision. This exposes users to open networks, evil-twin access points, weak or legacy encryption (WEP, WPA), downgrade attacks, passive sniffing, and ARP-spoofing on shared LANs. CyberShield addresses this by separating authentication from authorization: every visible network and the current connection are re-scored on each scan, with reasons, recommended actions, and per-threat defensive guidance.

## 2. System Architecture

```
macOS collectors (system_profiler, networksetup, ipconfig, arp, ping, netstat, tcpdump*)
        |
        v
real_net.py (link state, nearby networks, IP/gateway/DNS, LAN census)
packet_monitor.py (gateway loss probe, flow metadata, bounded PCAP capture)
        |
        +---> policy.py (network scoring, verdicts, block/allow enforcement)
        +---> threat_model.py (proximity estimation, per-network threat catalog)
        +---> rogue.py (SSID fingerprint history, change warnings as indicators)
        +---> diagnosis.py (attack-versus-fault classification with evidence)
        +---> ai_detector.py (Isolation Forest over environment + packet snapshot)
        |
        v
FastAPI (backend/main.py) + SQLite (backend/database.py)
        |
        v
Single-page dashboard (frontend/index.html)
```

* tcpdump is optional. All loss, flow, scoring, and AI features work without it.

Components:

- `backend/real_net.py`: live collectors. Wi-Fi link (SSID, BSSID, channel, band, PHY mode, rate, security, RSSI/noise), nearby networks, IP/gateway/DNS, gateway/DNS latency, captive-portal and TLS checks, LAN device census via ARP (fast) and ping sweep (full). All collectors are best-effort with graceful degradation and short TTL caches.
- `backend/packet_monitor.py`: gateway loss/latency probes (cached ICMP bursts), flow metadata from socket and interface counters (TCP connections, destination diversity, packet rate, retransmission counters), and bounded header-truncated tcpdump captures with automatic expiry. Headers and counters only, never payloads.
- `backend/policy.py`: deterministic network scoring and macOS enforcement (`networksetup` forget, allowlist, Wi-Fi power off).
- `backend/threat_model.py`: RSSI-to-proximity mapping and a defensive threat catalog keyed by security class.
- `backend/rogue.py`: per-SSID fingerprint history with warnings for new networks, security mismatches, duplicate channel/security variants, and strong open signals. Every warning is labeled a risk indicator, not proof.
- `backend/diagnosis.py`: attack-versus-fault classifier combining signal quality, loss/latency, security posture, rogue warnings, AI assessment, and radar verdicts into healthy, network_fault, suspected_attack, mixed, or degraded_unknown, with cited evidence and a recommended action.
- `backend/ai_detector.py`: two Isolation Forest models (device-behavior corroboration and live-environment assessment) with a rule-based fallback when scikit-learn is unavailable.
- `backend/risk_engine.py`: behavior-based device risk function and trust mapping.
- `backend/database.py`: SQLite persistence for devices, events, incidents, decoy hits, block/allow lists, and flagged LAN devices.
- `backend/simulator.py`: static fixtures (normal devices, decoys, authorization matrix) used to seed the device table.
- `frontend/index.html`: dashboard with live connection panel, signal radar, per-network detail, LAN table, and AI panel.

## 3. Threat Model

The system models defender-visible risks per advertised network. For each network it reports a proximity zone estimated from RSSI, a connect/caution/avoid verdict with reasons, and a list of applicable threats. Each threat entry contains a high-level mechanism description, the parameters an attacker would require, and mitigation guidance. No offensive tooling is included.

Threat coverage by security class:

| Class | Threats modeled |
|---|---|
| Open | Passive sniffing; evil-twin with fake captive portal; ARP-spoofing man-in-the-middle |
| WEP | Static key recovery via IV collection |
| WPA | Handshake capture with offline passphrase guessing |
| WPA2 | PMKID/handshake capture with offline guessing; evil twin; forced-disconnect nuisance via unprotected management frames |
| WPA3 | Transition-mode downgrade to WPA2; Dragonblood-class side channels on unpatched implementations |
| Unknown | Treated as untrusted; same precautions as open networks |

Proximity is a coarse RSSI heuristic (same room / nearby / far / edge of range), not a location measurement.

### 3.1 Rogue access-point indicators

`backend/rogue.py` maintains a per-SSID observation history (security class, channel, signal, first/last seen) and reports four warning types on each scan: new never-before-seen networks, known SSIDs whose security class changed, identical SSIDs with divergent channel/security pairs in one scan (possible twin), and strong nearby open networks. Warnings carry severity, evidence, a recommendation, and an explicit indicator-only disclaimer. Identical symptoms also follow legitimate router swaps or band steering, so the dashboard presents them for confirmation rather than acting automatically.

## 4. Network Risk Scoring

`policy.score_network` computes a score in [0, 100] from a security-class base plus adjustments:

| Signal | Effect |
|---|---|
| Open baseline | 85 |
| WEP baseline | 92 |
| WPA baseline | 75 |
| Unknown baseline | 60 |
| WPA2 baseline | 15 |
| WPA3 baseline | 5 |
| Public-hotspot SSID hint on WPA2/WPA3 | floor at 45 |
| Same SSID with divergent channel/security (possible twin) | +15 (cap 95) |
| RSSI below -78 dBm | +5 |

Verdict thresholds: score >= 65 is `avoid`, score >= 35 is `caution`, otherwise `connect`. Reasons are returned with every verdict and surfaced in the dashboard and API.

Device behavior risk (`risk_engine.calculate_risk`) is a separate additive model over stored counters, capped at 100:

| Feature | Weight |
|---|---|
| Authentication failures > 5 | +20 |
| Unknown destinations | +20 |
| Port scan | +30 |
| Traffic spike | +15 |
| Request-rate anomaly | +15 |
| Decoy interaction (per hit) | +40 |
| Unauthorized attempts | +20 |

Levels: 0-30 trusted, 31-60 suspicious, 61-80 high, 81-100 critical. Trust is defined as `100 - risk`. Scores at or above 80 trigger automatic isolation in the device model.

## 5. Anomaly Detection

Two detectors are implemented in `backend/ai_detector.py`, both Isolation Forest with contamination 0.08 and a deterministic rule fallback.

1. Device-behavior corroboration (`ai_score`): feature vector of connection count, unique destinations, port attempts, request frequency, and traffic volume. Trained on 200 synthetic normal samples. Used as corroborating evidence; rule-based risk remains authoritative.
2. Live-environment assessment (`assess_live`): eleven-feature vector combining environment signals with packet/flow telemetry. Trained on 300 synthetic normal home-Wi-Fi snapshots. Normal ranges are exposed via the API for transparency:

| Feature | Normal range | Source |
|---|---|---|
| Nearby networks | 2-15 | Wi-Fi scan |
| Open networks | 0-3 | Wi-Fi scan |
| LAN devices | 1-10 | ARP census |
| Gateway latency (ms) | 1-40 | gateway probe |
| DNS latency (ms) | 2-80 | resolver timing |
| Signal (dBm) | -70 to -25 | link state |
| Packet loss (%) | 0-5 | gateway loss probe |
| Packet rate (pps) | 0-500 | interface counters |
| TCP retransmissions | 0-50 | TCP stack counters |
| TCP connections | 1-60 | socket table |
| Destination diversity | 1-20 | socket table |

When scikit-learn is absent, the engine reports `rules` mode and flags a snapshot as anomalous when three or more features fall outside these ranges. Packet features that the host cannot provide are imputed to their medians and listed as such. Engine health, baseline size, and per-feature in/out status are returned by `GET /api/real/ai`.

## 6. Enforcement Policy
Enforcement is ask-first. Radar scans return `pending_blocks` (networks scored `avoid` that are neither blocked nor allowed). The dashboard presents Block and Allow actions for each. No network is forgotten without explicit confirmation.

macOS actions (no elevated privileges required):

- Block: remove the SSID from the preferred-network list so the host will not auto-join it, and record it in the blocklist.
- Allow: record the SSID in the allowlist; auto-protect will not propose it again.
- Disconnect: turn Wi-Fi off. Manual and confirmed only; never invoked automatically.
- LAN flag: record an IP/MAC pair as flagged. The host cannot isolate third-party LAN devices; the API response directs the operator to apply a MAC filter on the router.

## 7. Attack-Versus-Fault Classification and Incident Timeline

`backend/diagnosis.py` combines weak-signal, latency, and loss evidence (fault family) with open/legacy security, twin variants, rogue security changes, and anomalous environment features (attack family) into one of five verdicts: healthy, network_fault, suspected_attack, mixed, or degraded_unknown. Each verdict carries a confidence value, per-family scores, cited evidence lists, a recommended action, and a disclaimer that the output is triage guidance rather than attribution.

The timeline combines the existing event and incident tables into a single chronology (`GET /api/real/timeline`), showing when an issue started, which evidence triggered each alert, and what action was taken. Passive health samples (gateway latency, loss, signal, risk) are recorded about once a minute into `health_history`; `GET /api/real/verify` compares the older versus newer half of a window and reports improved, degraded, mixed, or insufficient data, so an operator can check whether a block, network switch, or router restart actually helped.

## 8. Packet Evidence and Privacy

`backend/packet_monitor.py` prefers metadata over content:

- Loss and latency come from small ICMP bursts against the default gateway (default 5 probes, hard cap 10, cached 60 s). The dashboard shows sent, received, loss percentage, and average latency.
- Flow telemetry comes from the local socket table and interface counters only: established TCP connection count, unique remote endpoint count, packet rate derived from counter deltas, and TCP retransmission counters. No payloads are read at any point.
- Optional PCAP captures use the system tcpdump when present and are hard-bounded: maximum 30 s, 2000 packets, 5 MB per file, 5 retained files, snap length 128 bytes (link, network, and transport headers; payloads truncated at capture time). Files are stored under the OS temporary directory and deleted automatically after 15 minutes. The status endpoint lists file metadata only; contents leave the host only through an explicit per-file download.

## 9. Implementation

- Backend: FastAPI with permissive CORS for same-LAN access, served on port 8000. The frontend is served from `/` as a static file.
- Persistence: SQLite via standard library only. Tables: `devices`, `events`, `incidents`, `decoy_hits`, `blocked`, `allowed`, `flagged_devices`, `net_observations`, `health_history`. Default path is `backend/cybershield.db` (`/tmp` on Vercel).
- Frontend: dependency-free JavaScript with Tailwind CDN. Polling intervals: live status 8 s, radar 12 s, AI 10 s, packet 30 s, timeline 30 s. Radar positions networks by signal strength on a deterministic angular layout; selection is by list or canvas hit-test.
- Dependencies: `fastapi`, `uvicorn`, `scikit-learn`, `numpy` (see `backend/requirements.txt`). tcpdump is an optional system tool, not a Python dependency.

## 10. API Reference

Device and audit model:

- `GET /api/devices`: tracked devices with allow/deny matrix.
- `GET /api/stats`: counts by status, isolated count, incident count.
- `GET /api/events?limit=120`: event log.
- `GET /api/incidents`: recorded incidents.
- `GET /api/decoys`: static decoy inventory.
- `POST /api/simulate/normal`: reset device table to the normal baseline.
- `POST /api/device/{id}/allow`: restore a device to trusted and lift quarantine.
- `POST /api/device/{id}/isolate`: manually isolate a device (risk floor 85, status critical).
- `GET /api/decoy/{decoy_id}?device_id=...`: record a decoy touch; any touch is a high-confidence signal.

Live network:

- `GET /api/real/status`: current link, IP/gateway/DNS, latency, protocol checks, risk score with verdict and recommendations.
- `GET /api/real/networks`: nearby networks with signal and security classification.
- `GET /api/real/radar`: scored networks with proximity, verdict, reasons, threats, preferred/blocked flags, pending blocks, and policy state.
- `GET /api/real/devices?mode=fast|full&fresh=0|1`: LAN census (ARP fast path; ping sweep on full).
- `POST /api/real/scan`: full subnet sweep.
- `GET /api/real/link`: link statistics.
- `POST /api/real/speedtest`: best-effort throughput probe.
- `GET /api/real/ai`: environment snapshot, anomaly assessment, engine status, normal ranges.
- `POST /api/real/block {ssid}`: forget network and blocklist it.
- `POST /api/real/unblock {ssid}`: allowlist a network.
- `POST /api/real/disconnect`: turn Wi-Fi off.
- `POST /api/real/device/flag {ip, mac, note}`: flag a LAN device.
- `GET /api/policy`: auto-protect state with block, allow, and flagged-device lists.

Packet, rogue, diagnosis, and timeline:

- `GET /api/real/packet?count=5&fresh=0`: cached gateway loss probe plus flow metadata.
- `POST /api/real/packet/probe {count}`: force a fresh loss measurement.
- `GET /api/real/rogue`: rogue-AP warnings for the current scan.
- `GET /api/real/diagnosis`: attack-versus-fault verdict with evidence and recommended action.
- `GET /api/real/radar`: now also returns `rogue_warnings` and `diagnosis` alongside networks.
- `GET /api/real/timeline?limit=50`: merged incident and event chronology plus recent health samples.
- `GET /api/real/health/history?limit=60`: passive health samples (oldest first).
- `GET /api/real/verify?window_min=30`: before/after comparison for the window.
- `GET /api/real/capture/status`: tcpdump availability, active capture, retained files, bounds.
- `POST /api/real/capture/start {interface, duration_s, max_packets, filter}`: start a bounded capture.
- `POST /api/real/capture/stop`: stop the active capture.
- `GET /api/real/capture/download?file=...`: download one retained capture (404 once expired).

## 11. Usage

Requirements: macOS for full live collectors (Linux and other hosts return degraded `unavailable` fields), Python 3 with pip, Node 18+ for the npm scripts. tcpdump is optional and only needed for the capture panel.

```bash
cd cybershield-wifi
npm install
npm start
# open http://127.0.0.1:8000
# development with reload: npm run dev
```

Python-only equivalent:

```bash
cd cybershield-wifi/backend
pip install -r requirements.txt
uvicorn main:app --reload --port 8000
```

Optional capture setup (macOS):

```bash
brew install tcpdump
# Capturing on en0 may prompt for permission or require sudo.
# Without it, the capture panel reports unavailable while all
# other features keep working.
```

Standard workflow: inspect the live connection panel and protocol checks, review packet loss and flow telemetry, review the radar verdicts with rogue warnings and the diagnosis, open a network for its threat analysis, block or allow high-risk networks as appropriate, use deep scan plus device flagging to review LAN membership, and use the timeline with before/after verification to confirm an action helped.

## 12. Limitations

- Proximity is an RSSI heuristic affected by walls, orientation, and transmit power; it is not ranging.
- Nearby-network visibility depends on `system_profiler` output and inherits its latency and completeness limits.
- LAN sweeps observe only hosts that respond to ARP or ping; silent or client-isolated hosts are missed.
- Blocking prevents future auto-joins but does not disconnect the current session and does not affect other devices.
- The anomaly detectors are trained on synthetic normal baselines, not on the operator's own environment; treat AI output as corroboration, not ground truth.
- Rogue warnings and diagnosis verdicts are heuristic indicators. Identical signals follow legitimate router changes, congestion, and weak coverage; confirm with the network owner before acting.
- Packet capture requires a local tcpdump binary with capture permission and is unavailable in sandboxed or serverless deployments (notably Vercel, which also lacks `system_profiler`, `networksetup`, ARP, and raw ICMP). Captures never leave the host except through explicit download and expire after 15 minutes.
- Live collection is macOS-specific; other platforms operate in degraded mode.

## 13. Repository Structure

```
cybershield-wifi/
  backend/
    main.py          FastAPI routes and device-risk helpers
    real_net.py      live macOS collectors and LAN census
    packet_monitor.py gateway loss probes, flow metadata, bounded capture
    rogue.py         SSID history and rogue-AP change warnings
    diagnosis.py     attack-versus-fault classification
    policy.py        network scoring and enforcement actions
    threat_model.py  proximity and defensive threat catalog
    ai_detector.py   Isolation Forest models and rule fallback
    risk_engine.py   device risk function and trust mapping
    database.py      SQLite persistence (devices, audits, observations, health)
    simulator.py     seed fixtures and authorization matrix
  frontend/
    index.html       dashboard (live, radar, LAN, AI, packet, timeline)
  package.json       npm scripts (start, dev, health)
  run.sh             backend-only launch script
```
