# CyberShield Wi-Fi: Zero-Trust Wireless Security with Rule-Based Risk Scoring, Anomaly Detection, and IP Purpose Intelligence

## Abstract

CyberShield Wi-Fi is a host-based wireless security system that applies the Zero-Trust principle "connected does not imply trusted" to Wi-Fi networks. It continuously collects live link state, nearby network advertisements, LAN membership, latency signals, and packet/flow telemetry on the host, scores each network with a deterministic risk model, flags rogue access-point indicators, classifies degradation as fault or suspected attack, corroborates the environment with an Isolation Forest anomaly detector, and enforces an ask-first blocking policy. Packet evidence is restricted to headers and flow counters, with bounded, auto-expiring captures.

On top of the wireless layer it performs **IP purpose intelligence**: every external address this host talks to is classified by *what it is for* (CDN edge, cloud provider, hosting, Tor exit, resolver, tracker, LAN peer) and scored in *context* — purpose alone is never a verdict, because a hosting address contacted by a browser is ordinary while the same address contacted by a printer at 3am is a finding. Enrichment is local-first (scope, reverse DNS, Team Cymru's DNS-only ASN service, locally matched reputation feeds); geolocation is opt-in because it is the only step that sends an address to a third party. The system consists of a FastAPI backend, a SQLite persistence layer, and a single-page dashboard. This document describes the threat model, scoring methodology, detection method, enforcement semantics, IP intelligence layer, API surface, and reproduction steps.

## 1. Problem Statement

Standard Wi-Fi clients trust a network after authentication and rarely re-evaluate that decision. This exposes users to open networks, evil-twin access points, weak or legacy encryption (WEP, WPA), downgrade attacks, passive sniffing, and ARP-spoofing on shared LANs. CyberShield addresses this by separating authentication from authorization: every visible network and the current connection are re-scored on each scan, with reasons, recommended actions, and per-threat defensive guidance.

## 2. System Architecture

```
Host collectors, per OS (stdlib only; first working source wins):
  macOS:   system_profiler, networksetup, ipconfig, route, scutil, arp, ping
  Linux:   iw, nmcli, ip route, /etc/resolv.conf, arp, ping
  Windows: netsh wlan, route print, ipconfig, arp, ping
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
        +---> ip_intel.py / ip_purpose.py / ip_alerts.py (IP purpose intelligence)
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
- `backend/packet_monitor.py`: gateway loss/latency probes (cached ICMP bursts), flow metadata from socket and interface counters (TCP connections, destination diversity, packet rate, retransmission counters), the **observed remote endpoints with port and connection state**, the **local program that owns each socket**, and bounded header-truncated tcpdump captures with automatic expiry. Headers and counters only, never payloads.
- `backend/policy.py`: deterministic network scoring and enforcement (forget saved network, allowlist, Wi-Fi power off) via `networksetup` (macOS), `nmcli` (Linux), or `netsh` (Windows).
- `backend/threat_model.py`: RSSI-to-proximity mapping and a defensive threat catalog keyed by security class.
- `backend/rogue.py`: per-SSID fingerprint history with warnings for new networks, security mismatches, identical SSIDs with divergent security types (possible twin), and strong open signals. Same-name multichannel sightings with identical security are low-severity notes (normal dual-band/mesh). Every warning is labeled a risk indicator, not proof.
- `backend/diagnosis.py`: attack-versus-fault classifier combining signal quality, loss/latency, security posture, rogue warnings, AI assessment, and radar verdicts into healthy, network_fault, suspected_attack, mixed, or degraded_unknown, with cited evidence and a recommended action.
- `backend/ai_detector.py`: two Isolation Forest models (device-behavior corroboration and live-environment assessment) with a rule-based fallback when scikit-learn is unavailable.
- `backend/ip_intel.py`: local-first IP enrichment — scope classification, reverse DNS with a hard deadline, Team Cymru ASN/prefix/RIR via DNS (no key, no account), opt-in geolocation, and local reputation-feed matching.
- `backend/ip_purpose.py`: the purpose taxonomy and the context-aware suspicion score.
- `backend/ip_alerts.py`: IP-level alert rules with severity, cited evidence, recommended actions, and a dedup cooldown.
- `backend/ip_report.py`: investigation report generation (Markdown and JSON) from locally stored telemetry.
- `backend/feeds.py`: reputation feed download, local storage, and freshness tracking.
- `backend/http_util.py`: outbound HTTP with a CA bundle that resolves on the host. TLS verification is never disabled — an unauthenticated feed could inject arbitrary addresses into the reputation list.
- `backend/risk_engine.py`: behavior-based device risk function and trust mapping.
- `backend/database.py`: SQLite persistence for devices, events, incidents, decoy hits, block/allow lists, flagged LAN devices, IP observations, IP intelligence cache, IP alerts, the IP watchlist, and feed status.
- `backend/simulator.py`: static fixtures (normal devices, decoys, authorization matrix) used to seed the device table.
- `frontend/index.html`: dashboard with live connection panel, health sparklines, signal radar, per-network detail, LAN table, IP Intel tab, and AI panel.

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

`backend/rogue.py` maintains a per-SSID observation history (security class, channel, signal, first/last seen) and reports warning types on each scan: new never-before-seen networks, known SSIDs whose security class changed, identical SSIDs with divergent security types in one scan (possible twin), and strong nearby open networks. Same-name sightings on several channels with identical security are low-severity informational notes, since that is normal dual-band, mesh, or extender behaviour. Warnings carry severity, evidence, a recommendation, and an explicit indicator-only disclaimer. Identical symptoms also follow legitimate router swaps or band steering, so the dashboard presents them for confirmation rather than acting automatically.

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
| Same SSID with divergent security types (possible twin) | +15 (cap 95) |
| Same SSID on several channels with identical security (dual-band/mesh) | +0 |
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

Per-OS actions (no elevated privileges required for the common cases):

- Block: delete the saved network so the host will not auto-join it (`networksetup` on macOS, `nmcli connection delete` on Linux, `netsh wlan delete profile` on Windows), and record the SSID in the blocklist. If the platform tool is missing, the API says so instead of pretending.
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

## 8a. IP Purpose Intelligence

### The two questions

**Purpose** — what is this address *for*? **Context** — is that purpose surprising *here*? The second question is where the value is. A hosting address contacted by a browser during a page load is ordinary; the same address contacted by a printer at 03:00 is a finding. A purpose on its own is never a verdict, so the score is always purpose × local actor × behaviour.

### Where the data comes from

The peer addresses were already being computed by the flow collector and then discarded — only the *count* of unique remote endpoints was kept. They are now retained, together with the remote port, the connection state, and the name of the local program that owns the socket (`lsof` on macOS/Linux, `netstat` + `tasklist` on Windows). No payloads are involved at any point.

Enrichment is local-first and strictly ordered:

| Signal | Source | External? | Default |
|---|---|---|---|
| Scope (public/private/loopback/link-local/multicast/CGNAT) | computed locally | No | Always on |
| Reverse DNS | local resolver, hard deadline | No | Always on |
| Origin ASN, prefix, RIR, AS name | Team Cymru DNS interface | No (DNS only, no key, no account) | Always on |
| Reputation match | locally downloaded feed files | No | Always on |
| Geolocation, city, ISP | third-party resolver | **Yes** | **Off** |

Geolocation is disabled unless `CYBERSHIELD_GEO=1` is set, because it is the only step that puts an observed address in front of another party. The dashboard states which enrichers are active (`GET /api/ip/sources`). Reputation is matched locally against downloaded lists, so a raw observed address is never handed to a reputation API.

Reputation feeds (Tor exit nodes, FireHOL level 1, FireHOL anonymisers) are downloaded one-way into the OS temp directory and matched locally. A feed that cannot be fetched is reported as *unavailable*, never treated as clean, and TLS verification is never disabled — an unauthenticated feed could inject arbitrary addresses into the list and every match would then be a false positive.

### Purpose taxonomy

`loopback`, `lan-peer`, `gateway`, `dns-resolver`, `public-dns`, `ntp`, `mdns`, `dhcp`, `cdn`, `cloud-provider`, `hosting`, `vps`, `bulletproof-hosting`, `tor-exit`, `vpn-exit`, `proxy`, `tracker`, `mail`, `update-distribution`, `streaming`, `game-server`, `web-app`, `unknown`.

Shared infrastructure (CDN, cloud) is classified but is never treated as hostile on its own — attributing traffic to a CDN edge tells you nothing about the actor behind it.

### Context-aware score

Base score by purpose, then additive modifiers, capped at 100. Verdicts match the wireless layer: `>=65 avoid`, `>=35 caution`, otherwise `connect`.

| Signal | Effect |
|---|---|
| Purpose baseline (bulletproof-hosting 70, tor-exit 65, vpn-exit 45, proxy 40, hosting 30, vps 32, cloud 15, cdn 10, tracker 8, web-app 5, unknown 20) | base |
| Malware/botnet feed match | +30 |
| Anonymiser feed match | +12 |
| Tor exit list match | +25 |
| Unrecognised local program contacting hosting/Tor/proxy infrastructure | +25 |
| Other non-standard local program contacting the same | +15 |
| 5+ distinct ports on one remote address (scanning shape) | +30 |
| 3–4 distinct ports on one remote address | +12 |
| First-seen remote address on a non-standard port | +15 |
| Contact at 02:00–05:00 local with hosting/Tor infrastructure | +10 |
| Regular contact interval (beaconing shape) | +20 / +8 |
| No intelligence could be established (uncertainty, not suspicion) | +5 |
| Origin network could not be identified (uncertainty) | +5 |

Local addresses are excluded from the port-count and uncertainty penalties — a loopback service using several ports is normal, and scope alone settles a local address.

### Alerts

Alerts are indicators surfaced for the operator, never autonomous actions. The host cannot block an external address, so every recommended action is one a person can take. Each alert cites the exact observations that produced it and carries a dedup cooldown, so a persistent condition yields one alert rather than hundreds.

| Alert | Severity | Trigger |
|---|---|---|
| `bulletproof_host` | critical | Connection to a bulletproof hosting provider |
| `tor_exit_contact` | high | Traffic reached a Tor exit node |
| `reputation_malware` | high | Address matched a malware or botnet feed |
| `scan_shape` | high | One remote address contacted across 5+ distinct ports |
| `beaconing` | high | Regular interval connection pattern |
| `unexpected_hosting` | medium | Unrecognised program contacted hosting infrastructure |
| `watchlist_hit` | medium | A watched address was contacted |
| `new_external_ip` | info | First contact with a new external address |

### Investigation reports

`GET /api/ip/report?ip=…&format=md|json` builds a report entirely from data already stored on this host: summary and verdict, the reasoning behind the score, address facts (scope, reverse DNS, ASN, prefix, RIR, location, organisation), reputation matches, observed behaviour with a service table, related alerts, recommended actions, and an explicit method-and-limits section naming the enrichment sources used and the ones unavailable.

The narrative is template-generated from cited fields. It is deliberately **not** labelled as AI-generated: there is no language model in this pipeline, and calling a rule-based summary "AI" would misrepresent the evidence.

## 9. Implementation

- Backend: FastAPI with permissive CORS for same-LAN access, served on port 8000. The frontend is served from `/` as a static file.
- Persistence: SQLite via standard library only. Tables: `devices`, `events`, `incidents`, `decoy_hits`, `blocked`, `allowed`, `flagged_devices`, `net_observations`, `health_history`, `ip_observations`, `ip_services`, `ip_intel_cache`, `ip_alerts`, `ip_watchlist`, `ip_feeds`. Default path is `backend/cybershield.db` (`/tmp` on Vercel).
- Frontend: dependency-free JavaScript with Tailwind CDN. Polling is **tab-aware**: only the active tab's refreshers run, so a background tab does not keep driving the scanner. Live status 8 s, radar 12 s, AI 10 s, packet 30 s, health 20 s, timeline 15 s, IP intel 10 s. The radar canvas animation pauses when the Networks tab is hidden or the browser tab is in the background. Radar positions networks by signal strength on a deterministic angular layout, with shape as well as colour encoding the verdict; selection is by list or canvas hit-test. API calls carry a timeout, and a failed backend is surfaced in the header rather than silently leaving stale panels.
- Dependencies: `fastapi`, `uvicorn`, `scikit-learn`, `numpy` (see `backend/requirements.txt`). tcpdump is an optional system tool, not a Python dependency. `certifi` is optional but recommended: some Python builds ship without a resolvable CA bundle, which breaks reputation-feed downloads.

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

IP purpose intelligence:

- `GET /api/ip/observed?limit=200&filter=`: every external address this host is talking to, with purpose, score, verdict, reasons, observed ports, local program, and first/last seen.
- `GET /api/ip/lookup?ip=...`: full intelligence payload for one address (scope, reverse DNS, ASN, prefix, RIR, organisation, location, reputation, provenance).
- `GET /api/ip/alerts?limit=100&unacked=1`: IP alerts with severity, evidence, and recommended action.
- `POST /api/ip/alerts/{id}/ack`: acknowledge one alert.
- `POST /api/ip/watch {ip, note}` / `DELETE /api/ip/watch/{ip}`: manage the watchlist.
- `GET /api/ip/watchlist`: current watchlist.
- `GET /api/ip/report?ip=...&format=md|json`: investigation report.
- `GET /api/ip/feeds/status`: reputation feed freshness, item counts, and where the lists are stored.
- `POST /api/ip/feeds/refresh`: re-download the reputation feeds.
- `GET /api/ip/sources`: which enrichers are enabled and what each one sends off-host.

## 11. Usage

Requirements: Windows 10/11, macOS, or Linux with Python 3.12+, plus pip. Node 18+ only needed for the npm scripts. tcpdump is optional and only needed for the capture panel.

macOS or Linux:

```bash
cd cybershield-wifi
./run.sh
# open http://127.0.0.1:8000
```

Windows (Command Prompt or PowerShell):

```bat
cd cybershield-wifi
run.bat
```

npm alternative (any OS):

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

Linux notes: Wi-Fi details need `iw` and NetworkManager (`nmcli`); Debian/Ubuntu: `sudo apt install iw network-manager`. Nearby scans use cached results (`--rescan no`) to stay fast.

Windows notes: Wi-Fi details come from `netsh wlan` (built in). Disabling Wi-Fi may need the exact interface name or administrator rights; the API reports either case.

IP intelligence notes:

- Everything in the IP Intel tab works with no configuration. Scope, reverse DNS, Team Cymru ASN lookups and reputation matching are local or DNS-only.
- Reputation feeds download on demand from the **Refresh reputation feeds** button, and are stored in the OS temp directory. Edit `feeds.json` in that directory to add or replace feeds. TLS verification is never disabled.
- Geolocation is **off by default** because it sends the observed address to a third-party resolver. To enable it:

  ```bash
  CYBERSHIELD_GEO=1 python3 -m uvicorn main:app --host 0.0.0.0 --port 8000 --app-dir backend
  # optional: CYBERSHIELD_GEO_PROVIDER=ipapi.co|ipinfo.io
  ```

- If reputation feeds fail to download with a TLS error, your Python build has no resolvable CA bundle. `pip install certifi` fixes it; `backend/http_util.py` also falls back to the system bundle paths.
- Local program attribution on macOS and Linux needs `lsof` (`brew install lsof` / `sudo apt install lsof`). Without it, connections show as `unknown`.

Dashboard smoke test (requires the server running):

```bash
python3 -m uvicorn main:app --port 8000 --app-dir backend &
CS_BASE=http://127.0.0.1:8000 node smoke_test.js
```

Optional capture setup:

```bash
# macOS
brew install tcpdump
# Debian/Ubuntu
sudo apt install tcpdump
# Windows: install Npcap, plus WinDump or Wireshark (tshark)
```

Capturing may require elevated permission (sudo, a macOS developer-tools prompt, or Npcap in WinPcap-compatible mode). Without it, the capture panel reports unavailable while all other features keep working.

Standard workflow: inspect the live connection panel and protocol checks, review packet loss and flow telemetry, review the radar verdicts with rogue warnings and the diagnosis, open a network for its threat analysis, block or allow high-risk networks as appropriate, use deep scan plus device flagging to review LAN membership, open the IP Intel tab to see what each external address is *for* and whether that is surprising for the local program that contacted it, generate a report for anything that warrants escalation, and use the timeline with before/after verification to confirm an action helped.

## 12. Limitations

- Proximity is an RSSI heuristic affected by walls, orientation, and transmit power; it is not ranging.
- Nearby-network visibility depends on the platform scanner (`system_profiler` on macOS, `nmcli` cache on Linux, `netsh` on Windows) and inherits its latency and completeness limits.
- LAN sweeps observe only hosts that respond to ARP or ping; silent or client-isolated hosts are missed.
- Blocking prevents future auto-joins but does not disconnect the current session and does not affect other devices.
- The anomaly detectors are trained on synthetic normal baselines, not on the operator's own environment; treat AI output as corroboration, not ground truth.
- Rogue warnings and diagnosis verdicts are heuristic indicators. Identical signals follow legitimate router changes, congestion, and weak coverage; confirm with the network owner before acting.
- Twin detection compares security/channel fingerprints, not BSSIDs, so a perfect clone (same name, security, and channel) is not distinguishable from the legitimate AP by these signals alone.
- Packet capture requires a local tcpdump binary with capture permission and is unavailable in sandboxed or serverless deployments (notably Vercel, which also lacks Wi-Fi scanners, ARP, and raw ICMP). Captures never leave the host except through explicit download and expire after 15 minutes.
- On hosts without Wi-Fi hardware or scanner tools, link and radar fields report unavailable while scoring, AI, timeline, and audit features keep working.

IP purpose intelligence:

- Purpose classification is heuristic. A hosting provider that runs a CDN is classified as a CDN; an address whose organisation matches no rule is left `unknown` rather than guessed. Expect occasional misclassification and treat the evidence list, not the label, as the substance.
- A purpose is never a verdict on its own. Shared infrastructure (CDN, cloud, big transit providers) carries many unrelated actors, so it is never treated as hostile without corroboration.
- Local program attribution is best-effort. `lsof` is required on macOS and Linux and is frequently not installed; without it, connections are attributed to `unknown`, which costs score points. Windows attribution needs `tasklist` and is slower.
- The socket table shows *current* connections. A short-lived connection that opened and closed between polls is never observed, and long-lived connections can change purpose between observations. The observation history is therefore a sampled view, not a complete log.
- Beacon detection needs at least four observations of the same address at regular intervals. It cannot fire on a first sighting, and it will not fire on an address whose usage is genuinely irregular.
- Reputation feeds are point-in-time snapshots. A feed that cannot be downloaded is reported as unavailable, and an address is then neither cleared nor condemned by it.
- Reverse DNS and ASN lookups depend on the host's resolver and on Team Cymru's DNS service being reachable. Where they are not, the address carries an explicit "enrichment pending / unavailable" marker, and the score adds a small uncertainty penalty rather than defaulting to clean.
- Geolocation is off by default and, when enabled, sends the observed address to a third-party resolver. That is the only step in this system that shares an observed address externally, and it is labelled as such in the dashboard.
- The investigation report is template-generated from cited fields. There is no language model in the pipeline, so it is not described as AI-generated.
- Nothing in this layer can block an external address. The host can only report, and the recommended actions point at the router or firewall where the actual control lives.

## 13. Repository Structure

```
cybershield-wifi/
  backend/
    main.py          FastAPI routes and device-risk helpers
    real_net.py      cross-platform collectors (Wi-Fi, IP, LAN census)
    packet_monitor.py gateway loss probes, flow metadata, peer endpoints, bounded capture
    rogue.py         SSID history and rogue-AP change warnings
    diagnosis.py     attack-versus-fault classification
    policy.py        network scoring and enforcement actions
    threat_model.py  proximity and defensive threat catalog
    ai_detector.py   Isolation Forest models and rule fallback
    ip_intel.py      scope, reverse DNS, Team Cymru ASN, opt-in geo, feed matching
    ip_purpose.py    purpose taxonomy and context-aware suspicion score
    ip_alerts.py     IP alert rules with severity, evidence and cooldown
    ip_report.py     investigation report generation (Markdown / JSON)
    feeds.py         reputation feed download, storage and freshness
    http_util.py     outbound HTTP with a resolvable CA bundle
    risk_engine.py   device risk function and trust mapping
    database.py      SQLite persistence (devices, audits, observations, health, IP intel)
    simulator.py     seed fixtures and authorization matrix
  frontend/
    index.html       dashboard (live, radar, LAN, IP Intel, AI, packet, timeline)
  package.json       npm scripts (start, dev, health)
  run.sh             launcher for macOS and Linux
  run.bat            launcher for Windows
  smoke_test.js      headless render check for the dashboard (needs a running server)
```


git hub 