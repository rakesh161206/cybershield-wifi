"""IP purpose classification and context-aware suspicion scoring.

Two ideas do the work here:

1. PURPOSE — what is this address for? A CDN edge, a hosting provider, a
   Tor exit, a DNS resolver, a LAN peer, an advertising tracker. Purpose is
   derived from local signals first (scope, port, ASN name, reputation
   feeds) and never asserted beyond the evidence available.

2. CONTEXT — is that purpose surprising *here*? A hosting IP contacted by a
   browser during a page load is normal. The same hosting IP contacted by a
   printer at 3am is a finding. A purpose on its own is never a verdict;
   the score multiplies purpose by local actor, timing and behaviour.

Missing information is scored as uncertainty (+5), never as safety.
"""
import re
from datetime import datetime, timezone

try:
    import ip_intel
except ImportError:  # pragma: no cover - import-style fallback
    from backend import ip_intel

# ---------------- purpose catalogue ----------------
PURPOSES = {
    "loopback": ("Loopback", "Your own machine", "benign"),
    "lan-peer": ("LAN peer", "Another device on your local network", "benign"),
    "gateway": ("Router / gateway", "Your default gateway", "benign"),
    "dns-resolver": ("DNS resolver", "Answers name lookups", "benign"),
    "public-dns": ("Public DNS resolver", "Third-party resolver (e.g. 8.8.8.8)", "benign"),
    "ntp": ("Time server", "Network time synchronisation", "benign"),
    "mdns": ("Multicast discovery", "Local device discovery (Bonjour/SSDP)", "benign"),
    "dhcp": ("DHCP server", "Hands out addresses on your LAN", "benign"),
    "cdn": ("CDN edge", "Shared content delivery network", "shared"),
    "cloud-provider": ("Cloud provider", "Major cloud / hyperscaler", "shared"),
    "hosting": ("Hosting provider", "Servers rented by many customers", "interesting"),
    "vps": ("VPS / dedicated server", "Single-tenant machine rented out", "interesting"),
    "bulletproof-hosting": ("Bulletproof hosting", "Hosting marketed to abuse", "hostile"),
    "tor-exit": ("Tor exit node", "Traffic is relayed and anonymised", "hostile"),
    "vpn-exit": ("VPN exit", "Commercial VPN endpoint", "interesting"),
    "proxy": ("Proxy", "Open or configured relay", "interesting"),
    "tracker": ("Tracker / telemetry", "Behavioural analytics endpoint", "benign"),
    "mail": ("Mail server", "SMTP / IMAP / POP3", "benign"),
    "update-distribution": ("Update server", "Software or OS update delivery", "benign"),
    "streaming": ("Streaming service", "Video / audio delivery", "benign"),
    "game-server": ("Game server", "Multiplayer session traffic", "benign"),
    "web-app": ("Web application", "HTTP/HTTPS service", "benign"),
    "unknown": ("Unclassified", "Purpose could not be established", "unknown"),
}

# ASN / organisation name keywords -> purpose. First match wins, so the
# list is ordered most-specific first.
ORG_RULES = [
    (("tor ", "tornode", "torproject", "tor network"), "tor-exit"),
    (("bulletproof", "abuse.ch", "flokinet", "bulletproof"), "bulletproof-hosting"),
    (("cloudflare", "akamai", "fastly", "cloudfront", "bunny.net", "vercel",
      "netlify", "incapsula", "sucuri", "stackpath"), "cdn"),
    (("amazon web services", "aws", "amazon", "microsoft", "azure",
      "google", "alibaba cloud", "tencent cloud", "oracle cloud",
      "akamai connected"), "cloud-provider"),
    (("digitalocean", "linode", "hetzner", "contabo", "ovh",
      "leaseweb", "scaleway", "vultr", "hostinger", "ionos", "1and1",
      "hostwinds", "dreamhost", "godaddy"), "hosting"),
    (("vpn", "nordvpn", "expressvpn", "mullvad", "protonvpn", "surfshark",
      "private internet access"), "vpn-exit"),
    (("proxy", "squid", "privoxy", "webcache"), "proxy"),
    (("tracker", "doubleclick", "adservice", "adnxs", "scorecardresearch",
      "amplitude", "mixpanel", "segment", "hotjar", "newrelic",
      "google-analytics", "sentry", "datadog"), "tracker"),
    (("akamai connected cloud", "hosting", "host ", "datacenter", "data center",
      "hosting provider", "server", "colo", "cloud", "virtual host",
      "hosting solutions", "vps", "dedicated"), "hosting"),
]

PORT_RULES = {
    53: "dns-resolver", 5353: "mdns", 123: "ntp", 67: "dhcp", 68: "dhcp",
    1900: "mdns", 137: "mdns", 5355: "mdns", 546: "dhcp",
    22: "web-app", 23: "web-app", 25: "mail", 110: "mail", 143: "mail",
    465: "mail", 587: "mail", 993: "mail", 995: "mail",
    80: "web-app", 443: "web-app", 8080: "web-app", 8443: "web-app",
    3128: "proxy", 8888: "proxy", 8118: "proxy",
    53 + 10000: "dns-resolver",
}

# Well-known public resolvers.
PUBLIC_DNS = {"8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9",
               "149.112.112.112", "208.67.222.222", "208.67.220.220",
               "64.6.64.6", "77.88.8.8", "9.9.9.10", "76.76.2.0"}

SUSPICIOUS_PORTS = {4444, 1337, 31337, 6667, 6668, 6669, 1080, 3389, 445, 23,
                    135, 139, 3389, 5000, 5555, 8888, 9001, 1080}

# Local actors that should never be talking to hosting/Tor infrastructure.
BENIGN_ACTORS = {"browser", "system", "updater", "mail", "cybershield", "tool"}
UNKNOWN_ACTORS = {"unknown", "application"}

# Purpose -> suspicion base score.
BASE_SCORE = {
    "bulletproof-hosting": 70,
    "tor-exit": 65,
    "vpn-exit": 45,
    "proxy": 40,
    "hosting": 30,
    "vps": 32,
    "cloud-provider": 15,
    "cdn": 10,
    "tracker": 8,
    "web-app": 5,
    "mail": 5,
    "streaming": 3,
    "game-server": 3,
    "update-distribution": 0,
    "dns-resolver": 0,
    "public-dns": 0,
    "ntp": 0,
    "mdns": 0,
    "dhcp": 0,
    "loopback": 0,
    "lan-peer": 0,
    "gateway": 0,
    "unknown": 20,
}

HIGH_RISK_PURPOSES = {"hosting", "vps", "tor-exit", "bulletproof-hosting",
                      "vpn-exit", "proxy"}


def _org_purpose(name: str):
    low = (name or "").lower()
    if not low:
        return None
    for keys, purpose in ORG_RULES:
        for k in keys:
            if k in low:
                return purpose
    return None


def classify(ip, intel=None, ports=None):
    """Return (purpose, confidence, evidence list)."""
    intel = intel or {}
    ports = ports or []
    evidence = []
    scope = intel.get("scope") or ip_intel.classify_scope(ip)

    if scope == "loopback":
        return "loopback", 1.0, ["Loopback address"]
    if scope == "private":
        return "lan-peer", 1.0, ["RFC1918 private address — a device on your LAN"]
    if scope == "linklocal":
        return "lan-peer", 0.9, ["Link-local address (169.254/16, fe80::/10)"]
    if scope == "multicast":
        return "mdns", 0.9, ["Multicast address"]
    if scope == "cgnat":
        return "lan-peer", 0.7, ["Carrier-grade NAT address (100.64/10)"]
    if scope in ("documentation", "reserved"):
        return "unknown", 0.8, [f"{scope} address — not a real endpoint"]

    # reputation feeds first: strongest evidence available
    rep = intel.get("reputation") or {}
    for lst in rep.get("lists") or []:
        t = (lst.get("type") or "").lower()
        if t == "tor":
            return "tor-exit", 1.0, [f"Listed as a Tor exit node ({lst.get('name')})"]
        if t == "bulletproof":
            return "bulletproof-hosting", 1.0, [
                f"Listed as bulletproof hosting ({lst.get('name')})"]
        if t == "anonymiser":
            evidence.append(f"Listed in an anonymiser list ({lst.get('name')})")
            return "vpn-exit", 0.9, evidence

    # well-known public resolver
    if ip in PUBLIC_DNS:
        return "public-dns", 1.0, [f"Known public resolver ({ip})"]

    # organisation / ASN name
    org = intel.get("org") or intel.get("as_name") or ""
    p = _org_purpose(org)
    if p:
        return p, 0.85, [f"Organisation '{org}' classifies as {p}"]
    if org:
        evidence.append(f"Organisation '{org}' — no classification rule matched")

    if intel.get("hosting_hint"):
        return "hosting", 0.7, ["Geolocation provider flags this as hosting/datacenter"]

    # port-based
    ports = [int(x) for x in ports if x]
    if ports:
        for prt in ports:
            if prt in PORT_RULES:
                pur = PORT_RULES[prt]
                if pur == "dns-resolver" and ip in PUBLIC_DNS:
                    continue
                return pur, 0.6, [f"Observed service on port {prt} suggests {pur}"]
        evidence.append("Observed ports: " + ", ".join(str(x) for x in sorted(set(ports))))

    if any(prt in SUSPICIOUS_PORTS for prt in ports):
        return "hosting", 0.5, [
            "Connection to a port commonly used by remote-access tools or proxies "
            + ", ".join(str(x) for x in sorted(set(ports) & SUSPICIOUS_PORTS))]

    if intel.get("rdns"):
        rd = intel["rdns"].lower()
        if "cdn" in rd or "edge" in rd or "cache" in rd:
            return "cdn", 0.6, [f"Reverse DNS '{intel['rdns']}' looks like an edge node"]
        if "mail" in rd or "mx" in rd or "smtp" in rd:
            return "mail", 0.5, [f"Reverse DNS '{intel['rdns']}' looks like mail infrastructure"]

    if evidence:
        return "unknown", 0.4, evidence
    return "unknown", 0.3, ["No classification signal available"]


def _hour(ts=None):
    try:
        return (datetime.now(timezone.utc) if ts is None else ts).hour
    except Exception:
        return 12


def _interval_regularity(samples):
    """Return (mean_gap_s, stddev) between consecutive observation samples."""
    if not samples or len(samples) < 4:
        return None, None
    times = []
    for s in samples:
        try:
            times.append(datetime.fromisoformat(s).timestamp())
        except Exception:
            continue
    if len(times) < 4:
        return None, None
    gaps = [b - a for a, b in zip(times, times[1:]) if b > a]
    if len(gaps) < 3:
        return None, None
    mean = sum(gaps) / len(gaps)
    var = sum((g - mean) ** 2 for g in gaps) / len(gaps)
    return mean, var ** 0.5


def score(ip, purpose, ctx=None):
    """Context-aware suspicion score 0-100 with cited reasons."""
    ctx = ctx or {}
    reasons = []
    score = BASE_SCORE.get(purpose, 20)
    reasons.append(f"Purpose '{purpose}' baseline ({score})")

    rep = ctx.get("reputation") or {}
    for lst in rep.get("lists") or []:
        t = (lst.get("type") or "").lower()
        if t == "malware":
            score += 30
            reasons.append(f"Present in a malware/botnet feed ({lst.get('name')}) (+30)")
        elif t == "anonymiser":
            score += 12
            reasons.append(f"Present in an anonymiser feed ({lst.get('name')}) (+12)")
        elif t == "tor":
            score += 25
            reasons.append(f"Present in the Tor exit list (+25)")

    actor = (ctx.get("actor_class") or "unknown").lower()
    ports = [int(x) for x in (ctx.get("ports") or []) if x]
    distinct_ports = len(set(ports))
    scope_is_public = (ctx.get("scope") == "public")

    # unexpected local actor talking to infrastructure that can host C2
    if purpose in HIGH_RISK_PURPOSES and actor in UNKNOWN_ACTORS:
        score += 25
        reasons.append(f"Unexpected local program '{actor}' contacting "
                       f"{purpose} infrastructure (+25)")
    elif purpose in HIGH_RISK_PURPOSES and actor not in BENIGN_ACTORS:
        score += 15
        reasons.append(f"Local program '{actor}' contacting {purpose} infrastructure (+15)")

    # scan shape: one IP, many distinct ports. Only meaningful for a
    # remote peer -- a local service using several ports is normal.
    if scope_is_public and distinct_ports >= 5:
        score += 30
        reasons.append(f"{distinct_ports} distinct ports contacted on one address — "
                       f"a scanning shape (+30)")
    elif scope_is_public and distinct_ports >= 3:
        score += 12
        reasons.append(f"{distinct_ports} distinct ports on one address (+12)")

    # newly seen address on a non-standard port
    if scope_is_public and ctx.get("is_new") and ports and \
            not set(ports) & {80, 443, 53, 123, 22, 25, 993}:
        score += 15
        reasons.append("First-seen address contacted on a non-standard port (+15)")

    # unusual hours
    hr = _hour()
    if hr >= 2 and hr < 5 and purpose in HIGH_RISK_PURPOSES:
        score += 10
        reasons.append(f"Contact at {hr:02d}:xx local time with "
                       f"{purpose} infrastructure (+10)")

    # beaconing / regular interval
    mean, sd = _interval_regularity(ctx.get("samples") or [])
    if mean is not None and sd is not None and 5 <= mean <= 600 and sd <= max(2.0, mean * 0.25):
        extra = 20 if purpose in HIGH_RISK_PURPOSES else 8
        score += extra
        reasons.append(f"Regular ~{int(mean)}s contact interval — a beaconing shape (+{extra})")

    # uncertainty, never silence. Only a remote peer can be "unknown" in a
    # way that matters -- scope alone settles a local address.
    if scope_is_public:
        if not (ctx.get("sources") or []):
            score += 5
            reasons.append("No intelligence could be established (+5 uncertainty, not suspicion)")
        if not ctx.get("asn"):
            score += 5
            reasons.append("Origin network could not be identified (+5 uncertainty)")

    score = max(0, min(100, int(round(score))))
    verdict = "avoid" if score >= 65 else "caution" if score >= 35 else "connect"
    return {"score": score, "verdict": verdict, "reasons": reasons}


def label(purpose):
    meta = PURPOSES.get(purpose) or PURPOSES["unknown"]
    return {"key": purpose, "label": meta[0], "detail": meta[1], "class": meta[2]}


def assess(peers, intel_map=None, observations=None):
    """Enrich observed peers with purpose, score and reasons.

    peers: [{ip, port, state, actor_class, actors}]
    intel_map: {ip: intel payload}
    observations: {ip: observation row}
    """
    intel_map = intel_map or {}
    observations = observations or {}
    by_ip = {}
    for p in peers or []:
        ip = p.get("ip")
        if not ip:
            continue
        rec = by_ip.setdefault(ip, {"ip": ip, "ports": [], "states": [], "actors": [],
                                    "actor_class": p.get("actor_class", "unknown"),
                                    "actor_names": p.get("actors") or []})
        if p.get("port") and p["port"] not in rec["ports"]:
            rec["ports"].append(p["port"])
        if p.get("state") and p["state"] not in rec["states"]:
            rec["states"].append(p["state"])
        for a in (p.get("actors") or []):
            if a not in rec["actor_names"]:
                rec["actor_names"].append(a)

    out = []
    for ip, rec in by_ip.items():
        intel = intel_map.get(ip) or {}
        obs = observations.get(ip) or {}
        purpose, conf, ev = classify(ip, intel, rec["ports"])
        ctx = {
            "reputation": intel.get("reputation"),
            "actor_class": rec["actor_class"],
            "ports": rec["ports"],
            "sources": intel.get("sources"),
            "scope": intel.get("scope"),
            "asn": intel.get("asn"),
            "is_new": bool(obs.get("first_seen") and obs.get("hits", 0) <= 1),
            "samples": obs.get("samples") or [],
        }
        sc = score(ip, purpose, ctx)
        out.append({
            **rec,
            "intel": intel,
            "purpose": purpose,
            "purpose_label": label(purpose),
            "purpose_confidence": conf,
            "purpose_evidence": ev,
            "score": sc["score"],
            "verdict": sc["verdict"],
            "reasons": sc["reasons"],
            "first_seen": obs.get("first_seen", ""),
            "last_seen": obs.get("last_seen", ""),
            "hits": obs.get("hits", 0),
        })
    out.sort(key=lambda r: (-r["score"], r["ip"]))
    return out
