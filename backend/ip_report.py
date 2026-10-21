"""Investigation report generation for a single IP address.

Reports are built entirely from data already stored on this host: the
observation history, observed services, cached intelligence and the alert
log. Nothing is fetched at report time beyond a refresh of the address
itself, and the report states plainly which enrichment sources were used
and which were unavailable.

The narrative is template-generated from cited fields. It is deliberately
NOT labelled as AI-generated: there is no language model in this pipeline,
and calling a rule-based summary "AI" would misrepresent the evidence.
"""
from datetime import datetime, timezone

try:
    import database as db
    import ip_intel
    import ip_purpose
except ImportError:  # pragma: no cover - import-style fallback
    from backend import database as db
    from backend import ip_intel
    from backend import ip_purpose

DISCLAIMER = ("Heuristic report built from host-visible telemetry only. "
              "Purpose and reputation are indicators, not proof. A benign "
              "explanation is always possible and should be checked first.")


def _fmt_ts(ts):
    if not ts:
        return "unknown"
    try:
        return datetime.fromisoformat(ts).strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        return str(ts)


def build(ip, intel=None, assessed=None, alerts=None, services=None):
    ip = (ip or "").strip()
    intel = intel or ip_intel.lookup(ip)
    obs_row = None
    for o in db.get_ip_observations():
        if o.get("ip") == ip:
            obs_row = o
            break
    services = services if services is not None else db.get_ip_services(ip)
    alerts = alerts if alerts is not None else [
        a for a in db.get_ip_alerts(limit=500) if a.get("ip") == ip]

    ports = sorted({s.get("port") for s in services if s.get("port")})
    protos = sorted({s.get("proto") for s in services if s.get("proto")})
    purpose, conf, evidence = ip_purpose.classify(ip, intel, ports)
    ctx = {
        "reputation": intel.get("reputation"),
        "actor_class": (assessed or {}).get("actor_class", "unknown"),
        "ports": ports,
        "sources": intel.get("sources"),
        "scope": intel.get("scope"),
        "asn": intel.get("asn"),
        "is_new": bool(obs_row and obs_row.get("hits", 0) <= 1),
        "samples": (obs_row or {}).get("samples") or [],
    }
    sc = ip_purpose.score(ip, purpose, ctx)
    pl = ip_purpose.label(purpose)

    return {
        "ip": ip,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "verdict": sc["verdict"],
        "score": sc["score"],
        "purpose": pl,
        "purpose_confidence": conf,
        "purpose_evidence": evidence,
        "reasons": sc["reasons"],
        "facts": {
            "scope": intel.get("scope"),
            "reverse_dns": intel.get("rdns") or "",
            "asn": intel.get("asn") or "",
            "as_name": intel.get("as_name") or "",
            "prefix": intel.get("prefix") or "",
            "rir": intel.get("rir") or "",
            "country": intel.get("country") or "",
            "country_source": intel.get("country_source") or "",
            "city": intel.get("city") or "",
            "org": intel.get("org") or "",
            "isp": intel.get("isp") or "",
        },
        "reputation": intel.get("reputation") or {"matched": False, "lists": []},
        "observed": {
            "first_seen": (obs_row or {}).get("first_seen", ""),
            "last_seen": (obs_row or {}).get("last_seen", ""),
            "hits": (obs_row or {}).get("hits", 0),
            "ports": ports,
            "protocols": protos,
            "services": services,
            "actors": (obs_row or {}).get("actors", []),
            "samples": (obs_row or {}).get("samples", []),
        },
        "alerts": alerts,
        "sources_used": intel.get("sources") or [],
        "sources_missing": intel.get("missing") or [],
        "watched": any(w.get("ip") == ip for w in db.get_watchlist()),
        "note": DISCLAIMER,
        "recommendations": _recommend(purpose, sc, intel, obs_row),
    }


def _recommend(purpose, sc, intel, obs_row):
    out = []
    if sc["verdict"] == "avoid":
        out.append("Treat this address as hostile until the local program that "
                   "contacted it is identified and explained.")
        out.append("Terminate the connection and block the address at the router "
                   "or firewall.")
    elif sc["verdict"] == "caution":
        out.append("Confirm which local program opened this connection and that "
                   "the destination is expected.")
    else:
        out.append("No action required for this address on current evidence. "
                   "It is recorded for the incident timeline.")
    if purpose in ("cdn", "cloud-provider"):
        out.append("Shared infrastructure: this address is not attributable to a "
                   "single actor, so avoid over-weighting it in an investigation.")
    if (obs_row or {}).get("hits", 0) <= 1:
        out.append("First-seen address. Behaviour over time is not yet established, "
                   "so treat the current score as provisional.")
    if not intel.get("asn"):
        out.append("The origin network could not be identified — enrichment was "
                   "partial, which is uncertainty rather than evidence of safety.")
    return out


def render_markdown(r):
    f = r.get("facts", {})
    o = r.get("observed", {})
    lines = []
    lines.append(f"# IP investigation report — {r.get('ip')}")
    lines.append("")
    lines.append(f"*Generated {r.get('generated_at')} — {r.get('note')}*")
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    lines.append(f"- **Verdict:** {str(r.get('verdict', '')).upper()} "
                 f"(score {r.get('score')}/100)")
    lines.append(f"- **Purpose:** {r.get('purpose', {}).get('label')} — "
                 f"{r.get('purpose', {}).get('detail')} "
                 f"(confidence {r.get('purpose_confidence')})")
    lines.append(f"- **First seen:** {_fmt_ts(o.get('first_seen'))}")
    lines.append(f"- **Last seen:** {_fmt_ts(o.get('last_seen'))} "
                 f"({o.get('hits', 0)} observation(s))")
    lines.append(f"- **Watchlist:** {'yes' if r.get('watched') else 'no'}")
    lines.append("")
    lines.append("## Why")
    lines.append("")
    for x in r.get("reasons") or []:
        lines.append(f"- {x}")
    if r.get("purpose_evidence"):
        lines.append("")
        lines.append("### Purpose evidence")
        lines.append("")
        for x in r["purpose_evidence"]:
            lines.append(f"- {x}")
    lines.append("")
    lines.append("## Address facts")
    lines.append("")
    lines.append("| Field | Value |")
    lines.append("|---|---|")
    for k, label in (("scope", "Scope"), ("reverse_dns", "Reverse DNS"),
                     ("asn", "Origin ASN"), ("as_name", "AS name"),
                     ("prefix", "Announced prefix"), ("rir", "RIR"),
                     ("country", "Country" + (" (RIR allocation)"
                                              if f.get("country_source") == "rir" else "")),
                     ("city", "City"),
                     ("org", "Organisation / host"), ("isp", "ISP")):
        lines.append(f"| {label} | {f.get(k) or '—'} |")
    lines.append("")
    rep = r.get("reputation") or {}
    lines.append("## Reputation")
    lines.append("")
    if rep.get("matched"):
        for lst in rep.get("lists") or []:
            lines.append(f"- Matched **{lst.get('name')}** (type: {lst.get('type')})")
    else:
        lines.append("- No match in the local reputation feeds.")
    lines.append("")
    lines.append("## Observed behaviour")
    lines.append("")
    lines.append(f"- Ports: {', '.join(str(p) for p in o.get('ports') or []) or 'none recorded'}")
    lines.append(f"- Protocols: {', '.join(o.get('protocols') or []) or 'none recorded'}")
    lines.append(f"- Local programs: {', '.join(o.get('actors') or []) or 'not attributed'}")
    if o.get("services"):
        lines.append("")
        lines.append("| Service | First seen | Last seen | Hits |")
        lines.append("|---|---|---|---|")
        for s in o["services"][:40]:
            lines.append(f"| {s.get('proto')}/{s.get('port')} | {_fmt_ts(s.get('first_seen'))} "
                         f"| {_fmt_ts(s.get('last_seen'))} | {s.get('hits', 0)} |")
    lines.append("")
    lines.append("## Alerts")
    lines.append("")
    if r.get("alerts"):
        for a in r["alerts"]:
            lines.append(f"- **{str(a.get('severity', '')).upper()}** {a.get('title')} "
                         f"({_fmt_ts(a.get('ts'))})")
            lines.append(f"  - Evidence: {a.get('evidence')}")
            lines.append(f"  - Action: {a.get('action')}")
    else:
        lines.append("- No alerts recorded for this address.")
    lines.append("")
    lines.append("## Recommended actions")
    lines.append("")
    for x in r.get("recommendations") or []:
        lines.append(f"- {x}")
    lines.append("")
    lines.append("## Method and limits")
    lines.append("")
    lines.append(f"- Enrichment sources used: {', '.join(r.get('sources_used') or []) or 'none'}")
    lines.append(f"- Unavailable: {', '.join(r.get('sources_missing') or []) or 'none'}")
    lines.append("- Geolocation is opt-in and sends the address to a third-party "
                 "resolver; when it is off, country/city fields are empty by design.")
    lines.append("- Purpose and reputation are indicators. Legitimate shared "
                 "infrastructure (CDNs, cloud providers) and misclassification are "
                 "common and must be excluded before any escalation.")
    lines.append(f"- {r.get('note')}")
    lines.append("")
    return "\n".join(lines)
