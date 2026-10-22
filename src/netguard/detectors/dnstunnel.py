"""DNS tunnelling indicators: many long, unique subdomains of one domain from one client.

DNS tunnels (iodine, dnscat2, DNSExfiltrator, Cobalt Strike DNS beacons)
encode data in query names, ``<encoded-chunk>.t.attacker.example``, and the
attacker's authoritative server decodes it. Every chunk is new, so the client
queries a stream of **distinct, long, high-entropy subdomains under one
registered domain**, which ordinary browsing rarely does.

Signal, per ``(client, registered domain)`` in a sliding window:

* distinct subdomains ``>= min_distinct_subdomains`` opens an incident;
* the incident is reported only if the mean subdomain length is
  ``>= min_mean_subdomain_length``; short random-looking names (CDN shards,
  ``e1234.akamaiedge.net``) are dropped.

Entropy, the longest label and the TXT/NULL/CNAME share (record types tunnels
prefer, because they carry more downstream data) are reported as evidence and
raise severity. Registered domains are approximated (see
``dns.registered_domain``), so a tunnel under a multi-level public suffix may
be keyed one level too high; that only merges keys, it does not hide a tunnel.
"""

from __future__ import annotations

from collections.abc import Iterable

from netguard.config import Config
from netguard.detectors.base import Detector, RuleInfo, as_early
from netguard.dns import registered_domain, shannon_entropy
from netguard.models import Alert, Packet, Severity, Technique
from netguard.window import BurstTracker, Incident

T1071_004 = Technique("T1071.004", "Application Layer Protocol: DNS")
RULE_ID = "NG-DNS-001"
TUNNEL_QTYPES = frozenset({"TXT", "NULL", "CNAME", "MX"})

Key = tuple[str, str]  # (client, registered domain)


class DnsTunnelDetector(Detector):
    name = "dnstunnel"
    packet_protos = frozenset({"udp"})
    rules = (RuleInfo(RULE_ID, "Possible DNS tunnelling", T1071_004),)

    def __init__(self, config: Config) -> None:
        self.cfg = config.dnstunnel
        self.global_cfg = config
        self.tracker: BurstTracker[Key, str] = BurstTracker(
            window=self.cfg.window_seconds,
            threshold=self.cfg.min_distinct_subdomains,
            idle_timeout=self.cfg.idle_timeout_seconds,
            max_keys=self.cfg.max_keys,
            max_age=config.alerts.max_incident_age_seconds,
            track_opened=config.alerts.early_warning,
        )
        self.suppressed = 0

    def on_packet(self, pkt: Packet) -> Iterable[Alert]:
        name = pkt.dns_query
        if name is None or pkt.src_ip is None or self.global_cfg.is_allowlisted(pkt.src_ip):
            return ()
        domain = registered_domain(name)
        if len(name) <= len(domain) + 1:
            return ()  # no subdomain part
        assert pkt.dns is not None
        sub = name[: -len(domain) - 1]
        self.tracker.observe((pkt.src_ip, domain), pkt.ts, sub, pkt.dns.qtype_name or "?")
        return ()

    def tick(self, now: float) -> Iterable[Alert]:
        early = as_early(self._report(self.tracker.take_opened()))
        return early + self._report(self.tracker.expire(now))

    def flush(self) -> Iterable[Alert]:
        return self._report(self.tracker.drain())

    def _report(self, incidents: list[Incident[Key, str]]) -> list[Alert]:
        alerts = []
        for inc in incidents:
            alert = self._alert(inc)
            if alert is None:
                self.suppressed += 1
            else:
                alerts.append(alert)
        return alerts

    def _alert(self, inc: Incident[Key, str]) -> Alert | None:
        client, domain = inc.key
        subs = sorted(inc.items)
        if not subs:
            return None
        mean_len = sum(map(len, subs)) / len(subs)
        if mean_len < self.cfg.min_mean_subdomain_length:
            return None
        entropy = sum(shannon_entropy(s.replace(".", "")) for s in subs) / len(subs)
        longest_label = max(len(label) for s in subs for label in s.split("."))
        queries = sum(inc.tags.values())
        tunnel_types = sum(n for t, n in inc.tags.items() if t in TUNNEL_QTYPES)
        tunnel_share = tunnel_types / queries if queries else 0.0
        distinct = inc.distinct_items
        high = distinct >= self.cfg.high_severity_subdomains or tunnel_share >= 0.5
        qtypes = ", ".join(f"{t}={n}" for t, n in inc.tags.most_common())

        summary = (
            f"{client} queried {distinct} distinct subdomains of {domain} in {inc.duration:.0f}s "
            f"(threshold: {self.cfg.min_distinct_subdomains} within {self.cfg.window_seconds:g}s). "
            f"Mean subdomain length {mean_len:.1f} characters (threshold {self.cfg.min_mean_subdomain_length:g}), "
            f"longest label {longest_label}, mean entropy {entropy:.2f} bits/char. Query types: {qtypes}. "
            f"This pattern is consistent with data encoded in DNS names (tunnelling or exfiltration); "
            f"some security and telemetry products also encode lookups this way."
        )
        return Alert(
            detector=self.name,
            rule_id=RULE_ID,
            title=self.rules[0].title,
            severity=Severity.HIGH if high else Severity.MEDIUM,
            first_seen=inc.first_seen,
            last_seen=inc.last_seen,
            src=client,
            dst=domain,
            technique=T1071_004,
            summary=summary,
            evidence={
                "registered_domain": domain,
                "distinct_subdomains": distinct,
                "queries": queries,
                "mean_subdomain_length": round(mean_len, 1),
                "longest_label": longest_label,
                "mean_entropy_bits_per_char": round(entropy, 2),
                "query_types": dict(inc.tags),
                "tunnel_record_type_share": round(tunnel_share, 3),
                "sample_names": [f"{s}.{domain}" for s in subs[:10]],
                "threshold": {
                    "min_distinct_subdomains": self.cfg.min_distinct_subdomains,
                    "window_seconds": self.cfg.window_seconds,
                    "min_mean_subdomain_length": self.cfg.min_mean_subdomain_length,
                },
            },
        )
