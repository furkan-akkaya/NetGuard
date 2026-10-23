"""Bursts of non-existent domain lookups (NXDOMAIN): a DGA indicator.

Malware with a domain generation algorithm (DGA) computes hundreds of
candidate C2 domains per day and tries them until one resolves; almost all
lookups fail with NXDOMAIN. The signal is **many distinct names answered with
NXDOMAIN to one client** within a window, observed in resolver *responses*
(so it works whichever resolver the client uses, as long as the sensor sees
the replies).

Benign causes are real and common: a wrong DNS search suffix (every lookup is
first tried as ``name.corp.example``), typos, broken software retrying with
variants, ad/tracker blockers that answer NXDOMAIN on purpose, and Chrome's
intranet-redirect probes (three random 7-15 letter names at start-up). The
evidence therefore includes how many *registered domains* the failed names
span and their entropy: a search-suffix problem concentrates on one or two
domains with readable names; a DGA spreads over many random-looking ones.
"""

from __future__ import annotations

from collections.abc import Iterable

from netguard.config import Config
from netguard.detectors.base import Detector, RuleInfo, as_early
from netguard.dns import RCODE_NXDOMAIN, registered_domain, shannon_entropy
from netguard.models import Alert, Packet, Severity, Technique
from netguard.window import BurstTracker, Incident

T1568_002 = Technique("T1568.002", "Dynamic Resolution: Domain Generation Algorithms")
RULE_ID = "NG-DNS-002"


class NxdomainDetector(Detector):
    name = "nxdomain"
    packet_protos = frozenset({"udp"})
    rules = (RuleInfo(RULE_ID, "Burst of failed DNS lookups (possible DGA)", T1568_002),)
    counters = ("tracker.evicted_keys",)

    def __init__(self, config: Config) -> None:
        self.cfg = config.nxdomain
        self.global_cfg = config
        self.tracker: BurstTracker[str, str] = BurstTracker(
            window=self.cfg.window_seconds,
            threshold=self.cfg.min_distinct_names,
            idle_timeout=self.cfg.idle_timeout_seconds,
            max_keys=self.cfg.max_keys,
            max_age=config.alerts.max_incident_age_seconds,
            track_opened=config.alerts.early_warning,
        )

    def on_packet(self, pkt: Packet) -> Iterable[Alert]:
        dns = pkt.dns
        if dns is None or not dns.response or dns.rcode != RCODE_NXDOMAIN or dns.qname is None:
            return ()
        client, resolver = pkt.dst_ip, pkt.src_ip
        if client is None or resolver is None or self.global_cfg.is_allowlisted(client):
            return ()
        self.tracker.observe(client, pkt.ts, dns.qname, resolver)
        return ()

    def tick(self, now: float) -> Iterable[Alert]:
        early = as_early(self._alert(inc) for inc in self.tracker.take_opened())
        return early + [self._alert(inc) for inc in self.tracker.expire(now)]

    def flush(self) -> Iterable[Alert]:
        return [self._alert(inc) for inc in self.tracker.drain()]

    def _alert(self, inc: Incident[str, str]) -> Alert:
        names = sorted(inc.items)
        domains = {registered_domain(n) for n in names}
        # The leftmost label is the generated part of a DGA name ("kq3vz7x.com")
        # and the typed part of a search-suffix failure ("intranet.corp.example").
        labels = [n.split(".")[0] for n in names]
        entropy = sum(map(shannon_entropy, labels)) / len(labels) if labels else 0.0
        mean_len = sum(map(len, labels)) / len(labels) if labels else 0.0
        distinct = inc.distinct_items
        resolvers = ", ".join(sorted(inc.tags))
        spread = len(domains) / len(names) if names else 0.0
        summary = (
            f"{inc.key} received NXDOMAIN (non-existent domain) for {distinct} distinct names in "
            f"{inc.duration:.0f}s (threshold: {self.cfg.min_distinct_names} within {self.cfg.window_seconds:g}s) "
            f"from resolver {resolvers}. The names span {len(domains)} registered "
            f"domain{'' if len(domains) == 1 else 's'}; "
            f"their leftmost label averages {mean_len:.1f} characters at {entropy:.2f} bits/char."
        )
        if spread >= 0.8:
            summary += " Nearly every name is a different domain, as produced by domain generation algorithms (DGA)."
        elif len(domains) <= 2:
            summary += " The names share one or two domains, which also fits a wrong DNS search suffix."
        return Alert(
            detector=self.name,
            rule_id=RULE_ID,
            title=self.rules[0].title,
            severity=Severity.HIGH if distinct >= self.cfg.high_severity_names else Severity.MEDIUM,
            first_seen=inc.first_seen,
            last_seen=inc.last_seen,
            src=inc.key,
            dst=None,
            technique=T1568_002,
            summary=summary,
            evidence={
                "distinct_names": distinct,
                "responses": inc.events,
                "registered_domains": len(domains),
                "domain_spread": round(spread, 3),
                "mean_label_length": round(mean_len, 1),
                "mean_entropy_bits_per_char": round(entropy, 2),
                "resolvers": dict(inc.tags),
                "sample_names": names[:15],
                "threshold": {
                    "min_distinct_names": self.cfg.min_distinct_names,
                    "window_seconds": self.cfg.window_seconds,
                },
            },
        )
