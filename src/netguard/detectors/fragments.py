"""IP fragmentation used for evasion (``nmap -f``, fragroute): tiny and header-splitting fragments.

An IDS that inspects packets one at a time cannot see a TCP header that is
split across fragments; RFC 1858 describes the two classic tricks:

* **tiny first fragment**: the first fragment is too small to hold the whole
  TCP (or UDP) header, so flags and ports are not in it. ``nmap -f`` sends
  8-byte fragments for exactly this reason;
* **TCP fragment at offset 8**: a later fragment that starts inside the TCP
  header (8 bytes in). Either the header is split across fragments, or, if
  an earlier fragment already covered those bytes, it *overwrites* header
  fields such as the flags after a filter inspected the first fragment
  (the RFC 1858 overlap attack). Both are reported as ``tcp_header_split``.

Real fragmentation happens at the path MTU (at least 576 bytes in practice),
so a non-final fragment much smaller than that (``small_fragment_bytes``) is
suspicious on its own. NetGuard does not reassemble fragments, so the probes
inside them are invisible to the other rules; this rule makes the evasion
attempt itself visible instead. IPv6 fragments are not covered yet.
"""

from __future__ import annotations

from collections import Counter, OrderedDict
from collections.abc import Iterable
from dataclasses import dataclass, field

from netguard.config import Config
from netguard.detectors.base import Detector, RuleInfo, as_early
from netguard.models import Alert, Packet, Severity, Technique

T1599 = Technique("T1599", "Network Boundary Bridging")
RULE_ID = "NG-FRAG-001"
_L4_PROTOS = frozenset({6, 17})  # TCP, UDP
_PROTO_NAMES = {6: "TCP", 17: "UDP", 1: "ICMP"}

Key = tuple[str, str]


@dataclass
class _Incident:
    first_seen: float
    last_seen: float
    kinds: Counter[str] = field(default_factory=Counter)
    protocols: Counter[str] = field(default_factory=Counter)
    smallest: int | None = None


class FragmentDetector(Detector):
    name = "fragments"
    packet_protos = frozenset({"ip-frag", "ip-other", "tcp", "udp", "icmp"})
    rules = (RuleInfo(RULE_ID, "Suspicious IP fragmentation (possible IDS evasion)", T1599),)
    counters = ("evicted",)

    def __init__(self, config: Config) -> None:
        self.cfg = config.fragments
        self.global_cfg = config
        self._incidents: OrderedDict[Key, _Incident] = OrderedDict()  # least recently updated first
        self.evicted = 0
        self.early_warning = config.alerts.early_warning
        self.max_age = config.alerts.max_incident_age_seconds
        self._opened: list[Key] = []  # incidents that just reached min_fragments

    def _kind(self, pkt: Packet) -> str | None:
        size = pkt.payload_len if pkt.payload_len is not None else 0
        # A first TCP/UDP fragment that did not decode as TCP/UDP is too short
        # to hold the transport header (the decoder needs the whole header).
        if pkt.frag_offset == 0 and pkt.frag_more and pkt.ip_proto in _L4_PROTOS and pkt.proto not in ("tcp", "udp"):
            return "tiny_first_fragment"
        if pkt.frag_offset == 8 and pkt.ip_proto == 6:
            return "tcp_header_split"
        if pkt.frag_more and size < self.cfg.small_fragment_bytes:
            return "small_fragment"
        return None

    def on_packet(self, pkt: Packet) -> Iterable[Alert]:
        if not pkt.fragment or pkt.src_ip is None or pkt.dst_ip is None:
            return ()
        kind = self._kind(pkt)
        if kind is None or self.global_cfg.is_allowlisted(pkt.src_ip):
            return ()
        key = (pkt.src_ip, pkt.dst_ip)
        inc = self._incidents.get(key)
        if inc is None:
            if len(self._incidents) >= self.cfg.max_keys:
                self._incidents.popitem(last=False)
                self.evicted += 1
            inc = self._incidents[key] = _Incident(first_seen=pkt.ts, last_seen=pkt.ts)
        else:
            self._incidents.move_to_end(key)
        inc.last_seen = max(inc.last_seen, pkt.ts)
        inc.kinds[kind] += 1
        if self.early_warning and sum(inc.kinds.values()) == self.cfg.min_fragments:
            self._opened.append(key)
        assert pkt.ip_proto is not None
        inc.protocols[_PROTO_NAMES.get(pkt.ip_proto, str(pkt.ip_proto))] += 1
        size = pkt.payload_len or 0
        inc.smallest = size if inc.smallest is None else min(inc.smallest, size)
        return ()

    def tick(self, now: float) -> Iterable[Alert]:
        opened, self._opened = self._opened, []
        alerts = as_early(a for k in opened if k in self._incidents for a in self._report(k, self._incidents[k]))
        while self._incidents:
            key, inc = next(iter(self._incidents.items()))
            if now - inc.last_seen <= self.cfg.idle_timeout_seconds:
                break
            del self._incidents[key]
            alerts += self._report(key, inc)
        # Long-running activity: close incidents past the maximum age (at most max_keys of them).
        for key in [k for k, inc in self._incidents.items() if now - inc.first_seen > self.max_age]:
            alerts += self._report(key, self._incidents.pop(key))
        return alerts

    def flush(self) -> Iterable[Alert]:
        alerts = [a for key, inc in self._incidents.items() for a in self._report(key, inc)]
        self._incidents.clear()
        return alerts

    def _report(self, key: Key, inc: _Incident) -> list[Alert]:
        total = sum(inc.kinds.values())
        if total < self.cfg.min_fragments:
            return []
        src, dst = key
        kinds = ", ".join(f"{k}={n}" for k, n in inc.kinds.most_common())
        protos = ", ".join(f"{p}={n}" for p, n in inc.protocols.most_common())
        summary = (
            f"{src} sent {total} suspicious IP fragments to {dst} in {inc.last_seen - inc.first_seen:.1f}s "
            f"(threshold: {self.cfg.min_fragments}). Kinds: {kinds}. Protocols: {protos}. Smallest fragment "
            f"payload: {inc.smallest} bytes (real fragmentation splits at the path MTU, >= 576 bytes in practice)."
        )
        if inc.kinds.get("tiny_first_fragment") or inc.kinds.get("tcp_header_split"):
            summary += (
                " Transport headers are split across fragments (RFC 1858), a technique to slip probes past "
                "packet filters and IDSs such as `nmap -f`; NetGuard does not reassemble them, so the probes "
                "inside are not analysed by the other rules."
            )
        return [
            Alert(
                detector=self.name,
                rule_id=RULE_ID,
                title=self.rules[0].title,
                severity=Severity.HIGH if total >= self.cfg.high_severity_fragments else Severity.MEDIUM,
                first_seen=inc.first_seen,
                last_seen=inc.last_seen,
                src=src,
                dst=dst,
                technique=T1599,
                summary=summary,
                evidence={
                    "suspicious_fragments": total,
                    "kinds": dict(inc.kinds),
                    "protocols": dict(inc.protocols),
                    "smallest_fragment_payload_bytes": inc.smallest,
                    "threshold": {
                        "min_fragments": self.cfg.min_fragments,
                        "small_fragment_bytes": self.cfg.small_fragment_bytes,
                    },
                },
            )
        ]
