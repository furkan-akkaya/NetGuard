"""ARP spoofing / ARP cache poisoning detection.

ARP has no authentication: any host can claim "IP X is at MAC Y". An attacker
who claims the gateway's IP receives the victims' traffic (man-in-the-middle).

The detector learns IP -> MAC bindings from ARP traffic and alerts when a known
IP is suddenly claimed by a different MAC. Extra context that raises suspicion:

* the reply was *unsolicited* (nobody asked for that IP recently),
* the binding keeps *flip-flopping* between MACs (the real owner and the
  attacker fight over the IP), and
* the IP is listed in ``critical_ips`` (e.g. the default gateway).

Known benign causes of a binding change: DHCP handing the IP to a new device,
VRRP/HSRP/CARP failover, NIC replacement, VM migration. They usually change the
binding once and do not flip back, which is why flip-flops are highlighted.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field

from netguard.config import Config
from netguard.detectors.base import Detector
from netguard.models import UNSPECIFIED_IPV4, Alert, Packet, Severity, Technique

T1557_002 = Technique("T1557.002", "Adversary-in-the-Middle: ARP Cache Poisoning")

ARP_REQUEST, ARP_REPLY = 1, 2
REQUEST_MEMORY_SECONDS = 5.0  # how long an ARP request "solicits" a reply
MAX_TRACKED_IPS = 65_536  # memory bound against floods of forged sender IPs


@dataclass
class Binding:
    mac: str
    owner: str  # the first MAC ever seen for this IP: our best guess at the legitimate owner
    first_seen: float
    last_seen: float
    changes: int = 0
    macs_seen: set[str] = field(default_factory=set)


class ArpSpoofDetector(Detector):
    name = "arpspoof"

    def __init__(self, config: Config) -> None:
        self.cfg = config.arpspoof
        self.critical = set(self.cfg.critical_ips)
        self.bindings: dict[str, Binding] = {}
        self._last_request: dict[str, float] = {}  # target IP -> ts of last who-has
        self._last_alert: dict[str, tuple[float, Severity]] = {}  # ip -> (ts, severity)

    def on_packet(self, pkt: Packet) -> Iterable[Alert]:
        if pkt.proto != "arp" or pkt.arp_sender_ip is None or pkt.arp_sender_mac is None:
            return ()
        ip, mac, ts = pkt.arp_sender_ip, pkt.arp_sender_mac, pkt.ts

        if pkt.arp_op == ARP_REQUEST and pkt.arp_target_ip:
            if len(self._last_request) >= MAX_TRACKED_IPS:
                self._last_request = {k: v for k, v in self._last_request.items() if ts - v <= REQUEST_MEMORY_SECONDS}
            self._last_request[pkt.arp_target_ip] = ts
        if ip == UNSPECIFIED_IPV4 or mac in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"):
            return ()

        binding = self.bindings.get(ip)
        if binding is None:
            if len(self.bindings) >= MAX_TRACKED_IPS:
                return ()
            self.bindings[ip] = Binding(mac=mac, owner=mac, first_seen=ts, last_seen=ts, macs_seen={mac})
            return ()
        if binding.mac == mac:
            binding.last_seen = ts
            return ()

        old_mac, old_since = binding.mac, binding.first_seen
        binding.changes += 1
        binding.macs_seen.add(mac)
        binding.mac, binding.first_seen, binding.last_seen = mac, ts, ts

        alert = self._alert(pkt, ip, old_mac, old_since, binding)
        # One alert per IP per realert period, unless the situation escalates.
        # An active MITM rewrites the binding every few seconds; without this the
        # analyst would get an alert per poisoned packet.
        last = self._last_alert.get(ip)
        if last is not None and ts - last[0] < self.cfg.realert_seconds and alert.severity <= last[1]:
            return ()
        self._last_alert[ip] = (ts, alert.severity)
        return [alert]

    def _alert(self, pkt: Packet, ip: str, old_mac: str, old_since: float, b: Binding) -> Alert:
        requested = self._last_request.get(ip)
        unsolicited = pkt.arp_op == ARP_REPLY and (requested is None or pkt.ts - requested > REQUEST_MEMORY_SECONDS)
        gratuitous = pkt.arp_target_ip == ip
        flip_flop = b.changes >= 2  # A->B->A (fight over the IP) or A->B->C
        critical = ip in self.critical

        reasons = []
        if critical:
            reasons.append("IP is marked critical")
        if flip_flop:
            reasons.append(f"binding changed {b.changes} times between {len(b.macs_seen)} MACs")
        if unsolicited:
            reasons.append("unsolicited ARP reply")
        if gratuitous:
            reasons.append("gratuitous ARP")

        # The suspect is whoever is *not* the original owner. When the binding
        # reverts to the owner, the suspect is the MAC it reverted from.
        reverted = b.mac == b.owner
        suspect = old_mac if reverted else b.mac
        severity = Severity.HIGH if critical or flip_flop else Severity.MEDIUM
        if reverted:
            head = f"IP {ip} reverted to its original MAC {b.owner} after being claimed by {suspect}"
        else:
            head = f"IP {ip} moved from MAC {old_mac} (held for {pkt.ts - old_since:.1f}s) to {b.mac}"
        summary = head + (f" — {'; '.join(reasons)}." if reasons else ".")
        return Alert(
            detector=self.name,
            title="ARP binding change (possible ARP spoofing)",
            severity=severity,
            first_seen=pkt.ts,
            last_seen=pkt.ts,
            src=suspect,
            dst=ip,
            technique=T1557_002,
            summary=summary,
            evidence={
                "ip": ip,
                "previous_mac": old_mac,
                "new_mac": b.mac,
                "original_mac": b.owner,
                "suspect_mac": suspect,
                "previous_binding_age_seconds": round(pkt.ts - old_since, 3),
                "binding_changes": b.changes,
                "macs_seen": sorted(b.macs_seen),
                "unsolicited_reply": unsolicited,
                "gratuitous": gratuitous,
                "critical_ip": critical,
                "arp_op": "reply" if pkt.arp_op == ARP_REPLY else "request",
            },
        )
