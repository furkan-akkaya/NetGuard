"""Traffic statistics and bidirectional flow tracking.

A *flow* is the set of packets sharing a 5-tuple (protocol, IP/port pairs),
regardless of direction. Flows are the unit future detectors (beaconing, data
exfiltration, long-lived connections) will operate on.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from typing import Any

from netguard.models import Packet

Endpoint = tuple[str, int]
FlowKey = tuple[str, Endpoint, Endpoint]


def flow_key(pkt: Packet) -> FlowKey | None:
    if pkt.src_ip is None or pkt.dst_ip is None:
        return None
    a: Endpoint = (pkt.src_ip, pkt.src_port or 0)
    b: Endpoint = (pkt.dst_ip, pkt.dst_port or 0)
    # Canonical ordering makes A->B and B->A map to the same flow.
    return (pkt.proto, a, b) if a <= b else (pkt.proto, b, a)


@dataclass
class Flow:
    initiator: str
    first_seen: float
    last_seen: float
    packets: int = 0
    bytes: int = 0


@dataclass
class TrafficStats:
    flow_idle_timeout: float = 120.0
    max_flows: int = 200_000
    packets: int = 0
    bytes: int = 0
    decode_errors: int = 0
    first_ts: float | None = None
    last_ts: float | None = None
    protocols: Counter[str] = field(default_factory=Counter)
    bytes_by_ip: Counter[str] = field(default_factory=Counter)
    flows_total: int = 0
    flows_dropped: int = 0
    _active: dict[FlowKey, Flow] = field(default_factory=dict)

    def add(self, pkt: Packet) -> None:
        self.packets += 1
        self.bytes += pkt.length
        self.protocols[pkt.proto] += 1
        if self.first_ts is None:
            self.first_ts = pkt.ts
        self.last_ts = pkt.ts
        if pkt.src_ip is not None:
            self.bytes_by_ip[pkt.src_ip] += pkt.length

        key = flow_key(pkt)
        if key is None:
            return
        flow = self._active.get(key)
        if flow is not None and pkt.ts - flow.last_seen > self.flow_idle_timeout:
            flow = None  # same 5-tuple after a long pause counts as a new flow
        if flow is None:
            if len(self._active) >= self.max_flows:
                self.expire(pkt.ts)
                if len(self._active) >= self.max_flows:
                    self.flows_dropped += 1
                    return
            assert pkt.src_ip is not None
            flow = self._active[key] = Flow(initiator=pkt.src_ip, first_seen=pkt.ts, last_seen=pkt.ts)
            self.flows_total += 1
        flow.packets += 1
        flow.bytes += pkt.length
        flow.last_seen = pkt.ts

    def expire(self, now: float) -> None:
        stale = [k for k, f in self._active.items() if now - f.last_seen > self.flow_idle_timeout]
        for k in stale:
            del self._active[k]

    @property
    def duration(self) -> float:
        if self.first_ts is None or self.last_ts is None:
            return 0.0
        return self.last_ts - self.first_ts

    def to_dict(self, top: int = 5) -> dict[str, Any]:
        return {
            "packets": self.packets,
            "bytes": self.bytes,
            "decode_errors": self.decode_errors,
            "duration_seconds": round(self.duration, 3),
            "flows": self.flows_total,
            "flows_dropped": self.flows_dropped,
            "protocols": dict(self.protocols.most_common()),
            "top_talkers": [{"ip": ip, "bytes": b} for ip, b in self.bytes_by_ip.most_common(top)],
        }
