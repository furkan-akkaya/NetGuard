"""Traffic statistics: capture totals, distributions, time series and endpoints.

Everything here is bounded in memory regardless of capture size, because a
statistic that grows with the number of distinct IPs is a denial-of-service
vector (one spoofed-source flood and the analyzer runs out of RAM):

* protocol, packet-size and connection-state counters have a fixed key space;
* the time series doubles its bucket width when it would exceed
  ``max_buckets`` (downsampling instead of growing);
* endpoint accounting keeps at most ``max_endpoints`` IPs. When it overflows
  it prunes to the heaviest half by bytes and marks itself ``approximate``, so
  top-talker numbers are exact for the heavy hitters that matter and the
  report says when the tail was dropped.

Per-packet work is O(1). Flow-level statistics are updated once per *finished*
flow (see :meth:`TrafficStats.add_flow`), not per packet.
"""

from __future__ import annotations

import heapq
from collections import Counter
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from netguard.flows import Flow
from netguard.models import Packet, iso_ts

# Wireshark's "Packet Lengths" buckets (upper bounds, inclusive). Frame length
# here is the *captured* length, which is smaller than the wire length when the
# capture used a short snaplen.
SIZE_BUCKETS = (64, 128, 256, 512, 1024, 1518)
SIZE_LABELS = ("0-64", "65-128", "129-256", "257-512", "513-1024", "1025-1518", "1519+")
#: Detector counters with these prefixes count detection state dropped by a full table.
LOSS_PREFIXES = ("evicted", "untracked")


def state_losses(detector_counters: Mapping[str, Mapping[str, int]]) -> dict[str, int]:
    """Detectors that dropped detection state under memory pressure: name -> items lost."""
    losses = {
        name: sum(v for k, v in counters.items() if k.startswith(LOSS_PREFIXES))
        for name, counters in detector_counters.items()
    }
    return {name: n for name, n in losses.items() if n}


@dataclass(slots=True)
class Endpoint:
    packets_sent: int = 0
    packets_received: int = 0
    bytes_sent: int = 0
    bytes_received: int = 0
    flows_originated: int = 0
    flows_responded: int = 0

    @property
    def total_bytes(self) -> int:
        return self.bytes_sent + self.bytes_received


@dataclass
class TimeSeries:
    """Packets and bytes per time bucket, with a hard cap on bucket count."""

    max_buckets: int = 1440
    width: float = 1.0
    buckets: dict[float, list[int]] = field(default_factory=dict)  # start -> [packets, bytes]

    def add(self, ts: float, length: int) -> None:
        start = (ts // self.width) * self.width
        cell = self.buckets.get(start)
        if cell is None:
            if len(self.buckets) >= self.max_buckets:
                self._downsample()
                start = (ts // self.width) * self.width
                cell = self.buckets.get(start)
            if cell is None:
                cell = self.buckets[start] = [0, 0]
        cell[0] += 1
        cell[1] += length

    def _downsample(self) -> None:
        self.width *= 2
        merged: dict[float, list[int]] = {}
        for start, (pkts, nbytes) in self.buckets.items():
            cell = merged.setdefault((start // self.width) * self.width, [0, 0])
            cell[0] += pkts
            cell[1] += nbytes
        self.buckets = merged

    def to_list(self) -> list[dict[str, Any]]:
        return [
            {"start": iso_ts(start), "packets": pkts, "bytes": nbytes}
            for start, (pkts, nbytes) in sorted(self.buckets.items())
        ]


@dataclass
class TrafficStats:
    max_endpoints: int = 10_000
    top_n: int = 10
    packets: int = 0
    bytes: int = 0
    decode_errors: int = 0
    first_ts: float | None = None
    last_ts: float | None = None
    protocols: Counter[str] = field(default_factory=Counter)
    unsupported_linktypes: Counter[int] = field(default_factory=Counter)
    fragments: int = 0
    sizes: list[int] = field(default_factory=lambda: [0] * len(SIZE_LABELS))
    timeseries: TimeSeries = field(default_factory=TimeSeries)
    # Flow-level aggregates, updated when a flow ends.
    flows_total: int = 0
    flows_evicted: int = 0
    conn_states: Counter[str] = field(default_factory=Counter)
    services: Counter[str] = field(default_factory=Counter)  # "tcp/443" -> flows
    retransmissions: int = 0
    endpoints: dict[str, Endpoint] = field(default_factory=dict)
    endpoints_approximate: bool = False
    _top_flows: list[tuple[int, int, Flow]] = field(default_factory=list)
    # Detector name -> Detector.counters values, filled in at the end of an analysis.
    detector_counters: dict[str, dict[str, int]] = field(default_factory=dict)

    def add(self, pkt: Packet) -> None:
        self.packets += 1
        self.bytes += pkt.length
        self.protocols[pkt.proto] += 1
        if self.first_ts is None:
            self.first_ts = pkt.ts
        self.last_ts = pkt.ts
        if pkt.fragment:
            self.fragments += 1
        for i, upper in enumerate(SIZE_BUCKETS):
            if pkt.length <= upper:
                self.sizes[i] += 1
                break
        else:
            self.sizes[-1] += 1
        self.timeseries.add(pkt.ts, pkt.length)

    def add_flow(self, flow: Flow) -> None:
        self.flows_total += 1
        if flow.end_reason == "evicted":
            self.flows_evicted += 1
        self.conn_states[flow.state] += 1
        if flow.proto in ("tcp", "udp"):
            self.services[f"{flow.proto}/{flow.dst_port}"] += 1
        self.retransmissions += flow.retransmissions

        orig = self._endpoint(flow.src_ip)
        orig.flows_originated += 1
        orig.packets_sent += flow.orig_packets
        orig.bytes_sent += flow.orig_bytes
        orig.packets_received += flow.resp_packets
        orig.bytes_received += flow.resp_bytes
        resp = self._endpoint(flow.dst_ip)
        resp.flows_responded += 1
        resp.packets_sent += flow.resp_packets
        resp.bytes_sent += flow.resp_bytes
        resp.packets_received += flow.orig_packets
        resp.bytes_received += flow.orig_bytes

        # Min-heap of the N largest flows; the counter breaks ties deterministically.
        entry = (flow.bytes, -self.flows_total, flow)
        if len(self._top_flows) < self.top_n:
            heapq.heappush(self._top_flows, entry)
        elif entry[:2] > self._top_flows[0][:2]:
            heapq.heapreplace(self._top_flows, entry)

    def _endpoint(self, ip: str) -> Endpoint:
        ep = self.endpoints.get(ip)
        if ep is None:
            if len(self.endpoints) >= self.max_endpoints:
                keep = sorted(self.endpoints.items(), key=lambda kv: kv[1].total_bytes, reverse=True)
                self.endpoints = dict(keep[: self.max_endpoints // 2])
                self.endpoints_approximate = True
            ep = self.endpoints[ip] = Endpoint()
        return ep

    def state_losses(self) -> dict[str, int]:
        return state_losses(self.detector_counters)

    @property
    def duration(self) -> float:
        if self.first_ts is None or self.last_ts is None:
            return 0.0
        return self.last_ts - self.first_ts

    def top_endpoints(self, n: int | None = None) -> list[tuple[str, Endpoint]]:
        ranked = sorted(self.endpoints.items(), key=lambda kv: (-kv[1].total_bytes, kv[0]))
        return ranked[: n or self.top_n]

    def top_flows(self) -> list[Flow]:
        return [f for _, _, f in sorted(self._top_flows, key=lambda e: e[:2], reverse=True)]

    def to_dict(self) -> dict[str, Any]:
        return {
            "packets": self.packets,
            "bytes": self.bytes,
            "decode_errors": self.decode_errors,
            "unsupported_linktype_frames": {str(k): v for k, v in sorted(self.unsupported_linktypes.items())},
            "fragments": self.fragments,
            "first_seen": iso_ts(self.first_ts) if self.first_ts is not None else None,
            "last_seen": iso_ts(self.last_ts) if self.last_ts is not None else None,
            "duration_seconds": round(self.duration, 3),
            "protocols": dict(self.protocols.most_common()),
            "packet_sizes": dict(zip(SIZE_LABELS, self.sizes, strict=True)),
            "timeseries": {"bucket_seconds": self.timeseries.width, "buckets": self.timeseries.to_list()},
            "flows": {
                "total": self.flows_total,
                "evicted": self.flows_evicted,
                "states": dict(self.conn_states.most_common()),
                "retransmissions": self.retransmissions,
                "top_services": [{"service": s, "flows": n} for s, n in self.services.most_common(self.top_n)],
                "top_by_bytes": [f.to_dict() for f in self.top_flows()],
            },
            "detectors": self.detector_counters,
            "endpoints": {
                "approximate": self.endpoints_approximate,
                "top_by_bytes": [
                    {
                        "ip": ip,
                        "bytes_sent": ep.bytes_sent,
                        "bytes_received": ep.bytes_received,
                        "packets_sent": ep.packets_sent,
                        "packets_received": ep.packets_received,
                        "flows_originated": ep.flows_originated,
                        "flows_responded": ep.flows_responded,
                    }
                    for ip, ep in self.top_endpoints()
                ],
            },
        }
