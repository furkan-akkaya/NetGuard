"""The analysis engine: drives packets through flows, statistics and detectors.

Per packet: decode -> statistics -> flow table -> detectors' ``on_packet``.
Flows that end (closed, idle, evicted, or end of input) go to the statistics,
to the detectors' ``on_flow_end`` and to the optional ``on_flow`` callback.
All timing uses capture timestamps, never the wall clock, so an offline run is
deterministic: the same pcap and config always produce the same output.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass, field

from netguard.config import Config
from netguard.decode import UnsupportedLinkType, decode
from netguard.detectors import Detector, build_detectors
from netguard.flows import Flow, FlowTable
from netguard.models import Alert, Packet
from netguard.stats import TrafficStats

TICK_SECONDS = 1.0  # how often (in capture time) detectors may close incidents and flows expire


@dataclass
class AnalysisResult:
    stats: TrafficStats
    alerts: list[Alert] = field(default_factory=list)


class Engine:
    def __init__(
        self,
        config: Config | None = None,
        detectors: list[Detector] | None = None,
        on_alert: Callable[[Alert], None] | None = None,
        on_flow: Callable[[Flow], None] | None = None,
    ) -> None:
        self.config = config or Config()
        self.detectors = detectors if detectors is not None else build_detectors(self.config)
        self.stats = TrafficStats()
        self.flows = FlowTable(self.config.flows)
        self.alerts: list[Alert] = []
        self._on_alert = on_alert
        self._on_flow = on_flow
        self._next_tick: float | None = None

    def _emit(self, alerts: Iterable[Alert]) -> None:
        for alert in alerts:
            self.alerts.append(alert)
            if self._on_alert:
                self._on_alert(alert)

    def _end_flows(self, flows: Iterable[Flow]) -> None:
        for flow in flows:
            self.stats.add_flow(flow)
            for det in self.detectors:
                self._emit(det.on_flow_end(flow))
            if self._on_flow:
                self._on_flow(flow)

    def process(self, pkt: Packet) -> None:
        # Tick *before* handing the packet to detectors: an incident that has been
        # idle must be closed first, otherwise this packet would extend it.
        if self._next_tick is None:
            self._next_tick = pkt.ts + TICK_SECONDS
        elif pkt.ts >= self._next_tick:
            self._end_flows(self.flows.expire(pkt.ts))
            for det in self.detectors:
                self._emit(det.tick(pkt.ts))
            self._next_tick = pkt.ts + TICK_SECONDS
        self.stats.add(pkt)
        self._end_flows(self.flows.add(pkt))
        for det in self.detectors:
            self._emit(det.on_packet(pkt))

    def process_frame(self, ts: float, buf: bytes, linktype: int) -> None:
        try:
            pkt = decode(ts, buf, linktype)
        except UnsupportedLinkType:
            # Counted, not fatal: one exotic interface in a multi-interface
            # pcapng must not abort the analysis of the others.
            self.stats.unsupported_linktypes[linktype] += 1
            return
        if pkt is None:
            self.stats.decode_errors += 1
            return
        self.process(pkt)

    def finish(self) -> AnalysisResult:
        self._end_flows(self.flows.drain())
        for det in self.detectors:
            self._emit(det.flush())
        self.alerts.sort(key=lambda a: (a.first_seen, a.detector))
        return AnalysisResult(stats=self.stats, alerts=self.alerts)


def analyze_frames(frames: Iterable[tuple[float, bytes, int]], config: Config | None = None) -> AnalysisResult:
    engine = Engine(config)
    for ts, buf, linktype in frames:
        engine.process_frame(ts, buf, linktype)
    return engine.finish()


def analyze_packets(packets: Iterable[Packet], config: Config | None = None) -> AnalysisResult:
    engine = Engine(config)
    for pkt in packets:
        engine.process(pkt)
    return engine.finish()
