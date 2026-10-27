"""The analysis engine: drives packets through flows, statistics and detectors.

Per packet: decode -> statistics -> flow table -> detectors' ``on_conn_event``
(only when the packet changed a TCP handshake) -> detectors' ``on_packet``.
Flows that end (closed, idle, evicted, or end of input) go to the statistics,
to the detectors' ``on_flow_end`` and to the optional ``on_flow`` callback.
All timing uses capture timestamps, never the wall clock, so an offline run is
deterministic: the same pcap and config always produce the same output.
"""

from __future__ import annotations

from collections import deque
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field, replace

from netguard.confidence import assess
from netguard.config import Config
from netguard.decode import UnsupportedLinkType, decode
from netguard.detectors import Detector, build_detectors
from netguard.flows import Flow, FlowTable
from netguard.models import STAGE_FINAL, Alert, Packet
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
        max_alert_history: int | None = None,
    ) -> None:
        self.config = config or Config()
        self.detectors = detectors if detectors is not None else build_detectors(self.config)
        self.stats = TrafficStats()
        self.flows = FlowTable(self.config.flows)
        if max_alert_history is not None and max_alert_history < 1:
            raise ValueError("max_alert_history must be positive")
        # Offline analyses keep every alert (None). Live sessions keep a bounded
        # tail: ``on_alert`` still receives every event, and the statistics
        # count how many were dropped from this in-memory history.
        self._alert_history: deque[Alert] = deque(maxlen=max_alert_history)
        self._on_alert = on_alert
        self._on_flow = on_flow
        self._next_tick: float | None = None
        self._now: float | None = None  # capture clock: last packet time or advance() time
        # Only detectors that implement a hook are called for it; on_packet is
        # further dispatched by protocol (Detector.packet_protos).
        self._conn_detectors = [d for d in self.detectors if type(d).on_conn_event is not Detector.on_conn_event]
        self._packet_detectors = [d for d in self.detectors if type(d).on_packet is not Detector.on_packet]
        self._by_proto: dict[str, list[Detector]] = {}

    @property
    def alerts(self) -> list[Alert]:
        """The retained alert events (all of them unless ``max_alert_history`` is set)."""
        return list(self._alert_history)

    def _emit(self, alerts: Iterable[Alert]) -> None:
        for alert in alerts:
            if alert.reported_at is None and self._now is not None:
                alert = replace(alert, reported_at=self._now)
            if alert.confidence is None:
                alert = replace(alert, confidence=assess(alert.rule_id, alert.evidence))
            self.stats.alert_events_total += 1
            self.stats.final_alerts_total += alert.stage == STAGE_FINAL
            if len(self._alert_history) == self._alert_history.maxlen:
                self.stats.alert_history_dropped += 1
            self._alert_history.append(alert)
            if self._on_alert:
                self._on_alert(alert)

    def _end_flows(self, flows: Iterable[Flow]) -> None:
        for flow in flows:
            self.stats.add_flow(flow)
            for det in self.detectors:
                self._emit(det.on_flow_end(flow))
            if self._on_flow:
                self._on_flow(flow)

    def _tick(self, now: float) -> None:
        self._end_flows(self.flows.expire(now))
        for det in self.detectors:
            self._emit(det.tick(now))
        self._next_tick = now + TICK_SECONDS

    def advance(self, now: float) -> None:
        """Move the capture clock forward without a packet (live capture during silence).

        Offline, time advances with packets; live, a scan followed by silence
        must still close its incidents. Times earlier than the clock are ignored.
        """
        if self._next_tick is None or (self._now is not None and now <= self._now):
            return
        self._now = now
        if now >= self._next_tick:
            self._tick(now)

    def process(self, pkt: Packet) -> None:
        # Tick *before* handing the packet to detectors: an incident that has been
        # idle must be closed first, otherwise this packet would extend it.
        if self._now is None or pkt.ts > self._now:
            self._now = pkt.ts
        if self._next_tick is None:
            self._next_tick = pkt.ts + TICK_SECONDS
        elif pkt.ts >= self._next_tick:
            self._tick(pkt.ts)
        self.stats.add(pkt)
        self._end_flows(self.flows.add(pkt))
        event, flow = self.flows.event, self.flows.current
        if event is not None and flow is not None:
            for det in self._conn_detectors:
                alerts = det.on_conn_event(event, flow, pkt.ts)
                if alerts:
                    self._emit(alerts)
        dets = self._by_proto.get(pkt.proto)
        if dets is None:
            dets = self._by_proto[pkt.proto] = [
                d for d in self._packet_detectors if d.packet_protos is None or pkt.proto in d.packet_protos
            ]
        for det in dets:
            alerts = det.on_packet(pkt)
            if alerts:
                self._emit(alerts)

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
        alerts = sorted(self._alert_history, key=lambda a: (a.first_seen, a.detector))
        self.stats.detector_counters = {d.name: d.counter_values() for d in self.detectors if d.counters}
        return AnalysisResult(stats=self.stats, alerts=alerts)


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
