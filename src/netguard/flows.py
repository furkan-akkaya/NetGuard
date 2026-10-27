"""Bidirectional flow tracking with a simplified TCP connection state.

A *flow* is every packet sharing a 5-tuple (protocol, IP/port pairs) in either
direction, from its first packet until it is closed, goes idle, or is evicted.
The side that sent the first packet is the *originator* (``src_*`` fields); the
other side is the *responder*. If the first TCP packet we see is a SYN-ACK we
missed the SYN, so the sender is the responder and the orientation is flipped.

Connection states follow Zeek's ``conn_state`` vocabulary so results can be
compared with ``conn.log`` (see :data:`CONN_STATES` and ADR-0004). They are
derived from the TCP flags seen in each direction, not from a full RFC 9293
state machine: we observe traffic, we do not participate in it, and an observer
cannot know which packets the endpoints really received.

Memory is bounded by ``max_flows``. Flows live in one LRU list per *timeout
class* (half-open TCP, established TCP, closed TCP, UDP, other). Inside one
class every flow has the same idle timeout, so the least recently updated flow
is always the first to expire: expiry pops from the front and stops at the
first live flow, which is O(1) amortized per flow instead of a full table scan
on every tick. When the table is full and nothing has expired, the least
recently seen flow overall is evicted (``end_reason="evicted"``). An attacker
who opens many flows can therefore push real flows out early; that is counted
and reported, never silent.
"""

from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Any

from netguard.config import FlowConfig
from netguard.models import ACK, FIN, RST, SYN, Packet, iso_ts

FlowKey = tuple[str, str, int, str, int]

SEQ_MOD = 1 << 32
HALF_SEQ = 1 << 31

#: Zeek-compatible connection states (subset). Precedence is documented in ADR-0004.
CONN_STATES = {
    "S0": "Connection attempt seen, no reply",
    "S1": "Connection established, not terminated",
    "SF": "Established and closed normally (FIN in both directions)",
    "REJ": "Connection attempt rejected (responder answered SYN with RST)",
    "S2": "Established, originator sent FIN, no FIN from responder",
    "S3": "Established, responder sent FIN, no FIN from originator",
    "RSTO": "Established, originator aborted with RST",
    "RSTR": "Established, responder aborted with RST",
    "RSTOS0": "Originator sent SYN then RST, no SYN-ACK seen",
    "RSTRH": "Responder sent SYN-ACK then RST, no SYN from originator seen",
    "SH": "Originator sent SYN then FIN, no SYN-ACK seen (half-open)",
    "SHR": "Responder sent SYN-ACK then FIN, no SYN from originator seen",
    "OTH": "No SYN seen: mid-stream traffic, or non-TCP with no reply pattern",
}

# Timeout classes. Each has exactly one timeout, which keeps every LRU list
# ordered by expiry time.
_HALF_OPEN, _ESTABLISHED, _CLOSED, _UDP, _OTHER = range(5)

# How one endpoint ended, for an established connection's state. It follows
# Zeek's endpoint state machine (TCPSessionAdapter: UpdateEstablishedState,
# UpdateClosedState) rather than the OR of flags, because there the order of
# FIN and RST matters: an RST from an endpoint that already sent its FIN is
# ignored when the peer has closed too, and a peer's later FIN turns such an
# RST back into a normal close.
_OPEN, _FINNED, _RESET, _RESET_AFTER_FIN = range(4)


def seq_after(a: int, b: int) -> bool:
    """``a`` is later than ``b`` in 32-bit sequence space (RFC 1982 serial arithmetic)."""
    diff = (a - b) % SEQ_MOD
    return 0 < diff < HALF_SEQ


@dataclass(slots=True)
class Flow:
    proto: str
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    first_seen: float
    last_seen: float
    orig_packets: int = 0
    orig_bytes: int = 0
    orig_payload_bytes: int = 0
    resp_packets: int = 0
    resp_bytes: int = 0
    resp_payload_bytes: int = 0
    orig_flags: int = 0  # OR of every TCP flag the originator sent
    resp_flags: int = 0
    retransmissions: int = 0
    seq_gaps: int = 0
    # Zeek-style history: S SYN, H SYN-ACK, A ACK, D data, F FIN, R RST,
    # T retransmission, G sequence gap. Upper case = originator, lower case =
    # responder. Each letter is recorded once per direction, so it is bounded.
    history: str = ""
    end_reason: str = ""
    _orig_next: int | None = field(default=None, repr=False)
    _resp_next: int | None = field(default=None, repr=False)
    _orig_end: int = field(default=_OPEN, repr=False)
    _resp_end: int = field(default=_OPEN, repr=False)
    _cls: int = field(default=_OTHER, repr=False)

    @property
    def duration(self) -> float:
        return self.last_seen - self.first_seen

    @property
    def packets(self) -> int:
        return self.orig_packets + self.resp_packets

    @property
    def bytes(self) -> int:
        return self.orig_bytes + self.resp_bytes

    @property
    def state(self) -> str:
        if self.proto != "tcp":
            return "SF" if self.resp_packets else "S0"
        o, r = self.orig_flags, self.resp_flags
        orig_syn, resp_syn = bool(o & SYN), bool(r & SYN)
        if orig_syn and not resp_syn:
            if r & RST:
                return "REJ"
            if o & RST:
                return "RSTOS0"
            if o & FIN:
                return "SH"
            return "S0"
        if resp_syn and not orig_syn:
            if r & RST:
                return "RSTRH"
            if r & FIN:
                return "SHR"
            return "OTH"
        if not orig_syn:
            return "OTH"
        oe, re = self._orig_end, self._resp_end
        if oe >= _RESET:
            return "RSTO"
        if re >= _RESET:
            return "RSTR"
        if oe == _FINNED and re == _FINNED:
            return "SF"
        if oe == _FINNED:
            return "S2"
        if re == _FINNED:
            return "S3"
        return "S1"

    @property
    def established(self) -> bool:
        return self.proto == "tcp" and bool(self.orig_flags & SYN) and bool(self.resp_flags & SYN)

    @property
    def closed(self) -> bool:
        flags = self.orig_flags | self.resp_flags
        return bool(flags & RST) or bool(self.orig_flags & FIN and self.resp_flags & FIN)

    def to_dict(self) -> dict[str, Any]:
        return {
            "proto": self.proto,
            "src_ip": self.src_ip,
            "src_port": self.src_port,
            "dst_ip": self.dst_ip,
            "dst_port": self.dst_port,
            "first_seen": iso_ts(self.first_seen),
            "last_seen": iso_ts(self.last_seen),
            "duration_seconds": round(self.duration, 6),
            "state": self.state,
            "history": self.history,
            "orig_packets": self.orig_packets,
            "orig_bytes": self.orig_bytes,
            "orig_payload_bytes": self.orig_payload_bytes,
            "resp_packets": self.resp_packets,
            "resp_bytes": self.resp_bytes,
            "resp_payload_bytes": self.resp_payload_bytes,
            "retransmissions": self.retransmissions,
            "seq_gaps": self.seq_gaps,
            "end_reason": self.end_reason,
        }

    # ---------------------------------------------------------------- updates

    def _mark(self, letter: str, orig: bool) -> None:
        letter = letter if orig else letter.lower()
        if letter not in self.history:
            self.history += letter

    def update(self, pkt: Packet, orig: bool) -> None:
        self.last_seen = max(self.last_seen, pkt.ts)
        payload = pkt.payload_len or 0
        if orig:
            self.orig_packets += 1
            self.orig_bytes += pkt.length
            self.orig_payload_bytes += payload
        else:
            self.resp_packets += 1
            self.resp_bytes += pkt.length
            self.resp_payload_bytes += payload
        if pkt.tcp_flags is None:
            return
        flags = pkt.tcp_flags
        if orig:
            self.orig_flags |= flags
        else:
            self.resp_flags |= flags
        if flags & SYN:
            self._mark("H" if flags & ACK else "S", orig)
        elif flags & ACK and not payload and not flags & (FIN | RST):
            self._mark("A", orig)
        if payload:
            self._mark("D", orig)
        if flags & FIN:
            self._mark("F", orig)
        if flags & (FIN | RST):
            self._update_end(flags, orig)
        if flags & RST:
            self._mark("R", orig)
        elif pkt.tcp_seq is not None:
            self._track_seq(pkt.tcp_seq, payload + bool(flags & SYN) + bool(flags & FIN), orig)

    def _update_end(self, flags: int, orig: bool) -> None:
        """Advance the sending endpoint's FIN/RST state (see ``_OPEN`` and friends)."""
        end, peer = (self._orig_end, self._resp_end) if orig else (self._resp_end, self._orig_end)
        if end == _OPEN:
            if flags & RST:
                end = _RESET  # FIN+RST in one segment is an abort
            else:
                end = _FINNED
                if peer == _RESET_AFTER_FIN:
                    peer = _FINNED  # the peer's FIN-then-RST was a normal close after all
        elif end == _FINNED and flags & RST and peer != _FINNED:
            end = _RESET_AFTER_FIN
        # Once reset, an endpoint stays reset; an RST after both FINs changes nothing.
        if orig:
            self._orig_end, self._resp_end = end, peer
        else:
            self._resp_end, self._orig_end = end, peer

    def _track_seq(self, seq: int, length: int, orig: bool) -> None:
        """Count segments that do not advance the sequence space.

        Only segments that consume sequence numbers (data, SYN, FIN) are
        checked. A segment whose end is not beyond the highest end seen so far
        is a retransmission *or* a late out-of-order arrival; an observer
        cannot tell the two apart without seeing both endpoints' ACK clocks, so
        both are counted as ``retransmissions``. A segment that starts beyond
        the highest end seen is a gap: lost or reordered packets, or packets
        the capture itself dropped. TCP keep-alives (one old byte) are counted
        as retransmissions, as Zeek does.
        """
        if not length:
            return
        end = (seq + length) % SEQ_MOD
        nxt = self._orig_next if orig else self._resp_next
        if nxt is not None:
            if not seq_after(end, nxt):
                self.retransmissions += 1
                self._mark("T", orig)
                return
            if seq_after(seq, nxt):
                self.seq_gaps += 1
                self._mark("G", orig)
        if orig:
            self._orig_next = end
        else:
            self._resp_next = end


# Handshake transitions (TCP) and first datagram / first reply (UDP), reported
# once per flow at the packet that causes them.
# They let detectors judge connection *outcomes* in real time instead of
# waiting for a flow to time out.
ATTEMPT = "attempt"  # originator's SYN opened a new flow
ANSWERED = "answered"  # responder's first SYN-ACK
REJECTED = "rejected"  # responder's RST before any SYN-ACK (closed port)
ESTABLISHED = "established"  # originator's first ACK after the SYN-ACK
CONN_EVENTS = (ATTEMPT, ANSWERED, REJECTED, ESTABLISHED)


def _conn_event(flow: Flow, new: bool, orig: bool, prev_o: int, prev_r: int, prev_resp_packets: int) -> str | None:
    if flow.proto == "udp":
        # UDP has no handshake: the first datagram is the attempt, the first reply the answer.
        if orig:
            return ATTEMPT if new else None
        return ANSWERED if prev_resp_packets == 0 else None
    o, r = flow.orig_flags, flow.resp_flags
    if not o & SYN:
        return None  # mid-stream flow: no handshake to report on
    if orig:
        if new and not o & ACK:
            return ATTEMPT
        if o & ACK and not prev_o & ACK and r & SYN:
            return ESTABLISHED
        return None
    if r & SYN and not prev_r & SYN:
        return ANSWERED
    if r & RST and not prev_r & (RST | SYN):
        return REJECTED
    return None


def flow_key(pkt: Packet) -> FlowKey | None:
    """Direction-independent key: A->B and B->A map to the same flow."""
    if pkt.src_ip is None or pkt.dst_ip is None or pkt.proto == "ip-frag":
        return None
    a = (pkt.src_ip, pkt.src_port or 0)
    b = (pkt.dst_ip, pkt.dst_port or 0)
    lo, hi = (a, b) if a <= b else (b, a)
    return (pkt.proto, lo[0], lo[1], hi[0], hi[1])


class FlowTable:
    def __init__(self, config: FlowConfig | None = None) -> None:
        cfg = config or FlowConfig()
        self.max_flows = cfg.max_flows
        self._timeouts = {
            _HALF_OPEN: cfg.tcp_handshake_timeout_seconds,
            _ESTABLISHED: cfg.tcp_idle_timeout_seconds,
            _CLOSED: cfg.tcp_closed_linger_seconds,
            _UDP: cfg.udp_idle_timeout_seconds,
            _OTHER: cfg.other_idle_timeout_seconds,
        }
        self._flows: dict[FlowKey, Flow] = {}
        self._lru: dict[int, OrderedDict[FlowKey, Flow]] = {c: OrderedDict() for c in self._timeouts}
        self.flows_evicted = 0
        self.current: Flow | None = None
        self.event: str | None = None

    def __len__(self) -> int:
        return len(self._flows)

    @staticmethod
    def _class_of(flow: Flow) -> int:
        if flow.proto == "tcp":
            if flow.closed:
                return _CLOSED
            return _ESTABLISHED if flow.resp_packets else _HALF_OPEN
        return _UDP if flow.proto == "udp" else _OTHER

    def add(self, pkt: Packet) -> list[Flow]:
        """Account ``pkt`` to its flow. Returns flows that ended because of it.

        Afterwards :attr:`current` is the packet's flow and :attr:`event` the
        handshake transition it caused, if any (see :data:`CONN_EVENTS`).
        """
        self.current = None
        self.event = None
        key = flow_key(pkt)
        if key is None:
            return []
        ended: list[Flow] = []
        flow = self._flows.get(key)
        if flow is not None:
            if pkt.ts - flow.last_seen > self._timeouts[flow._cls]:
                ended.append(self._end(key, "idle"))
                flow = None
            elif flow.closed and pkt.tcp_flags is not None and pkt.tcp_flags & (SYN | ACK) == SYN:
                # A fresh SYN on a closed 5-tuple is a new connection (port reuse).
                ended.append(self._end(key, "closed"))
                flow = None
        if flow is None:
            if len(self._flows) >= self.max_flows:
                ended += self.expire(pkt.ts)
                if len(self._flows) >= self.max_flows:
                    ended.append(self._evict_oldest())
            flow = self._start(key, pkt)
            new = True
        else:
            new = False
        assert pkt.src_ip is not None
        orig = pkt.src_ip == flow.src_ip and (pkt.src_port or 0) == flow.src_port
        prev_o, prev_r, prev_resp = flow.orig_flags, flow.resp_flags, flow.resp_packets
        flow.update(pkt, orig)
        self.current = flow
        if flow.proto in ("tcp", "udp"):
            self.event = _conn_event(flow, new, orig, prev_o, prev_r, prev_resp)
        cls = self._class_of(flow)
        if cls != flow._cls:
            del self._lru[flow._cls][key]
            self._lru[cls][key] = flow
            flow._cls = cls
        else:
            self._lru[cls].move_to_end(key)
        return ended

    def _start(self, key: FlowKey, pkt: Packet) -> Flow:
        assert pkt.src_ip is not None
        assert pkt.dst_ip is not None
        src, sport, dst, dport = pkt.src_ip, pkt.src_port or 0, pkt.dst_ip, pkt.dst_port or 0
        if pkt.tcp_flags is not None and pkt.tcp_flags & (SYN | ACK) == SYN | ACK:
            src, sport, dst, dport = dst, dport, src, sport  # we missed the SYN
        flow = Flow(pkt.proto, src, sport, dst, dport, first_seen=pkt.ts, last_seen=pkt.ts)
        flow._cls = self._class_of(flow)
        self._flows[key] = flow
        self._lru[flow._cls][key] = flow
        return flow

    def _end(self, key: FlowKey, reason: str) -> Flow:
        flow = self._flows.pop(key)
        del self._lru[flow._cls][key]
        flow.end_reason = reason
        return flow

    def _evict_oldest(self) -> Flow:
        heads = [(next(iter(od.items())), od) for od in self._lru.values() if od]
        (key, _), _ = min(heads, key=lambda h: h[0][1].last_seen)
        self.flows_evicted += 1
        return self._end(key, "evicted")

    def expire(self, now: float) -> list[Flow]:
        """End every flow whose idle time exceeds its class timeout."""
        ended: list[Flow] = []
        for cls, od in self._lru.items():
            timeout = self._timeouts[cls]
            reason = "closed" if cls == _CLOSED else "idle"
            while od:
                key, flow = next(iter(od.items()))
                if now - flow.last_seen <= timeout:
                    break
                ended.append(self._end(key, reason))
        return ended

    def drain(self) -> list[Flow]:
        """End of input: end every remaining flow in first-seen order."""
        ended = [self._end(k, "closed" if f.closed else "eof") for k, f in list(self._flows.items())]
        ended.sort(key=lambda f: f.first_seen)
        return ended
