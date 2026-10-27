import pytest

from netguard.config import Config, FlowConfig
from netguard.detectors.base import Detector
from netguard.engine import Engine, analyze_frames
from netguard.flows import Flow, FlowTable, seq_after
from netguard.lab.scenarios import ATTACKER, SERVER, WORKSTATION
from netguard.lab.synth import syn_probe, tcp_handshake
from netguard.models import ACK, FIN, PSH, RST, SYN, URG, Packet

from .helpers import arp, tcp, udp

C, S = "10.0.0.20", "10.0.0.10"  # client (originator), server (responder)


def _o(ts: float, flags: int, **kw) -> Packet:
    return tcp(ts, C, S, 80, flags, sport=40000, **kw)


def _r(ts: float, flags: int, **kw) -> Packet:
    return tcp(ts, S, C, 40000, flags, sport=80, **kw)


def _one_flow(pkts: list[Packet], config: FlowConfig | None = None) -> Flow:
    table = FlowTable(config)
    ended = [f for p in pkts for f in table.add(p)] + table.drain()
    assert len(ended) == 1, ended
    return ended[0]


# Each sequence is (direction, flags); 'o' = originator, 'r' = responder.
STATE_CASES = {
    "S0": [("o", SYN)],
    "REJ": [("o", SYN), ("r", RST | ACK)],
    "S1": [("o", SYN), ("r", SYN | ACK), ("o", ACK)],
    "SF": [("o", SYN), ("r", SYN | ACK), ("o", ACK), ("o", FIN | ACK), ("r", FIN | ACK), ("o", ACK)],
    "S2": [("o", SYN), ("r", SYN | ACK), ("o", ACK), ("o", FIN | ACK)],
    "S3": [("o", SYN), ("r", SYN | ACK), ("o", ACK), ("r", FIN | ACK)],
    "RSTO": [("o", SYN), ("r", SYN | ACK), ("o", RST)],
    "RSTR": [("o", SYN), ("r", SYN | ACK), ("o", ACK), ("r", RST)],
    "RSTOS0": [("o", SYN), ("o", RST)],
    "SH": [("o", SYN), ("o", FIN)],
    "SHR": [("r", SYN | ACK), ("r", FIN | ACK)],
    "RSTRH": [("r", SYN | ACK), ("r", RST)],
    "OTH": [("o", ACK | PSH), ("r", ACK)],
}


@pytest.mark.parametrize(("state", "sequence"), STATE_CASES.items(), ids=STATE_CASES)
def test_tcp_connection_states(state, sequence):
    pkts = [(_o if d == "o" else _r)(i * 0.01, flags) for i, (d, flags) in enumerate(sequence)]
    assert _one_flow(pkts).state == state


# FIN/RST orderings after an established handshake, with the state Zeek 8.2.2
# reports for each (checked by running Zeek on one pcap per case). The order
# matters: an RST from an endpoint that already sent its FIN is ignored once
# the peer has closed too, and a peer's later FIN turns it back into SF.
_HANDSHAKE = [("o", SYN), ("r", SYN | ACK), ("o", ACK)]
CLOSE_CASES = {
    "fin_both": ("SF", [("o", FIN | ACK), ("r", FIN | ACK), ("o", ACK)]),
    "fin_both_then_rst_o": ("SF", [("o", FIN | ACK), ("r", FIN | ACK), ("o", RST)]),
    "fin_both_then_rst_r": ("SF", [("o", FIN | ACK), ("r", FIN | ACK), ("r", RST)]),
    "fin_both_then_rst_o_and_r": ("SF", [("o", FIN | ACK), ("r", FIN | ACK), ("o", RST), ("r", RST)]),
    "fin_o_rst_o_then_fin_r": ("SF", [("o", FIN | ACK), ("o", RST), ("r", FIN | ACK)]),
    "fin_r_rst_r_then_fin_o": ("SF", [("r", FIN | ACK), ("r", RST), ("o", FIN | ACK)]),
    "fin_o_then_rst_o": ("RSTO", [("o", FIN | ACK), ("r", ACK), ("o", RST)]),
    "fin_o_then_rst_r": ("RSTR", [("o", FIN | ACK), ("r", ACK), ("r", RST)]),
    "fin_r_then_rst_o": ("RSTO", [("r", FIN | ACK), ("o", ACK), ("o", RST)]),
    "fin_r_then_rst_r": ("RSTR", [("r", FIN | ACK), ("o", ACK), ("r", RST)]),
    "fin_o_rst_r_then_fin_o_again": ("RSTR", [("o", FIN | ACK), ("r", RST), ("o", FIN | ACK)]),
    "rst_o_then_fin_r": ("RSTO", [("o", RST), ("r", FIN | ACK)]),
    "fin_rst_one_segment": ("RSTO", [("o", FIN | RST | ACK)]),
    "fin_r_then_fin_rst_o": ("RSTO", [("r", FIN | ACK), ("o", FIN | RST | ACK)]),
    # Both sides reset: Zeek checks the responder first, and with no payload
    # at all it calls the connection rejected.
    "rst_o_then_rst_r": ("REJ", [("o", RST), ("r", RST)]),
    "rst_r_then_rst_o": ("REJ", [("r", RST), ("o", RST)]),
    "fin_o_rst_o_then_rst_r": ("REJ", [("o", FIN | ACK), ("o", RST), ("r", RST)]),
    "data_then_rst_o_and_r": ("RSTR", [("o", PSH | ACK, 2), ("o", RST), ("r", RST)]),
    "resp_data_then_rst_r_and_o": ("RSTR", [("r", PSH | ACK, 6), ("r", RST), ("o", RST)]),
}


@pytest.mark.parametrize(("state", "sequence"), CLOSE_CASES.values(), ids=CLOSE_CASES)
def test_fin_and_rst_order_matches_zeek(state, sequence):
    steps = _HANDSHAKE + sequence
    pkts = [
        (_o if step[0] == "o" else _r)(i * 0.01, step[1], payload=step[2] if len(step) > 2 else 0)
        for i, step in enumerate(steps)
    ]
    assert _one_flow(pkts).state == state


# Connections with no SYN at all (NULL/FIN/Xmas probes, midstream pickup):
# Zeek still applies its endpoint states, where an endpoint that sent neither
# FIN nor RST is inactive. Each case checked against Zeek 8.2.2, one pcap each,
# state and history equal. NetGuard used to call all of them OTH.
NO_SYN_CASES = {
    "null_rst_r": ("RSTRH", [("o", 0), ("r", RST | ACK)]),
    "fin_rst_r": ("RSTR", [("o", FIN), ("r", RST | ACK)]),
    "xmas_rst_r": ("RSTR", [("o", FIN | PSH | URG), ("r", RST | ACK)]),
    "ack_rst_r": ("RSTRH", [("o", ACK), ("r", RST)]),
    "data_o_rst_r": ("RSTRH", [("o", PSH | ACK, 2), ("r", RST | ACK)]),
    "fin_unanswered": ("SH", [("o", FIN)]),
    "null_unanswered": ("OTH", [("o", 0)]),
    "rst_o_only": ("OTH", [("o", RST)]),
    "fin_o_rst_o": ("OTH", [("o", FIN | ACK), ("o", RST)]),
    "rst_o_then_fin_r": ("RSTO", [("o", RST), ("r", FIN | ACK)]),
    "fin_o_fin_r": ("SF", [("o", FIN | ACK), ("r", FIN | ACK)]),
    "ack_o_then_fin_r": ("SHR", [("o", ACK), ("r", FIN | ACK)]),
    "data_both_then_fin_r": ("SHR", [("o", PSH | ACK, 2), ("r", PSH | ACK, 2), ("r", FIN | ACK)]),
    "fin_o_then_data_r": ("SH", [("o", FIN | ACK), ("r", PSH | ACK, 2)]),
    "rst_o_rst_r": ("REJ", [("o", RST), ("r", RST)]),
    "data_o_rst_o_rst_r": ("RSTR", [("o", PSH | ACK, 2), ("o", RST), ("r", RST)]),
    "fin_o_rst_r": ("RSTR", [("o", FIN | ACK), ("r", ACK), ("r", RST)]),
}


@pytest.mark.parametrize(("state", "sequence"), NO_SYN_CASES.values(), ids=NO_SYN_CASES)
def test_connections_without_syn_match_zeek(state, sequence):
    pkts = [
        (_o if step[0] == "o" else _r)(i * 0.01, step[1], payload=step[2] if len(step) > 2 else 0)
        for i, step in enumerate(sequence)
    ]
    assert _one_flow(pkts).state == state


@pytest.mark.parametrize(
    ("probe", "closed", "open_"),
    [(0, "RSTRH", "OTH"), (FIN, "RSTR", "SH"), (FIN | PSH | URG, "RSTR", "SH")],
    ids=["null", "fin", "xmas"],
)
def test_real_stealth_scan_probes_match_zeek(probe, closed, open_):
    # Reduced from the real lab captures exp05 (NULL), exp04 (FIN) and exp03
    # (Xmas): a closed port answers RST|ACK with seq 0, the open SSH port stays
    # silent. Zeek 8.2.2 (checksums on): 999 x RSTRH/RSTR and 2 x OTH/SH per
    # capture; NetGuard reported OTH for all of them.
    seq = 259075004
    rst = tcp(0.000114, S, C, 55731, RST | ACK, sport=1, seq=0)
    closed_flow = _one_flow([tcp(0.0, C, S, 1, probe, sport=55731, seq=seq), rst])
    open_flow = _one_flow([tcp(0.0, C, S, 22, probe, sport=55731, seq=seq)])
    assert (closed_flow.state, open_flow.state) == (closed, open_)


def test_probes_without_syn_never_reach_trw_as_attempts():
    # The new labels (SH for an unanswered FIN probe, RSTR/RSTRH for a reset
    # one) do not change detection: TRW counts only first contacts opened by a
    # SYN (the "attempt" event), and none of these flows has one.
    for probe in (0, FIN, FIN | PSH | URG):
        assert _events([_o(0.0, probe), _r(0.01, RST | ACK)]) == [None, None]
        assert _events([_o(0.0, probe)]) == [None]


def test_rej_label_after_handshake_is_not_a_rejected_attempt():
    # The REJ *label* of an established connection that both sides reset
    # without payload must not reach the detectors as a rejection: TRW and the
    # SYN-flood rule use the connection events, where this connection was
    # answered and established, never rejected.
    pkts = [_o(0, SYN), _r(0.01, SYN | ACK), _o(0.02, ACK), _o(0.03, RST), _r(0.04, RST)]
    assert _events(pkts) == ["attempt", "answered", "established", None, None]
    assert _one_flow(pkts).state == "REJ"


def test_rst_after_fin_exchange_is_a_normal_close():
    # Reduced from a real SSH banner read in the lab (benign-01): both sides
    # sent FIN, then the client reset twice. Zeek 8.2.2 logs SF with history
    # ShAFadfR; NetGuard used to report RSTO.
    pkts = [
        _o(0.0, SYN, seq=2658235027),
        _r(0.0001, SYN | ACK, seq=2253569570),
        _o(0.0007, ACK, seq=2658235028),
        _o(0.0014, FIN | ACK, seq=2658235028),
        _r(0.0026, ACK, seq=2253569571),
        _r(0.0112, PSH | ACK, seq=2253569571, payload=42),
        _r(0.0116, FIN | ACK, seq=2253569613),
        _o(0.0118, RST, seq=2658235029),
        _o(0.0120, RST, seq=2658235029),
    ]
    flow = _one_flow(pkts)
    assert flow.state == "SF"
    assert flow.history == "ShAFadfR"
    assert flow.retransmissions == 0


def test_missed_syn_flips_orientation():
    flow = _one_flow([_r(0, SYN | ACK), _o(0.01, ACK)])
    assert (flow.src_ip, flow.src_port, flow.dst_ip, flow.dst_port) == (C, 40000, S, 80)
    assert flow.orig_packets == 1
    assert flow.resp_packets == 1


def test_per_direction_counters_and_history():
    pkts = [
        _o(0, SYN, seq=100),
        _r(0.01, SYN | ACK, seq=900),
        _o(0.02, ACK, seq=101),
        _o(0.03, ACK | PSH, seq=101, payload=10),
        _r(0.04, ACK | PSH, seq=901, payload=500),
    ]
    flow = _one_flow(pkts)
    assert (flow.orig_packets, flow.resp_packets) == (3, 2)
    assert flow.orig_payload_bytes == 10
    assert flow.resp_payload_bytes == 500
    assert flow.orig_bytes == 60 * 3 + 10
    assert flow.history == "ShADd"
    assert flow.retransmissions == 0
    assert flow.duration == pytest.approx(0.04)


def test_retransmission_and_gap_detection():
    pkts = [
        _o(0, SYN, seq=100),
        _r(0.01, SYN | ACK, seq=900),
        _o(0.02, ACK | PSH, seq=101, payload=100),
        _o(0.30, ACK | PSH, seq=101, payload=100),  # same segment again: retransmission
        _o(0.31, ACK | PSH, seq=401, payload=100),  # 201..400 never seen: gap
    ]
    flow = _one_flow(pkts)
    assert flow.retransmissions == 1
    assert flow.seq_gaps == 1
    assert "T" in flow.history
    assert "G" in flow.history


def test_sequence_wraparound_is_not_a_retransmission():
    top = (1 << 32) - 50
    pkts = [
        _o(0, SYN, seq=top - 1),
        _r(0.01, SYN | ACK, seq=7),
        _o(0.02, ACK | PSH, seq=top, payload=100),  # wraps past 2^32
        _o(0.03, ACK | PSH, seq=50, payload=100),  # continues right after the wrap
    ]
    flow = _one_flow(pkts)
    assert flow.retransmissions == 0
    assert flow.seq_gaps == 0


def test_seq_after_serial_arithmetic():
    assert seq_after(10, 5)
    assert not seq_after(5, 10)
    assert not seq_after(5, 5)
    assert seq_after(3, (1 << 32) - 3)  # after the wrap


def test_new_syn_on_closed_tuple_starts_a_new_flow():
    table = FlowTable()
    first = [_o(0, SYN), _r(0.01, SYN | ACK), _o(0.02, ACK), _o(0.03, RST)]
    ended = [f for p in first for f in table.add(p)]
    assert ended == []
    ended = table.add(_o(1.0, SYN))  # port reuse, well inside the linger time
    assert [f.state for f in ended] == ["RSTO"]
    assert ended[0].end_reason == "closed"
    assert [f.state for f in table.drain()] == ["S0"]


def test_idle_gap_splits_flow():
    table = FlowTable(FlowConfig(udp_idle_timeout_seconds=60))
    assert table.add(udp(0, C, S, 53)) == []
    ended = table.add(udp(61, C, S, 53))
    assert len(ended) == 1
    assert ended[0].end_reason == "idle"
    assert ended[0].state == "S0"


def test_timeout_classes_expire_independently():
    table = FlowTable(FlowConfig(tcp_handshake_timeout_seconds=30, tcp_idle_timeout_seconds=300))
    table.add(tcp(0, "10.0.0.66", S, 22, SYN))  # half-open: no reply
    for p in (_o(1, SYN), _r(1.01, SYN | ACK), _o(1.02, ACK)):  # established
        table.add(p)
    expired = table.expire(40)
    assert [(f.src_ip, f.state, f.end_reason) for f in expired] == [("10.0.0.66", "S0", "idle")]
    assert len(table) == 1
    assert table.expire(302) != []


def test_closed_flows_linger_briefly():
    table = FlowTable(FlowConfig(tcp_closed_linger_seconds=5))
    for p in STATE_CASES["SF"]:
        table.add((_o if p[0] == "o" else _r)(0, p[1]))
    assert table.expire(4) == []
    assert [f.end_reason for f in table.expire(6)] == ["closed"]


def test_full_table_evicts_least_recently_seen():
    table = FlowTable(FlowConfig(max_flows=2))
    table.add(udp(0, C, "10.0.0.1", 53))
    table.add(udp(1, C, "10.0.0.2", 53))
    table.add(udp(1.5, C, "10.0.0.1", 53))  # refresh the first flow
    ended = table.add(udp(2, C, "10.0.0.3", 53))
    assert [(f.dst_ip, f.end_reason) for f in ended] == [("10.0.0.2", "evicted")]
    assert table.flows_evicted == 1
    assert len(table) == 2


def test_full_table_prefers_expiry_over_eviction():
    table = FlowTable(FlowConfig(max_flows=1, udp_idle_timeout_seconds=10))
    table.add(udp(0, C, "10.0.0.1", 53))
    ended = table.add(udp(20, C, "10.0.0.2", 53))
    assert [f.end_reason for f in ended] == ["idle"]
    assert table.flows_evicted == 0


def test_packets_without_ip_or_l4_header_have_no_flow():
    table = FlowTable()
    table.add(arp(0, 1, C, "02:00:00:00:00:20", S))
    table.add(Packet(ts=0, length=60, proto="ip-frag", src_ip=C, dst_ip=S, fragment=True))
    assert len(table) == 0


def test_drain_orders_by_first_seen():
    table = FlowTable()
    table.add(udp(5, C, "10.0.0.2", 53))
    table.add(udp(1, C, "10.0.0.1", 53))
    assert [f.dst_ip for f in table.drain()] == ["10.0.0.1", "10.0.0.2"]


class FlowRecorder(Detector):
    name = "recorder"

    def __init__(self) -> None:
        self.flows: list[Flow] = []

    def on_packet(self, pkt):
        return ()

    def on_flow_end(self, flow):
        self.flows.append(flow)
        return ()


def test_engine_delivers_finished_flows_to_detectors_and_callback():
    recorder, streamed = FlowRecorder(), list[Flow]()
    engine = Engine(detectors=[recorder], on_flow=streamed.append)
    for p in [udp(0, C, S, 53), udp(0.5, S, C, 50000, sport=53), udp(100, C, "10.0.0.3", 53)]:
        engine.process(p)
    assert len(recorder.flows) == 1  # the first flow expired on the tick at t=100
    result = engine.finish()
    assert len(recorder.flows) == 2
    assert streamed == recorder.flows
    assert result.stats.flows_total == 2
    assert result.stats.conn_states == {"SF": 1, "S0": 1}


def test_full_pipeline_handshake_is_clean_sf():
    frames = tcp_handshake(WORKSTATION, SERVER, 10.0, 51000, 443, data=3)
    flows: list[Flow] = []
    engine = Engine(on_flow=flows.append)
    for ts, buf in frames:
        engine.process_frame(ts, buf, 1)
    engine.finish()
    assert len(flows) == 1
    flow = flows[0]
    assert flow.state == "SF"
    assert flow.history == "ShADdFf"  # the server never sends a pure ACK
    assert flow.retransmissions == 0
    assert flow.seq_gaps == 0
    assert flow.resp_payload_bytes == 3 * 512


def test_syn_scan_states_through_pipeline():
    frames = syn_probe(ATTACKER, SERVER, 0, 22, open_=True) + syn_probe(ATTACKER, SERVER, 0.1, 23, open_=False)
    result = analyze_frames(((ts, buf, 1) for ts, buf in frames), Config())
    assert result.stats.conn_states == {"RSTO": 1, "REJ": 1}


def _events(pkts: list[Packet]) -> list[str | None]:
    table = FlowTable()
    out = []
    for p in pkts:
        table.add(p)
        out.append(table.event)
    return out


def test_connection_events_for_a_full_handshake():
    pkts = [_o(0, SYN), _o(0.5, SYN), _r(1, SYN | ACK), _r(1.1, SYN | ACK), _o(1.2, ACK), _o(1.3, ACK | PSH, payload=5)]
    assert _events(pkts) == ["attempt", None, "answered", None, "established", None]


def test_connection_events_for_rejected_and_midstream():
    assert _events([_o(0, SYN), _r(0.1, RST | ACK), _r(0.2, RST | ACK)]) == ["attempt", "rejected", None]
    assert _events([_o(0, ACK | PSH, payload=5), _r(0.1, ACK)]) == [None, None]
    assert _events([udp(0, C, S, 53), udp(0.1, C, S, 53), udp(0.2, S, C, 50000, sport=53)]) == [
        "attempt",
        None,
        "answered",
    ]
