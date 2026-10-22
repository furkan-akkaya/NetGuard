import json

from netguard.engine import analyze_packets
from netguard.flows import Flow
from netguard.models import Packet
from netguard.stats import TimeSeries, TrafficStats

from .helpers import udp


def test_packet_size_histogram():
    stats = TrafficStats()
    for length in (60, 64, 65, 600, 1518, 9000):
        stats.add(Packet(ts=0, length=length, proto="other"))
    assert stats.to_dict()["packet_sizes"] == {
        "0-64": 2,
        "65-128": 1,
        "129-256": 0,
        "257-512": 0,
        "513-1024": 1,
        "1025-1518": 1,
        "1519+": 1,
    }


def test_timeseries_downsamples_instead_of_growing():
    ts = TimeSeries(max_buckets=8)
    for second in range(100):
        ts.add(1000.0 + second, 10)
    assert len(ts.buckets) <= 8
    assert ts.width == 16.0
    assert sum(p for p, _ in ts.buckets.values()) == 100
    assert sum(b for _, b in ts.buckets.values()) == 1000


def test_endpoint_table_is_bounded_and_flags_approximation():
    stats = TrafficStats(max_endpoints=10)
    heavy = Flow("udp", "10.0.0.1", 1, "10.0.0.2", 53, 0, 0, orig_packets=1, orig_bytes=1_000_000)
    stats.add_flow(heavy)
    for i in range(100):  # a spoofed-source flood: many tiny one-packet flows
        stats.add_flow(Flow("udp", f"198.51.100.{i}", 1, "10.0.0.2", 53, 0, 0, orig_packets=1, orig_bytes=60))
    assert len(stats.endpoints) <= 10
    assert stats.endpoints_approximate
    top_ip, top = stats.top_endpoints(1)[0]
    assert top_ip == "10.0.0.2"  # the heavy hitters survive pruning
    assert top.bytes_received == 1_000_000 + 100 * 60


def test_top_flows_keeps_the_largest():
    stats = TrafficStats(top_n=3)
    for i, size in enumerate([10, 500, 20, 400, 30, 300]):
        stats.add_flow(Flow("udp", "10.0.0.1", i, "10.0.0.2", 53, 0, 0, orig_packets=1, orig_bytes=size))
    assert [f.bytes for f in stats.top_flows()] == [500, 400, 300]


def test_stats_document_is_json_serializable():
    pkts = [udp(i, "10.0.0.20", "10.0.0.53", 53, sport=50000 + i) for i in range(5)]
    doc = analyze_packets(pkts).stats.to_dict()
    json.dumps(doc)
    assert doc["flows"]["total"] == 5
    assert doc["flows"]["states"] == {"S0": 5}
    assert doc["flows"]["top_services"] == [{"service": "udp/53", "flows": 5}]
    assert doc["endpoints"]["top_by_bytes"][0]["ip"] == "10.0.0.20"
    assert doc["timeseries"]["bucket_seconds"] == 1.0
