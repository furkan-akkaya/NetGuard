import struct

import dpkt
import pytest

from netguard.decode import decode
from netguard.dns import RCODE_NXDOMAIN, parse_dns, registered_domain, shannon_entropy
from netguard.lab.scenarios import ATTACKER, RESOLVER, SERVER, WORKSTATION
from netguard.lab.synth import dns_response


def _query(name: bytes, qtype: int = 1, qid: int = 7) -> bytes:
    return struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 0) + name + struct.pack("!HH", qtype, 1)


def test_parse_query():
    info = parse_dns(_query(b"\x03www\x07ExAmPlE\x03com\x00", qtype=16))
    assert info is not None
    assert (info.id, info.response, info.qname, info.qtype_name, info.rcode_name) == (
        7,
        False,
        "www.example.com",
        "TXT",
        "NOERROR",
    )


def test_compression_pointer_in_question():
    # Header, then a name at offset 12 that points to itself + 0 bytes: a loop.
    loop = struct.pack("!HHHHHH", 1, 0, 1, 0, 0, 0) + b"\xc0\x0c" + b"\x00\x01\x00\x01"
    info = parse_dns(loop)
    assert info is not None
    assert info.qname is None  # hop limit stops the loop; header still parsed


@pytest.mark.parametrize(
    "name",
    [
        b"\x05abc",  # label runs past the end
        b"\x40abc\x00",  # reserved label type
        b"\x3f" + b"a" * 63 + b"\x3f" + b"a" * 63 + b"\x3f" + b"a" * 63 + b"\x3f" + b"a" * 63 + b"\x00",  # > 255
    ],
)
def test_malformed_names_are_dropped_not_raised(name):
    info = parse_dns(_query(name))
    assert info is not None
    assert info.qname is None


def test_too_short_is_none():
    assert parse_dns(b"\x00\x01") is None


def test_response_decoded_through_pipeline():
    frame = dns_response(RESOLVER, WORKSTATION, "nope.example.org", qid=9, rcode=RCODE_NXDOMAIN)
    pkt = decode(0, frame)
    assert pkt is not None
    assert pkt.dns is not None
    assert pkt.dns.response
    assert pkt.dns.rcode_name == "NXDOMAIN"
    assert pkt.dns.qname == "nope.example.org"
    assert pkt.dns_query is None  # responses are not queries


def test_icmp_port_unreachable_quotes_the_closed_udp_port():
    probe = ATTACKER.udp(SERVER, 40000, 161)
    inner = dpkt.ethernet.Ethernet(probe).data
    msg = dpkt.icmp.ICMP(type=3, code=3, data=dpkt.icmp.ICMP.Unreach(data=bytes(inner)[:28]))
    ip = dpkt.ip.IP(src=bytes([10, 0, 0, 10]), dst=bytes([10, 0, 0, 66]), p=1, ttl=64, data=msg)
    ip.len = len(ip)
    frame = bytes(dpkt.ethernet.Ethernet(src=b"\x02" * 6, dst=b"\x04" * 6, type=0x0800, data=ip))
    pkt = decode(0, frame)
    assert pkt is not None
    assert (pkt.icmp_type, pkt.icmp_code, pkt.icmp_orig_proto, pkt.icmp_orig_dst_port) == (3, 3, "udp", 161)


@pytest.mark.parametrize(
    ("name", "domain"),
    [
        ("www.example.com", "example.com"),
        ("a.b.c.example.co.uk", "example.co.uk"),
        ("mail.itu.edu.tr", "itu.edu.tr"),
        ("example.com", "example.com"),
        ("localhost", "localhost"),
        ("x.github.io", "github.io"),  # known limitation: not a public-suffix-aware split
    ],
)
def test_registered_domain(name, domain):
    assert registered_domain(name) == domain


def test_shannon_entropy():
    assert shannon_entropy("") == 0.0
    assert shannon_entropy("aaaa") == 0.0
    assert shannon_entropy("abcd") == pytest.approx(2.0)
    assert shannon_entropy("0123456789abcdef" * 4) == pytest.approx(4.0)
