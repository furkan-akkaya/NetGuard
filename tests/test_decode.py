import random

import dpkt
import pytest

from netguard.decode import (
    DLT_EN10MB,
    DLT_LINUX_SLL,
    DLT_RAW,
    UnsupportedLinkType,
    _decode,
    _fast_eth_ipv4,
    decode,
)
from netguard.lab.scenarios import ATTACKER, GATEWAY, RESOLVER, SERVER, WORKSTATION
from netguard.lab.synth import dns_response, fragment
from netguard.models import ACK, SYN


def test_decode_tcp():
    pkt = decode(1.5, ATTACKER.tcp(SERVER, 40000, 22, SYN))
    assert pkt is not None
    assert (pkt.proto, pkt.src_ip, pkt.dst_ip, pkt.src_port, pkt.dst_port) == (
        "tcp",
        "10.0.0.66",
        "10.0.0.10",
        40000,
        22,
    )
    assert pkt.tcp_flags == SYN
    assert pkt.src_mac == ATTACKER.mac
    assert pkt.ts == 1.5


def test_decode_tcp_sequence_payload_and_ttl():
    pkt = decode(0, ATTACKER.tcp(SERVER, 40000, 80, ACK, b"hello", seq=4242, ack=77))
    assert pkt is not None
    assert (pkt.tcp_seq, pkt.tcp_ack, pkt.payload_len, pkt.ttl) == (4242, 77, 5, 64)
    assert not pkt.fragment


def test_payload_len_uses_ip_length_when_snaplen_truncates():
    frame = ATTACKER.tcp(SERVER, 40000, 80, ACK, b"x" * 1000)
    pkt = decode(0, frame[:96])  # 96-byte snaplen, as with "tcpdump -s 96"
    assert pkt is not None
    assert pkt.length == 96
    assert pkt.payload_len == 1000


def test_decode_udp_payload_len():
    pkt = decode(0, WORKSTATION.udp(RESOLVER, 5000, 53, b"abcd"))
    assert pkt is not None
    assert pkt.payload_len == 4


def _fragment(offset: int, more: bool, payload: bytes) -> bytes:
    ip = dpkt.ip.IP(src=bytes([10, 0, 0, 66]), dst=bytes([10, 0, 0, 10]), p=dpkt.ip.IP_PROTO_TCP, ttl=64)
    ip.data = payload
    ip.mf = int(more)
    ip.offset = offset  # in bytes; must be a multiple of 8
    ip.len = 20 + len(payload)
    return bytes(dpkt.ethernet.Ethernet(src=b"\x02" * 6, dst=b"\x04" * 6, type=dpkt.ethernet.ETH_TYPE_IP, data=ip))


def test_non_first_fragment_is_not_parsed_as_tcp():
    """Payload bytes of a later fragment must never be read as a TCP header."""
    fake_header = bytes(dpkt.tcp.TCP(sport=1, dport=445, flags=SYN))
    pkt = decode(0, _fragment(offset=24, more=False, payload=fake_header))
    assert pkt is not None
    assert pkt.proto == "ip-frag"
    assert pkt.fragment
    assert pkt.dst_port is None


def test_first_fragment_is_flagged():
    seg = bytes(dpkt.tcp.TCP(sport=1, dport=80, flags=SYN))
    pkt = decode(0, _fragment(offset=0, more=True, payload=seg))
    assert pkt is not None
    assert pkt.fragment
    assert pkt.proto == "tcp"


def test_decode_arp_reply():
    pkt = decode(0, ATTACKER.arp_reply(WORKSTATION, claimed_ip=GATEWAY.ip))
    assert pkt is not None
    assert pkt.proto == "arp"
    assert pkt.arp_op == 2
    assert pkt.arp_sender_ip == GATEWAY.ip
    assert pkt.arp_sender_mac == ATTACKER.mac
    assert pkt.arp_target_ip == WORKSTATION.ip


def test_decode_icmp_echo():
    pkt = decode(0, ATTACKER.icmp_echo("10.0.0.7", GATEWAY.mac))
    assert pkt is not None
    assert (pkt.proto, pkt.icmp_type, pkt.dst_ip) == ("icmp", 8, "10.0.0.7")


def test_decode_dns_query_name():
    pkt = decode(0, WORKSTATION.dns_query(RESOLVER, "www.example.com"))
    assert pkt is not None
    assert pkt.proto == "udp"
    assert pkt.dns_query == "www.example.com"


def test_decode_raw_ip_linktype():
    frame = ATTACKER.tcp(SERVER, 1, 2, SYN | ACK)
    ip_bytes = bytes(dpkt.ethernet.Ethernet(frame).data)
    pkt = decode(0, ip_bytes, DLT_RAW)
    assert pkt is not None
    assert pkt.src_ip == ATTACKER.ip
    assert pkt.src_mac is None


def test_decode_linux_sll_linktype():
    ip = dpkt.ethernet.Ethernet(ATTACKER.tcp(SERVER, 1, 2, SYN)).data
    sll = dpkt.sll.SLL(type=0, hrd=1, hlen=6, hdr=b"\x02\x00\x00\x00\x00\x66\x00\x00", ethtype=0x0800, data=ip)
    pkt = decode(0, bytes(sll), DLT_LINUX_SLL)
    assert pkt is not None
    assert pkt.dst_port == 2


def test_unsupported_linktype_is_an_error_not_silence():
    with pytest.raises(UnsupportedLinkType):
        decode(0, b"\x00" * 40, 147)


@pytest.mark.parametrize("buf", [b"", b"\x00", b"\xff" * 13, b"\x00" * 14 + b"\x45"])
def test_malformed_frames_return_none_or_packet(buf):
    # Must never raise: attacker-controlled input.
    decode(0, buf, DLT_EN10MB)


def test_invalid_utf8_dns_name_does_not_hide_the_packet():
    """Regression: the whole packet used to become a decode error (detection bypass)."""
    frame = bytearray(WORKSTATION.dns_query(RESOLVER, "abcdef.example.org"))
    frame[14 + 20 + 8 + 12 + 1] = 0xC6  # first byte of the first label
    pkt = decode(0, bytes(frame))
    assert pkt is not None
    assert pkt.proto == "udp"
    assert pkt.dst_port == 53
    assert pkt.dns_query == "\\xc6bcdef.example.org"  # kept, visibly escaped


def _mutants(n: int, seed: int) -> list[bytes]:
    rng = random.Random(seed)
    seeds = [
        ATTACKER.tcp(SERVER, 40000, 22, SYN),
        ATTACKER.tcp(SERVER, 40000, 80, ACK, b"payload" * 20, seq=7, ack=9),
        WORKSTATION.udp(RESOLVER, 5000, 123, b"ntp"),
        WORKSTATION.dns_query(RESOLVER, "a.example.org"),
        dns_response(RESOLVER, WORKSTATION, "a.example.org", rcode=3),
        ATTACKER.icmp_echo("10.0.0.7", GATEWAY.mac),
        SERVER.icmp_unreachable(ATTACKER, ATTACKER.udp(SERVER, 40000, 161)),
        SERVER.icmp_unreachable(ATTACKER, ATTACKER.tcp(SERVER, 40000, 22, SYN), code=1),
        *fragment(ATTACKER.tcp(SERVER, 40000, 22, SYN, b"x" * 40), 24),
    ]
    out = []
    for _ in range(n):
        buf = bytearray(rng.choice(seeds))
        for _ in range(rng.randint(0, 4)):
            buf[rng.randrange(14, len(buf))] = rng.randrange(256)
        if rng.random() < 0.3:
            del buf[rng.randint(0, len(buf)) :]
        out.append(bytes(buf))
    return out


def test_fast_path_matches_dpkt_path():
    """Differential test: whenever the fast path accepts a frame, dpkt must agree exactly."""
    accepted = 0
    for buf in _mutants(5000, seed=7):
        fast = _fast_eth_ipv4(0.0, buf)
        if fast is None:
            continue
        accepted += 1
        assert fast == _decode(0.0, buf, DLT_EN10MB), buf.hex()
    assert accepted > 1000  # the comparison must actually exercise the fast path


def test_decoder_survives_random_mutation():
    """A tiny mutation fuzzer: flip random bytes of valid frames and truncate them."""
    rng = random.Random(1337)
    seeds = [
        ATTACKER.tcp(SERVER, 40000, 22, SYN),
        ATTACKER.arp_request("10.0.0.9"),
        WORKSTATION.dns_query(RESOLVER, "a.example.org"),
        ATTACKER.icmp_echo("10.0.0.7", GATEWAY.mac),
    ]
    for _ in range(5000):
        buf = bytearray(rng.choice(seeds))
        for _ in range(rng.randint(1, 6)):
            buf[rng.randrange(len(buf))] = rng.randrange(256)
        if rng.random() < 0.3:
            del buf[rng.randint(0, len(buf)) :]
        decode(0, bytes(buf), DLT_EN10MB)
