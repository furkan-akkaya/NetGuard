import random

import dpkt
import pytest

from netguard.decode import DLT_EN10MB, DLT_LINUX_SLL, DLT_RAW, UnsupportedLinkType, decode
from netguard.lab.scenarios import ATTACKER, GATEWAY, RESOLVER, SERVER, WORKSTATION
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
