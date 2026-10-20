"""Small factories so tests read like scenarios, not like struct packing."""

from __future__ import annotations

from netguard.models import Packet


def tcp(ts: float, src: str, dst: str, dport: int, flags: int, sport: int = 40000) -> Packet:
    return Packet(
        ts=ts, length=60, proto="tcp", src_ip=src, dst_ip=dst, src_port=sport, dst_port=dport, tcp_flags=flags
    )


def icmp(ts: float, src: str, dst: str, icmp_type: int = 8) -> Packet:
    return Packet(ts=ts, length=98, proto="icmp", src_ip=src, dst_ip=dst, icmp_type=icmp_type, icmp_code=0)


def arp(
    ts: float, op: int, sender_ip: str, sender_mac: str, target_ip: str, target_mac: str = "00:00:00:00:00:00"
) -> Packet:
    return Packet(
        ts=ts,
        length=42,
        proto="arp",
        arp_op=op,
        arp_sender_ip=sender_ip,
        arp_sender_mac=sender_mac,
        arp_target_ip=target_ip,
        arp_target_mac=target_mac,
    )
