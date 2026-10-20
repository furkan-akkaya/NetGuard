"""Turn raw link-layer frames into :class:`~netguard.models.Packet` objects.

Every byte we parse here is attacker-controlled. The decoder therefore never
raises on malformed input: it returns ``None`` and the caller counts the error.
A crash in an IDS is itself a detection bypass.
"""

from __future__ import annotations

import socket
import struct
from typing import Any

import dpkt

from netguard.models import Packet

# Link-layer types (https://www.tcpdump.org/linktypes.html)
DLT_NULL = 0  # BSD loopback, e.g. macOS lo0
DLT_EN10MB = 1  # Ethernet
DLT_RAW = 101  # raw IPv4/IPv6
DLT_RAW_ALT = 12  # raw IP on some BSDs
DLT_LOOP = 108  # OpenBSD loopback
DLT_LINUX_SLL = 113  # Linux "any" interface cooked capture

SUPPORTED_LINKTYPES = frozenset({DLT_NULL, DLT_EN10MB, DLT_RAW, DLT_RAW_ALT, DLT_LOOP, DLT_LINUX_SLL})


class UnsupportedLinkType(ValueError):
    pass


def mac_str(raw: bytes) -> str:
    return ":".join(f"{b:02x}" for b in raw)


def _ip_str(raw: bytes) -> str:
    family = socket.AF_INET if len(raw) == 4 else socket.AF_INET6
    return socket.inet_ntop(family, raw)


def decode(ts: float, buf: bytes, linktype: int = DLT_EN10MB) -> Packet | None:
    """Decode one frame. Returns ``None`` if the frame is malformed.

    Raises :class:`UnsupportedLinkType` for link types we cannot parse at all,
    because silently dropping *every* packet would hide a configuration error.
    """
    if linktype not in SUPPORTED_LINKTYPES:
        raise UnsupportedLinkType(f"unsupported link type {linktype}")
    try:
        return _decode(ts, buf, linktype)
    except (dpkt.UnpackError, ValueError, IndexError, struct.error):
        return None


def _decode(ts: float, buf: bytes, linktype: int) -> Packet:
    fields: dict[str, Any] = {"ts": ts, "length": len(buf)}
    payload: Any

    if linktype == DLT_EN10MB:
        eth = dpkt.ethernet.Ethernet(buf)
        fields["src_mac"] = mac_str(eth.src)
        fields["dst_mac"] = mac_str(eth.dst)
        payload = eth.data
    elif linktype == DLT_LINUX_SLL:
        payload = dpkt.sll.SLL(buf).data
    elif linktype in (DLT_NULL, DLT_LOOP):
        payload = dpkt.loopback.Loopback(buf).data
    else:  # DLT_RAW / DLT_RAW_ALT
        version = buf[0] >> 4 if buf else 0
        payload = dpkt.ip.IP(buf) if version == 4 else dpkt.ip6.IP6(buf)

    if isinstance(payload, dpkt.arp.ARP):
        return _arp(fields, payload)
    if isinstance(payload, dpkt.ip.IP | dpkt.ip6.IP6):
        return _ip(fields, payload)
    return Packet(proto="other", **fields)


def _arp(fields: dict[str, Any], arp: dpkt.arp.ARP) -> Packet:
    # Only Ethernet/IPv4 ARP is meaningful for spoofing detection.
    if len(arp.sha) != 6 or len(arp.spa) != 4:
        return Packet(proto="other", **fields)
    return Packet(
        proto="arp",
        arp_op=arp.op,
        arp_sender_mac=mac_str(arp.sha),
        arp_sender_ip=_ip_str(arp.spa),
        arp_target_mac=mac_str(arp.tha),
        arp_target_ip=_ip_str(arp.tpa),
        **fields,
    )


def _ip(fields: dict[str, Any], ip: Any) -> Packet:
    fields["src_ip"] = _ip_str(ip.src)
    fields["dst_ip"] = _ip_str(ip.dst)
    l4 = ip.data

    if isinstance(l4, dpkt.tcp.TCP):
        return Packet(proto="tcp", src_port=l4.sport, dst_port=l4.dport, tcp_flags=l4.flags, **fields)
    if isinstance(l4, dpkt.udp.UDP):
        return Packet(
            proto="udp",
            src_port=l4.sport,
            dst_port=l4.dport,
            dns_query=_dns_query(l4),
            **fields,
        )
    if isinstance(l4, dpkt.icmp.ICMP):
        return Packet(proto="icmp", icmp_type=l4.type, icmp_code=l4.code, **fields)
    if isinstance(l4, dpkt.icmp6.ICMP6):
        return Packet(proto="icmp6", icmp_type=l4.type, icmp_code=l4.code, **fields)
    return Packet(proto="ip-other", **fields)


def _dns_query(udp: dpkt.udp.UDP) -> str | None:
    """Return the first question name of a DNS query on port 53, if any."""
    if udp.dport != 53 or not udp.data:
        return None
    try:
        dns = dpkt.dns.DNS(bytes(udp.data))
    except (dpkt.UnpackError, IndexError, struct.error):
        return None
    if dns.qr != dpkt.dns.DNS_Q or not dns.qd:
        return None
    return str(dns.qd[0].name)
