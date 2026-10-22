"""Turn raw link-layer frames into :class:`~netguard.models.Packet` objects.

Every byte we parse here is attacker-controlled. The decoder therefore never
raises on malformed input: it returns ``None`` and the caller counts the error.
A crash in an IDS is itself a detection bypass.

Two paths produce the same :class:`Packet`:

* :func:`_fast_eth_ipv4` handles the overwhelmingly common case (untagged
  Ethernet, IPv4, first or only fragment, a complete TCP/UDP/ICMP header) with
  ``struct.unpack_from`` on the raw bytes. It accepts only frames whose headers
  are complete and consistent and returns ``None`` for anything else.
* everything else goes through dpkt (VLAN, IPv6, ARP, other link types,
  fragments, truncated or odd headers).

Because the fast path declines every frame it is not certain about, both paths
agree by construction; ``tests/test_decode.py`` checks that with a
differential fuzz test. The fast path roughly halves decode time, which is most
of NetGuard's per-packet cost.
"""

from __future__ import annotations

import socket
import struct
from typing import Any

import dpkt

from netguard.dns import DNS_PORT, DnsInfo, parse_dns
from netguard.models import Packet

ICMP_UNREACH = 3

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


_ETH_IPV4 = struct.Struct("!BBHHHBBH4s4s")
_TCP = struct.Struct("!HHIIH")
_UDP = struct.Struct("!HHH")
_ETH_TYPE_IPV4 = b"\x08\x00"


def mac_str(raw: bytes) -> str:
    return raw.hex(":")


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
        if linktype == DLT_EN10MB:
            pkt = _fast_eth_ipv4(ts, buf)
            if pkt is not None:
                return pkt
        return _decode(ts, buf, linktype)
    except (dpkt.UnpackError, ValueError, IndexError, struct.error):
        return None


def _fast_eth_ipv4(ts: float, buf: bytes) -> Packet | None:
    """Decode a clean Ethernet/IPv4/(TCP|UDP|ICMP) frame, or return ``None``."""
    if len(buf) < 34 or buf[12:14] != _ETH_TYPE_IPV4:
        return None
    vihl, _tos, total, _id, frag, ttl, proto, _sum, sip, dip = _ETH_IPV4.unpack_from(buf, 14)
    ihl = (vihl & 0x0F) * 4
    if vihl >> 4 != 4 or ihl < 20 or frag & 0x1FFF or (total and total < ihl):
        return None  # odd header or a non-first fragment: let dpkt decide
    l4 = 14 + ihl
    end = min(len(buf), 14 + total) if total else len(buf)
    avail = end - l4
    common = {
        "ts": ts,
        "length": len(buf),
        "src_mac": buf[6:12].hex(":"),
        "dst_mac": buf[0:6].hex(":"),
        "src_ip": socket.inet_ntoa(sip),
        "dst_ip": socket.inet_ntoa(dip),
        "ttl": ttl,
        "fragment": bool(frag & 0x2000),
        "frag_more": bool(frag & 0x2000),
        "ip_proto": proto,
    }
    if proto == 6:
        if avail < 20:
            return None
        sport, dport, seq, ack, off_flags = _TCP.unpack_from(buf, l4)
        hdr = (off_flags >> 12) * 4
        if hdr < 20 or hdr > avail:
            return None
        payload = max(total - ihl - hdr, 0) if total else avail - hdr
        return Packet(
            proto="tcp",
            src_port=sport,
            dst_port=dport,
            tcp_flags=off_flags & 0x1FF,
            tcp_seq=seq,
            tcp_ack=ack,
            payload_len=payload,
            **common,
        )
    if proto == 17:
        if avail < 8:
            return None
        sport, dport, ulen = _UDP.unpack_from(buf, l4)
        data = buf[l4 + 8 : end]
        return Packet(
            proto="udp",
            src_port=sport,
            dst_port=dport,
            payload_len=ulen - 8 if ulen >= 8 else len(data),
            dns=_dns(sport, dport, data),
            **common,
        )
    if proto == 1 and avail >= 8:
        icmp_type = buf[l4]
        orig_proto = orig_port = None
        if icmp_type == ICMP_UNREACH:
            quoted = _quoted_l4(buf[l4 + 8 : end])
            if quoted is None:
                return None  # unusual quote: let dpkt decide
            orig_proto, orig_port = quoted
        return Packet(
            proto="icmp",
            icmp_type=icmp_type,
            icmp_code=buf[l4 + 1],
            payload_len=(total - ihl if total else avail) - 8,
            icmp_orig_proto=orig_proto,
            icmp_orig_dst_port=orig_port,
            **common,
        )
    return None


def _quoted_l4(quote: bytes) -> tuple[str, int] | None:
    """Protocol and destination port of the IPv4 datagram quoted in an ICMP error."""
    if len(quote) < 20 or quote[0] >> 4 != 4:
        return None
    ihl = (quote[0] & 0x0F) * 4
    proto = {6: "tcp", 17: "udp"}.get(quote[9])
    total = struct.unpack_from("!H", quote, 2)[0]
    if ihl < 20 or proto is None or len(quote) < ihl + 4 or (total and total < ihl + 4):
        return None
    return proto, struct.unpack_from("!H", quote, ihl + 2)[0]


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

    if isinstance(ip, dpkt.ip.IP):
        fields["ttl"] = ip.ttl
        fields["ip_proto"] = ip.p
        # Total length can be 0 with TCP segmentation offload; fall back to the bytes we have.
        l4_len = ip.len - ip.hl * 4 if ip.len else None
        if ip.mf or ip.offset:
            fields["fragment"] = True
            fields["frag_more"] = bool(ip.mf)
            fields["frag_offset"] = ip.offset
            if ip.offset:
                # Only the first fragment carries the L4 header: never parse the
                # bytes of a later fragment as TCP/UDP (they are payload).
                size = l4_len if l4_len is not None else len(bytes(l4))
                return Packet(proto="ip-frag", payload_len=max(size, 0), **fields)
    else:
        fields["ttl"] = ip.hlim
        fields["ip_proto"] = ip.p
        # Without extension headers the IPv6 payload length is the L4 length.
        l4_len = ip.plen if ip.plen and ip.nxt == ip.p else None

    if isinstance(l4, dpkt.tcp.TCP):
        hdr = l4.off * 4
        return Packet(
            proto="tcp",
            src_port=l4.sport,
            dst_port=l4.dport,
            tcp_flags=l4.flags,
            tcp_seq=l4.seq,
            tcp_ack=l4.ack,
            payload_len=max(l4_len - hdr, 0) if l4_len is not None else len(l4.data),
            **fields,
        )
    if isinstance(l4, dpkt.udp.UDP):
        return Packet(
            proto="udp",
            src_port=l4.sport,
            dst_port=l4.dport,
            payload_len=l4.ulen - 8 if l4.ulen >= 8 else len(l4.data),
            dns=_dns(l4.sport, l4.dport, bytes(l4.data)),
            **fields,
        )
    if isinstance(l4, dpkt.icmp.ICMP):
        orig_proto = orig_port = None
        if l4.type == ICMP_UNREACH and isinstance(l4.data, dpkt.icmp.ICMP.Unreach):
            inner = l4.data.data
            if isinstance(inner, dpkt.ip.IP) and inner.p in (6, 17):
                orig_proto = "tcp" if inner.p == 6 else "udp"
                l4_inner = inner.data
                if isinstance(l4_inner, dpkt.tcp.TCP | dpkt.udp.UDP):
                    orig_port = l4_inner.dport
                elif len(l4_inner) >= 4:
                    orig_port = struct.unpack_from("!H", bytes(l4_inner), 2)[0]
                else:
                    orig_proto = None
        return Packet(
            proto="icmp",
            icmp_type=l4.type,
            icmp_code=l4.code,
            payload_len=max((l4_len if l4_len is not None else len(l4)) - 8, 0),
            icmp_orig_proto=orig_proto,
            icmp_orig_dst_port=orig_port,
            **fields,
        )
    if isinstance(l4, dpkt.icmp6.ICMP6):
        return Packet(proto="icmp6", icmp_type=l4.type, icmp_code=l4.code, **fields)
    size = l4_len if l4_len is not None else len(bytes(l4))
    return Packet(proto="ip-other", payload_len=max(size, 0), **fields)


def _dns(sport: int, dport: int, data: bytes) -> DnsInfo | None:
    """Parse DNS on UDP port 53, queries and responses.

    A malformed message only loses its DNS fields, never the packet: an
    exception here used to make the whole packet a decode error, so any UDP/53
    packet could be hidden from every detector (see ``dns.py``).
    """
    if DNS_PORT not in (sport, dport) or not data:
        return None
    return parse_dns(data)
