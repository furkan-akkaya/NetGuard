"""Build Ethernet frames for tests and lab scenarios.

Using real encoded frames (rather than hand-made ``Packet`` objects) means the
scenarios exercise the full pipeline: pcap reader -> decoder -> detectors.
"""

from __future__ import annotations

import socket
import struct
from collections.abc import Iterable
from pathlib import Path

import dpkt

from netguard.models import ACK, FIN, PSH, RST, SYN

Frame = tuple[float, bytes]

BROADCAST = "ff:ff:ff:ff:ff:ff"


def _mac(mac: str) -> bytes:
    return bytes(int(x, 16) for x in mac.split(":"))


def _ip4(ip: str) -> bytes:
    return socket.inet_aton(ip)


def _eth(src_mac: str, dst_mac: str, etype: int, payload: dpkt.Packet) -> bytes:
    return bytes(dpkt.ethernet.Ethernet(src=_mac(src_mac), dst=_mac(dst_mac), type=etype, data=payload))


def _ipv4(src: str, dst: str, proto: int, payload: dpkt.Packet) -> dpkt.ip.IP:
    ip = dpkt.ip.IP(src=_ip4(src), dst=_ip4(dst), p=proto, ttl=64, data=payload)
    ip.len = len(ip)  # dpkt fills in lengths/checksums when serialized
    return ip


class Host:
    """A lab host with fixed IP/MAC, to keep scenarios readable."""

    def __init__(self, ip: str, mac: str) -> None:
        self.ip = ip
        self.mac = mac

    def tcp(
        self, dst: Host, sport: int, dport: int, flags: int, payload: bytes = b"", seq: int = 1000, ack: int = 0
    ) -> bytes:
        seg = dpkt.tcp.TCP(sport=sport, dport=dport, flags=flags, seq=seq, ack=ack, data=payload)
        return _eth(self.mac, dst.mac, dpkt.ethernet.ETH_TYPE_IP, _ipv4(self.ip, dst.ip, dpkt.ip.IP_PROTO_TCP, seg))

    def tcp_to_ip(self, gateway: Host, dst_ip: str, sport: int, dport: int, flags: int) -> bytes:
        """TCP to an off-link IP: L2 destination is the gateway."""
        seg = dpkt.tcp.TCP(sport=sport, dport=dport, flags=flags, seq=1000)
        return _eth(self.mac, gateway.mac, dpkt.ethernet.ETH_TYPE_IP, _ipv4(self.ip, dst_ip, dpkt.ip.IP_PROTO_TCP, seg))

    def udp(self, dst: Host, sport: int, dport: int, payload: bytes = b"") -> bytes:
        dgram = dpkt.udp.UDP(sport=sport, dport=dport, data=payload)
        dgram.ulen = len(dgram)
        return _eth(self.mac, dst.mac, dpkt.ethernet.ETH_TYPE_IP, _ipv4(self.ip, dst.ip, dpkt.ip.IP_PROTO_UDP, dgram))

    def dns_query(
        self, resolver: Host, name: str, sport: int = 53000, qid: int = 1, qtype: int = dpkt.dns.DNS_A
    ) -> bytes:
        q = dpkt.dns.DNS(id=qid, qd=[dpkt.dns.DNS.Q(name=name, type=qtype, cls=dpkt.dns.DNS_IN)])
        return self.udp(resolver, sport, 53, bytes(q))

    def icmp_unreachable(self, to: Host, offending: bytes, code: int = 3) -> bytes:
        """ICMP destination unreachable quoting the IP header + 8 bytes of ``offending`` (an Ethernet frame)."""
        quote = bytes(dpkt.ethernet.Ethernet(offending).data)[:28]
        msg = dpkt.icmp.ICMP(type=3, code=code, data=dpkt.icmp.ICMP.Unreach(data=quote))
        return _eth(self.mac, to.mac, dpkt.ethernet.ETH_TYPE_IP, _ipv4(self.ip, to.ip, dpkt.ip.IP_PROTO_ICMP, msg))

    def icmp_echo(self, dst_ip: str, dst_mac: str, reply: bool = False, seq: int = 1) -> bytes:
        echo = dpkt.icmp.ICMP.Echo(id=0x4242, seq=seq, data=b"netguard")
        msg = dpkt.icmp.ICMP(type=0 if reply else 8, code=0, data=echo)
        return _eth(self.mac, dst_mac, dpkt.ethernet.ETH_TYPE_IP, _ipv4(self.ip, dst_ip, dpkt.ip.IP_PROTO_ICMP, msg))

    def arp_request(self, target_ip: str) -> bytes:
        arp = dpkt.arp.ARP(
            op=dpkt.arp.ARP_OP_REQUEST,
            sha=_mac(self.mac),
            spa=_ip4(self.ip),
            tha=b"\x00" * 6,
            tpa=_ip4(target_ip),
        )
        return _eth(self.mac, BROADCAST, dpkt.ethernet.ETH_TYPE_ARP, arp)

    def arp_reply(self, to: Host, claimed_ip: str | None = None) -> bytes:
        """ARP reply "``claimed_ip`` is at my MAC". Spoofing = claiming someone else's IP."""
        arp = dpkt.arp.ARP(
            op=dpkt.arp.ARP_OP_REPLY,
            sha=_mac(self.mac),
            spa=_ip4(claimed_ip or self.ip),
            tha=_mac(to.mac),
            tpa=_ip4(to.ip),
        )
        return _eth(self.mac, to.mac, dpkt.ethernet.ETH_TYPE_ARP, arp)


def dns_response(
    resolver: Host, client: Host, name: str, qid: int = 1, rcode: int = 0, dport: int = 53000, answers: int = 1
) -> bytes:
    """A DNS response; NOERROR responses carry ``answers`` A records."""
    an = [
        dpkt.dns.DNS.RR(name=name, type=dpkt.dns.DNS_A, cls=dpkt.dns.DNS_IN, ttl=60, ip=bytes([93, 184, 0, i + 1]))
        for i in range(answers if rcode == 0 else 0)
    ]
    r = dpkt.dns.DNS(
        id=qid,
        qr=dpkt.dns.DNS_R,
        rcode=rcode,
        qd=[dpkt.dns.DNS.Q(name=name, type=dpkt.dns.DNS_A, cls=dpkt.dns.DNS_IN)],
        an=an,
    )
    return resolver.udp(client, 53, dport, bytes(r))


def tcp_handshake(client: Host, server: Host, ts: float, sport: int, dport: int, data: int = 3) -> list[Frame]:
    """A complete, benign TCP connection: handshake, some data, FIN close.

    Sequence numbers advance like a real stack's (SYN and FIN consume one), so
    flow tracking sees no retransmissions.
    """
    c, s = 1000, 5000  # initial sequence numbers
    frames = [
        (ts, client.tcp(server, sport, dport, SYN, seq=c)),
        (ts + 0.001, server.tcp(client, dport, sport, SYN | ACK, seq=s, ack=c + 1)),
        (ts + 0.002, client.tcp(server, sport, dport, ACK, seq=c + 1, ack=s + 1)),
    ]
    c, s = c + 1, s + 1
    t = ts + 0.003
    for i in range(data):
        request, response = b"GET / HTTP/1.1\r\n" * (i + 1), b"x" * 512
        frames.append((t, client.tcp(server, sport, dport, ACK | PSH, request, seq=c, ack=s)))
        c += len(request)
        frames.append((t + 0.001, server.tcp(client, dport, sport, ACK | PSH, response, seq=s, ack=c)))
        s += len(response)
        t += 0.01
    frames.append((t, client.tcp(server, sport, dport, ACK | FIN, seq=c, ack=s)))
    frames.append((t + 0.001, server.tcp(client, dport, sport, ACK | FIN, seq=s, ack=c + 1)))
    frames.append((t + 0.002, client.tcp(server, sport, dport, ACK, seq=c + 1, ack=s + 1)))
    return frames


def syn_probe(scanner: Host, target: Host, ts: float, dport: int, open_: bool, flags: int = SYN) -> list[Frame]:
    """One scan probe and the target's reply (SYN-ACK if open, RST-ACK if closed)."""
    sport = 40000 + dport % 20000
    frames = [(ts, scanner.tcp(target, sport, dport, flags))]
    if flags == SYN and open_:
        frames.append((ts + 0.0005, target.tcp(scanner, dport, sport, SYN | ACK)))
        frames.append((ts + 0.0007, scanner.tcp(target, sport, dport, RST)))  # half-open scan resets
    elif flags == SYN or not open_:
        frames.append((ts + 0.0005, target.tcp(scanner, dport, sport, RST | ACK)))
    return frames


def write_pcap(path: str | Path, frames: Iterable[Frame]) -> int:
    count = 0
    with open(path, "wb") as fh:
        writer = dpkt.pcap.Writer(fh, linktype=dpkt.pcap.DLT_EN10MB)
        for ts, buf in sorted(frames, key=lambda f: f[0]):
            writer.writepkt(buf, ts=ts)
            count += 1
    return count


def bulk_transfer(
    client: Host, server: Host, ts: float, sport: int, dport: int, nbytes: int, duration: float, mss: int = 1448
) -> list[Frame]:
    """A TCP connection in which ``client`` uploads ``nbytes`` evenly over ``duration`` seconds.

    The server ACKs every 8th segment (delayed ACKs); enough realism for flow
    and volume statistics without doubling the frame count.
    """
    c, s = 1000, 5000
    frames = [
        (ts, client.tcp(server, sport, dport, SYN, seq=c)),
        (ts + 0.001, server.tcp(client, dport, sport, SYN | ACK, seq=s, ack=c + 1)),
        (ts + 0.002, client.tcp(server, sport, dport, ACK, seq=c + 1, ack=s + 1)),
    ]
    c += 1
    segments = max(1, -(-nbytes // mss))
    step = duration / segments
    chunk = b"\x00" * mss
    for i in range(segments):
        t = ts + 0.003 + i * step
        size = min(mss, nbytes - i * mss)
        frames.append((t, client.tcp(server, sport, dport, ACK | PSH, chunk[:size], seq=c, ack=s + 1)))
        c += size
        if i % 8 == 7:
            frames.append((t + step / 2, server.tcp(client, dport, sport, ACK, seq=s + 1, ack=c)))
    t = ts + 0.004 + duration
    frames.append((t, client.tcp(server, sport, dport, ACK | FIN, seq=c, ack=s + 1)))
    frames.append((t + 0.001, server.tcp(client, dport, sport, ACK | FIN, seq=s + 1, ack=c + 1)))
    frames.append((t + 0.002, client.tcp(server, sport, dport, ACK, seq=c + 1, ack=s + 2)))
    return frames


def fragment(frame: bytes, size: int) -> list[bytes]:
    """Split an Ethernet/IPv4 frame's IP payload into fragments of ``size`` bytes (like ``nmap -f``: 8)."""
    if size % 8:
        raise ValueError("fragment payload size must be a multiple of 8")
    eth = dpkt.ethernet.Ethernet(frame)
    ip = eth.data
    payload = bytes(ip.data)
    out = []
    for off in range(0, len(payload), size):
        chunk = payload[off : off + size]
        frag = dpkt.ip.IP(src=ip.src, dst=ip.dst, p=ip.p, ttl=ip.ttl, id=0x4E47, data=chunk)
        frag.offset = off
        frag.mf = int(off + size < len(payload))
        frag.len = 20 + len(chunk)
        out.append(bytes(dpkt.ethernet.Ethernet(src=eth.src, dst=eth.dst, type=eth.type, data=frag)))
    return out


def dhcp_ack(server: Host, client_mac: str, ip: str, lease_seconds: int = 86400, xid: int = 0x1234) -> bytes:
    """A DHCPACK from ``server`` assigning ``ip`` to ``client_mac`` (broadcast, as many servers send it)."""
    header = struct.pack("!BBBBIHH", 2, 1, 6, 0, xid, 0, 0x8000)
    header += b"\x00" * 4 + _ip4(ip) + _ip4(server.ip) + b"\x00" * 4
    header += _mac(client_mac) + b"\x00" * 10 + b"\x00" * 192
    options = (
        b"\x63\x82\x53\x63"
        + bytes([53, 1, 5])
        + bytes([54, 4])
        + _ip4(server.ip)
        + bytes([51, 4])
        + struct.pack("!I", lease_seconds)
        + b"\xff"
    )
    dgram = dpkt.udp.UDP(sport=67, dport=68, data=header + options)
    dgram.ulen = len(dgram)
    ip_pkt = _ipv4(server.ip, "255.255.255.255", dpkt.ip.IP_PROTO_UDP, dgram)
    return _eth(server.mac, BROADCAST, dpkt.ethernet.ETH_TYPE_IP, ip_pkt)
