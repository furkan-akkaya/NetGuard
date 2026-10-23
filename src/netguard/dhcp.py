"""Minimal DHCPv4 parser: the fields needed to explain IP-to-MAC changes.

Parses the BOOTP header (RFC 2131 §2) and walks the options for the message
type (53), server identifier (54) and lease time (51). Everything else is
ignored. Option lengths are checked against the buffer, so a truncated or
hostile message yields ``None`` or fewer fields, never an exception.
"""

from __future__ import annotations

import socket
import struct
from dataclasses import dataclass

DHCP_PORTS = frozenset({67, 68})
MAGIC_COOKIE = b"\x63\x82\x53\x63"
_FIXED = 236  # BOOTP header before the magic cookie
ACK = 5
MESSAGE_TYPES = {1: "DISCOVER", 2: "OFFER", 3: "REQUEST", 4: "DECLINE", 5: "ACK", 6: "NAK", 7: "RELEASE", 8: "INFORM"}


@dataclass(frozen=True, slots=True)
class DhcpInfo:
    op: int  # 1 request (client), 2 reply (server)
    xid: int
    msg_type: int | None
    client_mac: str | None  # chaddr, when the hardware type is Ethernet
    your_ip: str  # yiaddr: the address the server assigns
    server_id: str | None
    lease_seconds: int | None

    @property
    def msg_name(self) -> str:
        return MESSAGE_TYPES.get(self.msg_type or 0, str(self.msg_type))


def parse_dhcp(data: bytes) -> DhcpInfo | None:
    if len(data) < _FIXED + 4 or data[_FIXED : _FIXED + 4] != MAGIC_COOKIE:
        return None
    op, htype, hlen = data[0], data[1], data[2]
    xid = struct.unpack_from("!I", data, 4)[0]
    yiaddr = socket.inet_ntoa(data[16:20])
    mac = data[28:34].hex(":") if htype == 1 and hlen == 6 else None
    msg_type = server_id = lease = None
    pos = _FIXED + 4
    while pos < len(data):
        code = data[pos]
        if code == 255:  # end
            break
        if code == 0:  # pad
            pos += 1
            continue
        if pos + 1 >= len(data):
            break
        length = data[pos + 1]
        value = data[pos + 2 : pos + 2 + length]
        if len(value) < length:
            break
        if code == 53 and length == 1:
            msg_type = value[0]
        elif code == 54 and length == 4:
            server_id = socket.inet_ntoa(value)
        elif code == 51 and length == 4:
            lease = struct.unpack("!I", value)[0]
        pos += 2 + length
    return DhcpInfo(op, xid, msg_type, mac, yiaddr, server_id, lease)
