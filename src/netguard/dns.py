"""A minimal, defensive DNS message parser (header + first question).

Detectors need a handful of facts per DNS message: is it a query or a
response, the transaction id, the response code, how many answers, and the
first question's name and type. Parsing only that keeps the attack surface
small; resource records are never decoded.

Names are attacker-controlled bytes, not text. Labels are decoded as ASCII
with ``backslashreplace``, so a non-ASCII byte becomes the visible escape
``\\xc6`` instead of an exception (an earlier exception here hid the whole
packet from every detector). Names are lower-cased because DNS is
case-insensitive and attackers use 0x20 case randomisation.

Compression pointers are followed with a hop limit, so a pointer loop cannot
hang the parser.
"""

from __future__ import annotations

import math
import struct
from dataclasses import dataclass

DNS_PORT = 53
MAX_NAME_BYTES = 255
_MAX_POINTER_HOPS = 16
_HEADER = struct.Struct("!HHHHHH")

# Response codes (RFC 1035 §4.1.1, RFC 6895).
RCODE_NOERROR = 0
RCODE_SERVFAIL = 2
RCODE_NXDOMAIN = 3
RCODES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED"}

# Query types used by the detectors and in reports.
QTYPES = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 10: "NULL", 12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV"}
QTYPE_NULL = 10
QTYPE_TXT = 16


@dataclass(frozen=True, slots=True)
class DnsInfo:
    id: int
    response: bool
    opcode: int
    rcode: int
    qdcount: int
    ancount: int
    qname: str | None = None  # first question, lower-cased; None if absent or malformed
    qtype: int | None = None

    @property
    def rcode_name(self) -> str:
        return RCODES.get(self.rcode, str(self.rcode))

    @property
    def qtype_name(self) -> str | None:
        return None if self.qtype is None else QTYPES.get(self.qtype, str(self.qtype))


def parse_dns(data: bytes) -> DnsInfo | None:
    """Parse a DNS message carried over UDP. Returns ``None`` if the header is incomplete."""
    if len(data) < _HEADER.size:
        return None
    qid, flags, qdcount, ancount, _ns, _ar = _HEADER.unpack_from(data)
    qname: str | None = None
    qtype: int | None = None
    if qdcount:
        parsed = _read_name(data, _HEADER.size)
        if parsed is not None:
            qname, end = parsed
            if end + 4 <= len(data):
                qtype = struct.unpack_from("!H", data, end)[0]
            else:
                qname = None  # a question without type/class is malformed
    return DnsInfo(
        id=qid,
        response=bool(flags & 0x8000),
        opcode=(flags >> 11) & 0x0F,
        rcode=flags & 0x0F,
        qdcount=qdcount,
        ancount=ancount,
        qname=qname,
        qtype=qtype,
    )


def _read_name(data: bytes, pos: int) -> tuple[str, int] | None:
    """Read a (possibly compressed) name at ``pos``; return it and the offset after it."""
    labels: list[str] = []
    total = 0
    end: int | None = None  # where parsing continues after the first pointer
    hops = 0
    while True:
        if pos >= len(data):
            return None
        length = data[pos]
        if length == 0:
            pos += 1
            break
        if length & 0xC0 == 0xC0:  # compression pointer
            if pos + 1 >= len(data) or hops >= _MAX_POINTER_HOPS:
                return None
            if end is None:
                end = pos + 2
            pos = ((length & 0x3F) << 8) | data[pos + 1]
            hops += 1
            continue
        if length & 0xC0:  # 0x40/0x80: reserved label types
            return None
        label = data[pos + 1 : pos + 1 + length]
        if len(label) < length:
            return None
        total += length + 1
        if total > MAX_NAME_BYTES:
            return None
        labels.append(label.decode("ascii", "backslashreplace").lower())
        pos += 1 + length
    return ".".join(labels), end if end is not None else pos


# Second-level labels under which registrations happen one level deeper
# ("example.co.uk", "example.com.tr"). A small embedded heuristic instead of
# the full Public Suffix List: no dependency and no download, at the cost of
# occasionally treating a registrable domain as a subdomain (documented in the
# rule pages).
_SECOND_LEVEL = frozenset(
    {"ac", "co", "com", "edu", "gov", "gv", "ltd", "me", "mil", "ne", "net", "nom", "or", "org", "plc", "sch", "web"}
)


def registered_domain(name: str) -> str:
    """Approximate the registrable domain: ``a.b.example.co.uk`` → ``example.co.uk``."""
    labels = name.rstrip(".").split(".")
    if len(labels) >= 3 and len(labels[-1]) == 2 and labels[-2] in _SECOND_LEVEL:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def shannon_entropy(text: str) -> float:
    """Shannon entropy in bits per character (0 for empty or one repeated character).

    Random base32/hex/base64 strings score ~4-6 bits/char, English-like labels
    ~2.5-3.5. Short strings are biased low (a 5-character string has at most
    log2(5) ≈ 2.3 bits/char), so entropy is reported as evidence and never used
    alone on short names.
    """
    if not text:
        return 0.0
    counts: dict[str, int] = {}
    for ch in text:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(text)
    return abs(sum(c / n * math.log2(c / n) for c in counts.values()))  # abs: avoid -0.0
