# ADR-0005: Own capture-file readers and a fast decode path

- **Status:** Accepted (amends [ADR-0001](0001-python-and-dpkt.md))
- **Date:** 2026-10-22

## Context

ADR-0001 chose dpkt for parsing. Auditing Phase 1 found three problems:

1. **Multi-interface pcapng was decoded wrongly.** dpkt's pcapng reader reads
   only the first Interface Description Block. In `dumpcap -i eth0 -i lo`
   captures every loopback frame was decoded as Ethernet garbage.
2. **Unbounded allocation from a length field.** dpkt's pcap reader calls
   `read(caplen)` with the record's `caplen` unchecked, so one hostile record
   header (`caplen = 0xFFFFFFFF`) turns the rest of the input, up to 4 GiB,
   into a single frame held in memory. Measured on v0.1 with a stream
   (`… | netguard analyze -`): a 40-byte header followed by 300 MB of data
   produced one 300 MB "packet" and 628 MB peak RSS; the new reader rejects
   the record at 31 MB RSS.
3. **Decode cost.** Profiling the reference benchmark showed ~60% of runtime
   in dpkt object construction (three Python objects per packet, plus
   bit-field properties), which flow tracking then pushed ~28% past the
   v0.1 baseline.

## Decision

1. **`formats.py` implements the pcap and pcapng container formats** (≈250
   lines, standard library only). Every length field is checked against
   `MAX_RECORD_BYTES` (16 MiB) before reading. pcapng interfaces are tracked
   per section with their own link type, `if_tsresol` and `if_tsoffset`.
   A truncated final record is normal (a killed `tcpdump`): it ends the stream
   and sets `CaptureInfo.truncated`. Structural corruption raises
   `CaptureFormatError`. Unknown block types are skipped and counted.
2. **Frames with an unsupported link type are counted, not fatal**, so one
   exotic interface does not abort a multi-interface capture.
3. **`decode.py` gets a `struct`-based fast path** for untagged
   Ethernet/IPv4 with a complete TCP, UDP or ICMP header. It accepts only
   frames whose headers are complete and self-consistent and returns `None`
   otherwise; dpkt then handles the frame (VLAN, IPv6, ARP, fragments,
   truncated or odd headers). Equivalence is enforced by a differential test:
   5 000 mutated frames, and wherever the fast path accepts one its `Packet`
   must equal dpkt's.

dpkt stays for everything else (IPv6, ARP, link layers, DNS). Replacing it
completely would mean re-implementing well-tested dissectors for little gain.

## Alternatives considered

- **Patch dpkt upstream.** Worth doing and still planned, but we cannot depend
  on a release cadence for a security bound we need now.
- **scapy:** an order of magnitude slower than dpkt (ADR-0001).
- **pyshark / tshark:** an external process and dependency, and still not
  bounded by us.
- **A Rust/PyO3 decoder:** the right step if Python is ever the bottleneck at
  line rate; premature now (it would also complicate installation).

## Consequences

- Reference benchmark (242 003 frames, M1): 3.4–3.9 s before, ~2.2 s after,
  *including* the new flow tracking. Alerts on all lab scenarios are identical
  before and after.
- Fuzzing found that dpkt raises `UnicodeDecodeError` for non-UTF-8 DNS query
  names; the old decoder turned this into a decode error for the **whole
  packet**, so any UDP/53 packet could be hidden from every detector. The DNS
  helper now catches it and only loses the query name.
- Two parsers must stay in agreement; the differential test guards that and
  must be extended whenever the fast path learns a new protocol.
