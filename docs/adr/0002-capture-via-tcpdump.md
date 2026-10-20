# ADR-0002: Offline-first; live capture is delegated to tcpdump

- **Status:** Accepted
- **Date:** 2026-10-20

## Context

Live capture needs raw-socket privileges: root, or `CAP_NET_RAW` on Linux.
A security tool that parses hostile input **while running as root** turns any
parser bug into a privilege-escalation vector. Live capture is also hard to
test reproducibly.

## Decision

NetGuard reads pcap and pcapng **streams**. Live monitoring is a pipeline:

```bash
sudo tcpdump -i eth0 -U -w - | netguard analyze -f jsonl -
```

`tcpdump` opens the interface. It can drop privileges with `-Z user`, and its
capture code is hardened and widely audited. NetGuard runs as an unprivileged
user. The reader sniffs the magic number on a non-seekable stream, so it works
with pipes.

## Consequences

- One code path for offline and live analysis. Tests drive it with files and
  with simulated pipes (`tests/test_sources.py`).
- No dependency on libpcap bindings (pypcap, pcapy), whose maintenance has
  been patchy.
- Live alerts arrive with a latency of `idle_timeout_seconds` (see ADR-0003).
- Ring-buffer capture and rotation can be done with `tcpdump -G/-W` or
  `dumpcap -b` without any NetGuard changes.
