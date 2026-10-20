# Security policy

## Responsible use

NetGuard is a **defensive** tool. The lab scenarios and the lab guide describe
reconnaissance and ARP-spoofing techniques so that detections can be
validated. Only generate such traffic:

- in an isolated lab you own (see [docs/LAB_SETUP.md](docs/LAB_SETUP.md)), or
- on networks where you have **explicit written authorization**.

Captures can contain credentials and personal data. Handle pcaps as sensitive
data. The repository ignores `*.pcap`/`*.pcapng` by default.

## Reporting a vulnerability

NetGuard parses untrusted network input. If you find a crash, hang, or memory
blow-up that a crafted packet or capture file can trigger, please report it
privately through GitHub's **"Report a vulnerability"** (Security → Advisories)
instead of opening a public issue. Include a minimal pcap if possible.

## Supported versions

Only the latest release on `main` receives fixes during the 0.x series.
