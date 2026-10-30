# Security policy

## Responsible use

NetGuard is a **defensive** tool. The lab scenarios and the lab guide describe
reconnaissance and ARP-spoofing techniques so that detections can be
validated. Only generate such traffic:

- in an isolated lab you own (see [docs/LAB_SETUP.md](docs/LAB_SETUP.md)), or
- on networks where you have **explicit written authorization**.

Captures can contain credentials and personal data. Handle pcaps as sensitive
data. The repository ignores `*.pcap`/`*.pcapng` by default.

## Threat model

[docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) lists every entry point, its
threats, the mitigations and the tests that pin them, plus accepted residual
risks. Deployment hardening: [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md).

## Running the API safely

`netguard serve` stores uploaded captures and their analysis results on disk.

- Requests with an unknown `Host` name are refused (DNS rebinding) and
  cross-origin state-changing requests are rejected; add the names a reverse
  proxy forwards with `--allowed-host`.
- It binds to `127.0.0.1` by default. To expose it, set `NETGUARD_API_TOKEN`
  (at least 16 characters, e.g. `python -c "import secrets; print(secrets.token_urlsafe(32))"`);
  the server refuses a non-loopback address without a token unless you pass
  `--insecure-no-auth` (only behind another authenticating proxy).
- The API speaks plain HTTP. Put TLS in front of it (a reverse proxy such as
  Caddy or nginx) whenever it leaves the machine, otherwise the token and the
  captures travel in clear text.
- Each analysis runs in a separate worker process with a timeout, a CPU limit
  and, on Linux, a memory limit (`--job-timeout`, `--job-memory-mb`).
  Uploads are capped (`--max-upload-mb`, `--max-storage-gb` in total) and must
  be pcap/pcapng; at most 100 analyses can be pending.
- The data directory contains captures (possibly credentials and personal
  data): restrict its permissions, back it up like sensitive data, and delete
  captures through the API when they are no longer needed.

## Reporting a vulnerability

NetGuard parses untrusted network input. If you find a crash, hang, or memory
blow-up that a crafted packet or capture file can trigger, please report it
privately through GitHub's **"Report a vulnerability"** (Security → Advisories)
instead of opening a public issue. Include a minimal pcap if possible.

## Supported versions

There is no stable release yet. Only the latest release candidate on `main`
(currently `1.0.0rc3`) receives fixes; earlier candidates are not patched.
