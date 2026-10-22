# Installation and deployment

## Install

NetGuard needs Python ≥ 3.11 (tested on 3.11–3.14, Linux and macOS).

```bash
# From a release wheel (the dashboard is included):
python3 -m venv ~/netguard && ~/netguard/bin/pip install "netguard-0.8.0-py3-none-any.whl[web]"
# Analyzer only (one dependency: dpkt):
~/netguard/bin/pip install netguard-0.8.0-py3-none-any.whl
```

From source: `uv sync`, then `pnpm --dir frontend install && pnpm --dir frontend build`
to build the dashboard (see CONTRIBUTING.md).

**Verified (v0.8.0):** the wheel installed into a clean virtual environment on
macOS (Python 3.12) and in an Ubuntu 26.04 ARM64 container (Python 3.14):
`--version`, offline analysis, `lab evaluate`, `serve` with the dashboard,
uploads, the worker memory limit (a 40 MB limit stopped a large analysis
cleanly on Linux), and live capture on loopback as an unprivileged user with
`setcap`. The systemd unit below passes `systemd-analyze verify`
(exposure 1.6, "OK"); it has not been run under systemd on a real host yet.

## Ubuntu server (4 GB) with systemd

```bash
sudo useradd --system --shell /usr/sbin/nologin netguard
sudo python3 -m venv /opt/netguard/venv
sudo /opt/netguard/venv/bin/pip install "netguard-0.8.0-py3-none-any.whl[web]"
sudo install -m 0644 deploy/netguard.service /etc/systemd/system/netguard.service
sudo install -d -m 0750 /etc/netguard
python3 -c "import secrets; print('NETGUARD_API_TOKEN=' + secrets.token_urlsafe(32))" | sudo tee /etc/netguard/env >/dev/null
sudo chmod 0600 /etc/netguard/env
sudo systemctl daemon-reload && sudo systemctl enable --now netguard
curl -s http://127.0.0.1:8000/api/v1/health
```

The unit (`deploy/netguard.service`) runs NetGuard as an unprivileged user
with an empty capability set, a read-only system, no access to home
directories, a private /tmp, a system-call allowlist and `MemoryMax=2G`.
State lives in `/var/lib/netguard` (0700). It binds to 127.0.0.1; expose it
through a reverse proxy.

## TLS and remote access

NetGuard speaks plain HTTP. For access from other machines put a TLS reverse
proxy in front (`deploy/Caddyfile`), keep NetGuard on 127.0.0.1, and:

- set `NETGUARD_API_TOKEN` (the dashboard asks for it under Settings);
- pass the public name with `--allowed-host netguard.lab.example`: other Host
  names are refused (DNS-rebinding defence);
- keep the proxy's upload limit at or above `--max-upload-mb`.

## Live capture on the server

The service above does not capture. For `netguard monitor`, grant tcpdump the
capture capability once (`sudo setcap cap_net_raw,cap_net_admin=eip "$(command -v tcpdump)"`)
and run it as a normal user; see [LIVE_CAPTURE.md](LIVE_CAPTURE.md).

## Upgrading

Stop the service, install the new wheel into the same virtual environment,
start it. The database schema migrates automatically on start; a database
from a newer NetGuard is refused rather than modified.
