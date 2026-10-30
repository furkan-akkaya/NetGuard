# Installation and deployment

## Install

NetGuard needs Python ≥ 3.11 (tested on 3.11–3.14, Linux and macOS).

### From release artefacts (recommended)

A release (and every `release-dryrun.yml` run) ships, for version `V`
(currently `1.0.0rc3`):

| File | What it is |
|---|---|
| `netguard-V-py3-none-any.whl` | the package, dashboard included |
| `netguard-V.tar.gz` | the source archive (tests, docs, dashboard sources) |
| `netguard-V-requirements.txt` | the exact dependency versions it was tested with |
| `netguard-sbom.cdx.json` | CycloneDX SBOM of those same versions |
| `SHA256SUMS` | checksums of all of the above |

Verify, then install exactly the tested set into a fresh virtual environment:

```bash
sha256sum -c SHA256SUMS                       # macOS: shasum -a 256 -c SHA256SUMS
python3 -m venv ~/netguard
~/netguard/bin/pip install -c netguard-V-requirements.txt "netguard-V-py3-none-any.whl[web]"
~/netguard/bin/netguard --version
```

Without `-c`, pip picks the newest compatible versions, which were not tested
with that release. For the analyzer alone (one dependency, dpkt), leave out
`[web]`. To check that the SBOM matches what you installed:

```bash
python3 -c "import json; print(sorted((c['name'], c['version']) for c in json.load(open('netguard-sbom.cdx.json'))['components']))"
~/netguard/bin/pip list --format=freeze
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
sudo /opt/netguard/venv/bin/pip install -c netguard-V-requirements.txt "netguard-V-py3-none-any.whl[web]"
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
- pass the browser origin with `--allowed-origin https://netguard.lab.example`:
  state-changing requests must come from the server's exact origin (scheme,
  host and port) or an allowed one. Behind TLS the browser says `https://…`
  while NetGuard sees plain http, so without this flag uploads and profile
  changes from the dashboard get 403;
- keep the proxy's upload limit at or above `--max-upload-mb`.

## Live capture on the server

The service above does not capture. `netguard monitor` itself never needs
root: it reads packets from tcpdump. Two ways to give tcpdump the right, as a
normal user (see [LIVE_CAPTURE.md](LIVE_CAPTURE.md)):

- `netguard monitor --sudo -i IFACE` starts tcpdump through `sudo -n`; run
  `sudo -v` first. Nothing changes on the system. This is how the lab runs
  were made.
- Or grant tcpdump the capture capability once:
  `sudo setcap cap_net_raw,cap_net_admin=eip "$(command -v tcpdump)"`. This
  lets every user on the host capture; remove it with
  `sudo setcap -r "$(command -v tcpdump)"`.

## Upgrading

Stop the service, install the new wheel into the same virtual environment,
start it. The database schema migrates automatically on start; a database
from a newer NetGuard is refused rather than modified.

## Uninstalling

NetGuard installs nothing outside its virtual environment and the paths you
gave it. Remove what applies:

```bash
# Personal install
rm -rf ~/netguard                               # the virtual environment
rm -rf ./netguard-data                          # default `netguard serve --data-dir`, relative to where it ran

# Server install (systemd)
sudo systemctl disable --now netguard
sudo rm /etc/systemd/system/netguard.service && sudo systemctl daemon-reload
sudo rm -rf /opt/netguard /etc/netguard
sudo rm -rf /var/lib/netguard                   # stored captures, analyses and alerts: back up first if needed
sudo userdel netguard

# Only if you granted tcpdump the capability
sudo setcap -r "$(command -v tcpdump)"
```

Remove the Caddy site block if you added one. Captures written with
`monitor --write` stay wherever you wrote them.
