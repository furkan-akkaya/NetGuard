# Live capture and replay

`netguard monitor` analyses traffic from one network interface as it happens;
`netguard replay` feeds a recorded capture through the same live pipeline.
Design: [ADR-0010](adr/0010-live-capture-and-alert-lifecycle.md).

> **Authorisation.** Capture only on networks you own or are explicitly
> authorised to monitor. Captures contain other people's data; treat saved
> pcaps as sensitive (`--write` creates them with mode `0600`).

## Permissions (NetGuard never runs as root)

NetGuard refuses to run as root: it parses untrusted bytes. The capture
permission goes to `tcpdump`, which NetGuard starts as a child process.

| Platform | One-time setup (recommended) | Alternative |
|---|---|---|
| Linux | `sudo setcap cap_net_raw,cap_net_admin=eip "$(command -v tcpdump)"` | `--sudo` |
| macOS | Install Wireshark's *ChmodBPF* (adds your user to `access_bpf`, makes `/dev/bpf*` readable), log out and in | `--sudo` |

`--sudo` runs `sudo -n tcpdump … -Z $USER`: `-n` never prompts (it needs a
sudoers rule such as `analyst ALL=(root) NOPASSWD: /usr/bin/tcpdump`), and
`-Z` makes tcpdump drop to your user right after opening the device.

Without permission NetGuard stops with the exact fix for your platform:

```text
netguard: error: tcpdump has no permission to capture on lo0.
macOS: give your user access to the BPF devices (Wireshark's 'ChmodBPF' package, ...)
```

## Usage

```bash
netguard monitor --list                                   # capture interfaces (tcpdump -D)
netguard monitor -i eth0                                  # until Ctrl-C
netguard monitor -i eth0 --filter 'not port 22' --duration 3600 --write /var/tmp/ng.pcap
netguard monitor -i en0 -f jsonl | tee alerts.ndjson      # JSON Lines for a SIEM shipper
netguard replay capture.pcap --speed 10                   # 10x the recorded pace
netguard replay capture.pcap --speed 0 -f jsonl           # as fast as possible
```

| Option | Default | Meaning |
|---|---|---|
| `-i, --interface` | required | One interface; `any` is refused (name what you are authorised to watch) |
| `--filter` | none | BPF filter, passed to tcpdump as one argument (never through a shell) |
| `--duration` / `--count` | none | Stop after N seconds / packets |
| `--snaplen` | 262144 | Bytes captured per packet (64–262144) |
| `--write`, `--write-limit-mb` | off, 1024 | Also save the raw capture; writing stops at the limit, analysis continues |
| `--status-every` | 30 | Status line on stderr every N seconds (0 = off) |
| `--no-early-warning` | off | Report incidents only when they close |
| `-c, --config`, `-f text\|jsonl` | | As for `analyze` |

Ctrl-C (or SIGTERM) stops tcpdump cleanly, analyses the frames still in
flight, reports every open incident and prints a summary on stderr. Actual
output of a replay of the `slow_scan` lab capture:

```text
replay of slow_scan.pcap at 100x: end of capture after 15.4s; 201 packets, 100 flows, 1 alerts
(detection delay median 90.0s, max 90.0s)
```

For `monitor` the summary also lists tcpdump's own statistics: packets
captured, received by filter and **dropped by kernel**. Dropped packets are
traffic the OS discarded because NetGuard (or tcpdump) could not keep up; a
non-zero value means some traffic was not analysed. Narrow the filter or the
interface if it grows.

## Alerts while it runs

With early warnings (the default for `monitor` and `replay`) each incident can
produce two alerts with the same `alert_id`:

- `stage: "early"` as soon as it crosses its threshold (evidence so far);
- `stage: "final"` when it closes (complete evidence).

`reported_at - first_seen` is the detection delay. Incidents older than
`[alerts] max_incident_age_seconds` (default 3600) are reported and restarted
even if the activity never pauses.

Measured time-to-detect on the lab scenarios is in
[EVALUATION.md § Detection delay](EVALUATION.md#detection-delay).

## Replay notes

- Final alerts of a replay equal those of `netguard analyze` on the same file
  (tested), because everything runs on the capture's own clock.
- During replay the clock advances with the pace: at `--speed 100` one second
  of silence is 100 seconds of capture time, so early warnings appear with
  that granularity. `benchmarks/detection_delay.py` measures delays precisely.
- Replay feeds the analysis only. Replaying packets *onto a network*
  (`tcpreplay`) needs root and belongs in the isolated lab ([LAB_SETUP.md](LAB_SETUP.md)).

## Validating live = offline (lab)

On the lab victim (Ubuntu), with tcpdump allowed to capture:

```bash
netguard monitor -i enp0s1 --write live.pcap -f jsonl > live.ndjson   # while Kali runs nmap
netguard analyze -f json live.pcap > offline.json
# final alerts in live.ndjson == alerts in offline.json (same alert_id and summary)
```
