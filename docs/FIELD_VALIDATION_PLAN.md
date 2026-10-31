# Remaining live validation

These are preregistered experiments, written before execution and left unchanged.
They were executed on 30 October 2026; results and deviations are in [FIELD_VALIDATION_RC3.md](FIELD_VALIDATION_RC3.md).
The release remains an RC until field evidence supports a stable claim.
Use only the isolated Kali `10.77.0.10` and Ubuntu `10.77.0.20` VMs.
Do not use the physical bistlab server, home network or internet targets.

## Access check on 30 October 2026

Both existing UTM VMs were initially stopped and could be started.
`utmctl exec` reported that the QEMU guest agent was absent or stopped.
The previous bridge services were stopped; fresh status requests received no matching response.
Interactive capture requires the owner's guest sudo session.
No new live traffic result is claimed from these access checks.
No NIC, route, sudo policy, credential or network isolation change is authorized by this plan.

## Long benign run

1. Build the exact clean release commit with `uv run python scripts/build_lab_kit.py`.
2. Transfer the kit through the existing non-network share and verify `SHA256SUMS` inside each VM.
3. Record VM CPU allocation, RAM, host model, OS, Python, tcpdump and kit `BUILD.json`.
4. On Ubuntu, run `NETGUARD="python3 /path/to/kit/netguard-lab.pyz" bash victim-live-rss.sh benign-rc2-r01 4500`.
5. After the ready message, run `bash kali-benign.sh 4200` on Kali.
6. Retain pcap, SHA-256, JSONL, monitor, metadata and resource CSV locally.
7. Repeat with fresh names for variability when access permits.

Expected before execution: zero final alerts for the paced known services.
Any unexpected alert is a false-positive candidate requiring inspection.
The 4,500-second capture exceeds one hour; a short or interrupted run does not qualify.
The generated benign workload is real live lab traffic, not ordinary production-user traffic.
Report that distinction explicitly.

## Controlled stepped load (three fresh runs)

1. Start `python3 stepped_connections.py server` on Ubuntu.
2. Start a fresh 1,200-second live capture on Ubuntu and wait for readiness.
3. Run `python3 stepped_connections.py client` on Kali and save its JSON output.
4. Repeat the entire run three times with fresh baselines and names.
5. Separately repeat the existing paced volume experiment at its bounded 1 MiB/s default.

The client sends 512-byte payloads to one consenting service on port 9098.
It warms up for 780 seconds at 0.2 successful connections/s.
Then it requests 1, 5, 10 and 25 successful connections/s for 60 seconds each.
Five failures stop the client; it never catches up with a burst.
The server refuses other peers and stops after 30 minutes.

Preregistered expectation: NG-RATE-001 after the rise to 5/s, provided a complete interval exceeds the learned threshold.
NG-VOL-001 is not expected for these small payloads.
Port scan, host sweep and SYN-flood rules are not expected for successful single-service traffic at these rates.
Window splitting and baseline adaptation can shift the first rate alert; retain the actual count and threshold.
The separate volume experiment expects NG-VOL-001 but does not establish exfiltration intent.

## Measurements and acceptance

The live helper samples RSS, kernel high-water RSS, analyser CPU ticks and monotonic time every five seconds.
Convert tick deltas using the recorded `CLK_TCK`; 100% means one logical CPU.
These metrics describe the analyser, excluding tcpdump and the traffic generator.
Calculate processed packets/s from the monitor total and measured monotonic runtime.
Report per-stage offered/achieved client rates, failures, CPU and RSS, with per-run ranges across repeats.
Report tcpdump kernel captured/received/dropped counters separately from decode errors.
Unknown drops, nonzero drops, truncated capture or early termination invalidate a clean-run claim.

Use `live_delay.py LIVE.jsonl --pcap SAME.pcap` for early-warning delays.
Baseline rules wait until a complete interval closes; they do not promise sub-second burst detection.
Use `live_offline_equal.py SAME.pcap LIVE.jsonl` and investigate every difference.
EOF tail differences can reflect live clock advancement; document actual affected alerts rather than suppressing them.
Never replay saved traffic at high speed and label it a live field experiment.

Old raw captures contain HTTP control tokens. Keep them private and outside all release assets.
Record only redacted numeric summaries in public documents.
