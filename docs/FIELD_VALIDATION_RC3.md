# Field validation of 1.0.0rc3 (30 October 2026)

This records the execution of the preregistered [field validation plan](FIELD_VALIDATION_PLAN.md).
The analysed build is the `v1.0.0rc3` lab kit: source commit `fa42538`, `uncommitted_changes: false`.
Its `SHA256SUMS` (14 files) verified inside both VMs before any run.
Only the isolated Kali `10.77.0.10` and Ubuntu `10.77.0.20` VMs were used; no other host received experiment traffic.
All generated traffic is real live lab traffic, not ordinary production-user traffic.
Raw captures stay private, outside the repository and release assets; only numeric summaries and digests appear here.

## Deviations from the plan

These were deliberate, made or authorised by the owner, and none changes the analyser or the verified kit files.

1. **SSH control instead of "no ssh".** The owner enabled key-based ssh and passwordless sudo (`/etc/sudoers.d/ng-lab`) on both VMs.
   The plan had stated that no NIC, route, sudo policy, credential or isolation change was authorised; this run deviates on purpose.
   The owner also added non-persistent /32 routes on both VMs to the Mac's `192.168.128.1` and `10.77.0.1` addresses.
   The sudoers file is removed after the work; the 1.0.0 publication record confirms its removal.
2. **Kit transfer by scp** instead of the non-network share; hashes verified on arrival.
3. **Clock correction.** The VMs have no internet time source. Before correction Ubuntu was 24,905.8 s behind the Mac, Kali 0.038 s ahead.
   The Mac was itself within 0.4 ms of `time.apple.com`. Each VM clock was stepped to Mac time before every run, never during one.
4. **Mac traffic excluded from captures.** Experiments ran detached (`setsid nohup` on Ubuntu, `tmux` on Kali) and the launching ssh session closed.
   The live captures used the BPF filter `not host 192.168.128.1 and not host 10.77.0.1` through a `NETGUARD` wrapper outside the kit.
   The file-mode capture got the same filter through a `sudo` shim outside the kit that appends it to the `tcpdump -w` call.
5. **`sudo -v` shim on Ubuntu.** `sudo -v` asks for a password because the user also matches the password-protected sudo group rule.
   The shim maps only `sudo -v` to `sudo -n true`; every other call goes unchanged to `/usr/bin/sudo`.
6. **Names.** The benign run is `benign-rc3-r01` (the plan's text still said `benign-rc2-r01`); the volume repeat is `exp14-rate-volume-r03`.
   `kali_rate_burst.py`'s confirmation prompt was answered on stdin; its fixed-name record was renamed afterwards and the earlier record restored.
7. **Old bridge token files deleted.** Both `~/ng-control/token` files were deleted after owner approval.
   No process, listener (TCP 8766/8767), systemd unit or crontab entry for the bridges existed beforehand.
   No token was present in the other files in those directories.

Five short smoke captures (`smoke-rc3-00` to `-04`, 15-28 s) only tested this harness and are not evidence.
The first two started traffic after a 20 s window had ended; this was a launch bug in the harness, not a NetGuard fault.

## Environment

| | Kali (traffic) | Ubuntu (sensor) |
|---|---|---|
| OS, kernel | Kali Rolling, 6.11.2-arm64 | Ubuntu 26.04.1 LTS, 7.0.0-31-generic aarch64 |
| vCPU, RAM | 4, 3.8 GiB | 4, 3.3 GiB |
| Python, tcpdump | 3.14.7, 4.99.5 | 3.14.4, 4.99.6 |

Host: MacBook Air (M1, 16 GiB), macOS 27.2, UTM; analyser `CLK_TCK` 100, default CLI settings, no `--config`.
Ubuntu also runs an unrelated Portainer container (TCP 9443); no container traffic appears in any capture.

## Capture integrity

| Run | Mode | Duration | Packets | Kernel drops | Mac IPv4 packets | Mac-MAC IPv6 mDNS |
|---|---|---|---|---|---|---|
| benign-rc3-r01 | live | 4,504 s | 4,862 | 0 | 0 | 28 |
| exp15-load-r01 | live | 1,205 s | 26,192 | 0 | 0 | 8 |
| exp15-load-r02 | live | 1,205 s | 26,199 | 0 | 0 | 12 |
| exp15-load-r03 | live | 1,205 s | 26,193 | 0 | 0 | 4 |
| exp14-rate-volume-r03 | file, 64 MiB buffer | 1,020 s | 40,284 | 0 | 0 | 4 |

Durations are the helpers' monotonic measurements (benign request 4,500 s; load 1,200 s; file capture `timeout` 1,020 s).
Every live run exited 0 and has captured = received-by-filter.
Offline analysis of all five pcaps reports 0 decode errors, 0 skipped blocks and no truncation.
No packet to or from `192.168.128.1` or `10.77.0.1`, and no ssh control traffic, remained in any capture.
The only Mac-originated packets are IPv6 link-local mDNS announcements from the Mac's bridge interface, which the IPv4 host filter cannot exclude.

## Results against the preregistered expectations

| Expectation | Observed | Verdict |
|---|---|---|
| Benign, ≥ 1 h uninterrupted: zero final alerts | 4,504 s, 0 final and 0 early alerts | met |
| Load: NG-RATE-001 after the rise to 5/s | Every run: one NG-RATE-001 for `10.77.0.10`, first on the first complete interval dominated by 5/s | met, 3/3 |
| Load: no NG-VOL-001, scan, sweep or SYN-flood alert | None in any run | met, 3/3 |
| Volume repeat: NG-VOL-001 (exp14 also expects NG-RATE-001) | NG-VOL-001 for `10.77.0.20` and NG-RATE-001 for `10.77.0.10`, nothing else | met |
| Live final alerts equal offline analysis of the same pcap | Equal in all four live runs (0, 1, 1, 1) | met |

### Stepped load (exp15)

Client rates achieved (connections/s) and analyser CPU (percent of one logical CPU, mean over the stage):

| Stage (target) | Achieved r01 / r02 / r03 | Failures | CPU mean, range | CPU max 5 s | RSS max |
|---|---|---|---|---|---|
| 0.2/s, 780 s | 0.200 / 0.200 / 0.200 | 0 | 0.07-0.08 % | 0.2-0.4 % | 34.2-34.7 MiB |
| 1/s, 60 s | 1.000 / 1.000 / 1.000 | 0 | 0.16-0.18 % | 0.2-0.4 % | 34.2-34.7 MiB |
| 5/s, 60 s | 4.999 / 5.000 / 5.000 | 0 | 0.47-0.51 % | 0.6-0.8 % | 34.4-34.9 MiB |
| 10/s, 60 s | 9.998 / 9.999 / 10.000 | 0 | 0.81-0.83 % | 1.0 % | 34.6-35.1 MiB |
| 25/s, 60 s | 24.998 / 24.999 / 24.998 | 0 | 1.55-1.63 % | 2.0 % | 35.1-35.6 MiB |

Whole runs: 21.8 processed packets/s, peak VmHWM 35.1-35.6 MiB, 2,618-2,621 flows. Benign: 1.08 packets/s, 0.07 % mean CPU, VmHWM 34.3 MiB.
The pcap SYN count per stage matched the client's successes (±1 at stage boundaries).

| Run | Learned baseline (conn/60 s) | Threshold | First alert interval | Reported | After crossing packet | Final: intervals, total |
|---|---|---|---|---|---|---|
| r01 | 13.9 ± 1.9 (13 intervals) | 34.8 | 152 conn (36 s at 1/s + 23 s at 5/s) | 23.2 s into the 5/s stage | 0.194 s | 4, 2,436 |
| r02 | 19.2 ± 7.1 (14) | 61.9 | 325 conn (55 s at 5/s + 5 s at 10/s) | 65.7 s after the 5/s start | 0.695 s | 3, 2,374 |
| r03 | 17.7 ± 5.7 (14) | 51.8 | 309 conn (58 s at 5/s + 2 s at 10/s) | 62.1 s after the 5/s start | 0.308 s | 3, 2,390 |

The 1/s stage alone never alerts: 60 connections per interval exceed the learned threshold but not `min_count` 100.
In r02 and r03 the stage start fell late in a minute, so the interval holding the 1/s-to-5/s change (80 and 67 connections) stayed below `min_count`.
It was learned into the baseline, which raised mean and deviation; the first alert came at the close of the next, mostly 5/s, interval.
This is the window splitting and baseline adaptation the plan anticipated, not a missed detection.
Baseline rules report when a complete 60 s interval closes; they do not promise sub-second burst detection.

### Volume repeat (exp14-rate-volume-r03)

780 s paced baseline (122 cycles), then 300/300 answered SSH banner reads at 10/s, then one 50,331,648-byte upload paced at 1 MiB/s (48.0 s).
NG-RATE-001 for `10.77.0.10`: 170 connections peak, threshold 23.3 over 9.32 ± 0.38, 2 intervals, 306 connections.
NG-VOL-001 for `10.77.0.20`: 42.2 MB in one interval, 5.6 Mbit/s, threshold max(30,830 B learned, 20 MB floor).
This run used file mode as in exp14, so there is no live stream to compare. The alert does not establish exfiltration intent.

## Clock and delay evaluation

Offsets (VM − Mac) were measured over a persistent ssh session (best 5 of 25, RTT 0.5-1.1 ms).
After each correction they were within ±0.8 ms. Measured drift before the next correction:

| Interval | Kali | Ubuntu |
|---|---|---|
| benign (89 min) | +213 ms | +40 ms |
| each 20 min load run | +50 to +51 ms | +10 ms |
| volume repeat (17 min) | +42 ms | +8 ms |

The early-warning delays above use only the Ubuntu clock: kernel packet timestamps, NetGuard's `reported_at` and pcap-anchored stage boundaries.
Cross-host drift therefore does not affect them.
As a cross-check, Kali's client start preceded Ubuntu's first SYN by 60-69 ms, which includes the client's start-up, at offsets under 1 ms.

## Evidence

Retained privately on the Mac under `~/netguard-field-rc3/incoming/` with an 83-file `SHA256SUMS`: pcap, digest, JSONL, monitor, metadata, resource CSV, console logs, client JSON and clock logs.
Each file was hashed on its VM, transferred by scp and verified on the Mac.

```text
43e7250a95ddb4a23a8a16f2c3658bf408d62c9960d88e6ea515fb1d116ab6d8  benign-rc3-r01.pcap
f9bd88e414ac8b1745e3f32df89d78fc87cca7135cc3a56d752e4b88692d727b  exp15-load-r01.pcap
c75540ed1bec5cb581e8253d11d3f14a07b7cdaa3b3732f370865dd253ff7dfb  exp15-load-r02.pcap
8d80c57fd2fc101f404aa1eb85946157d0778c287738afa8b091fe6f0a57e9dc  exp15-load-r03.pcap
ba393e72248250300670032e5aed753682848f8f76bcc02cfccc0596f5c304bd  exp14-rate-volume-r03.pcap
```

## What this does and does not show

It closes the plan's open gap: an uninterrupted live run longer than one hour and three repeated live runs under stepped load.
Each had zero kernel drops and matched its preregistered expectation.
It is still one lab host pair with generated traffic at low rates (≤ 25 connections/s, ≤ 1 MiB/s).
It is not a false-positive rate for real networks, nor a throughput limit; one benign run gives no variability estimate.
Confidence scores remain heuristic, not attack probabilities. Fixed-window blind spots, Linux-only worker memory limits and the lack of fragment reassembly are unchanged.
