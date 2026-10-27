# Lab run sheet (remaining experiments)

For the isolated UTM lab only: Kali 10.77.0.10, Ubuntu victim 10.77.0.20.
Every script refuses to run on other addresses, sends a fixed, bounded amount
of traffic, and records what it did. Ground truth for each experiment is in
`experiments.toml` and was written before the run; never change it after
seeing a result. Already done, do not repeat: exp01, live-syn-01, benign-01
(1 h).

Rules for every run:

1. **Ubuntu first.** Start the capture and wait for `>>> Capture is running`.
2. Then Kali. Each Kali script asks you to type `capture-running`.
3. After Kali finishes, wait about 15 s, then `Ctrl-C` on Ubuntu
   (`victim-live-rss.sh` stops by itself).
4. Transfer `~/ng-captures/NAME.*` (Ubuntu) and `~/ng-experiments/NAME.*`
   (Kali) to the Mac. A failed or partial run is still a result: transfer it
   and say what happened.

## 0. Install the kit (once per VM)

On the Mac, copy this kit directory into the transfer share as `kit/`. Then
on **each** VM:

```bash
sudo cp -r /mnt/ng-transfer/kit ~/ng-kit && sudo chown -R "$USER": ~/ng-kit
cd ~/ng-kit && sha256sum -c SHA256SUMS
```

Ubuntu only, for the live runs:

```bash
export NETGUARD="python3 $HOME/ng-kit/netguard-lab.pyz"
$NETGUARD --version
```

Kali needs `nmap` (all scans) and `hping3` (exp10). Check with
`nmap --version; hping3 --version`.

## 1. Scans (one capture each, about 1-2 min)

For NAME in `exp02-connect-scan`, `exp07-udp-scan`, `exp03-xmas-scan`,
`exp04-fin-scan`, `exp05-null-scan`, `exp08-ping-sweep`, `exp09-frag-scan`,
in this order:

```bash
bash ~/ng-kit/victim-capture.sh NAME           # Ubuntu
bash ~/ng-kit/kali-run.sh NAME                  # Kali
```

`exp06-slow-scan` the same way; it takes about 12 minutes.
`exp10-syn-burst` last (1500 SYNs at about 100/s to one closed port).

## 2. Live early-warning delay (live-early-01, 2 min)

```bash
bash ~/ng-kit/victim-live-rss.sh live-early-01 120     # Ubuntu (uses $NETGUARD)
bash ~/ng-kit/kali-run.sh live-early-01                # Kali, after the ready line
```

Transfer `~/ng-captures/live-early-01.*` (pcap, jsonl, monitor, rss, meta,
sha256).

## 3. ARP binding change (exp11, under 1 min)

```bash
bash ~/ng-kit/victim-capture.sh exp11-arp-binding      # Ubuntu
sudo python3 ~/ng-kit/kali_arp_binding.py              # Kali
```

It refuses if 10.77.0.99 is in use. It announces only that unused address, so
no host's traffic is redirected.

## 4. DNS (exp12 and exp13, under 2 min each)

Three terminals: capture and queries on Ubuntu, responder on Kali.

```bash
bash ~/ng-kit/victim-capture.sh exp12-dns-nxdomain     # Ubuntu, terminal 1
sudo python3 ~/ng-kit/kali_dns_responder.py 300        # Kali
python3 ~/ng-kit/victim_dns_queries.py nxdomain        # Ubuntu, terminal 2
```

Then `Ctrl-C` the capture, and repeat with `exp13-dns-tunnel` and
`victim_dns_queries.py tunnel` (start the responder again if it has stopped).
The query script writes its record to `~/ng-captures/NAME.attack.txt` on
Ubuntu.

## 5. Connection rate and volume against a baseline (exp14, about 16 min)

```bash
bash ~/ng-kit/victim-capture.sh exp14-rate-volume      # Ubuntu, terminal 1
python3 ~/ng-kit/kali_rate_burst.py                    # Kali: 13 min baseline, then a burst
python3 ~/ng-kit/victim_volume_burst.py                # Ubuntu, terminal 2, ONLY when Kali says NOW
```

## On the Mac afterwards

```bash
python3 eval/lab/ingest.py /path/to/transfer-dir
uv run netguard lab evaluate --manifest eval/captures.toml
uv run python eval/lab/live_delay.py /path/to/live-early-01.jsonl --pcap /path/to/live-early-01.pcap
uv run python eval/lab/live_offline_equal.py /path/to/live-early-01.pcap /path/to/live-early-01.jsonl
uv run python eval/lab/real_regression.py captures --zeek
```
