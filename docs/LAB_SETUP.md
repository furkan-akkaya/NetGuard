# Lab setup: validating NetGuard on real traffic

This guide builds an **isolated** lab on an Apple Silicon Mac with UTM:

```mermaid
flowchart LR
    subgraph Mac["macOS host (M1) — runs NetGuard offline"]
        subgraph HO["UTM host-only network (isolated)"]
            K["Kali (ARM64)<br/>attacker: nmap, arp-scan, bettercap"]
            U["Ubuntu Server (4 GB)<br/>victim: ssh, nginx, vsftpd + tcpdump"]
            K <--> U
        end
    end
```

> ⚠️ **Rules of engagement.** Run scans and ARP spoofing **only** on the
> host-only network. Never point them at your home, university (ITU) or ISP
> network. Scanning networks you do not own can be illegal, including under
> Turkish Penal Code art. 243–244, and violates acceptable-use policies.

## 1. Network

1. In UTM, set the network mode of **both VMs** to **Host Only**. The VMs can
   then reach each other and the Mac, but nothing beyond. UTM picks the subnet
   (often `192.168.128.0/24`); check it with `ip -br a` on each VM.
2. If you need internet access for package installs, add a *second* "Shared
   Network" NIC temporarily, install the packages, then remove it. Scan only
   the host-only interface.

## 2. Victim (Ubuntu Server 4 GB)

```bash
sudo apt update && sudo apt install -y tcpdump openssh-server nginx vsftpd
ip -br a                                   # note the host-only interface, e.g. enp0s1
```

Running services give the scans some *open* ports to find (22, 80, 21).

## 3. Attacker (Kali)

`nmap`, `arp-scan`, `masscan` and `bettercap` ship with Kali.

## 4. Capture an experiment

On **Ubuntu**, start one capture per experiment:

```bash
sudo tcpdump -i enp0s1 -s 0 -w ~/syn_scan.pcap
```

On **Kali** (replace `VICTIM`):

| Experiment | Command | Expected NetGuard result |
|---|---|---|
| SYN scan | `sudo nmap -sS VICTIM` | `portscan` HIGH, open 21/22/80 |
| Connect scan | `nmap -sT VICTIM` | `portscan` |
| XMAS / NULL / FIN | `sudo nmap -sX VICTIM` (`-sN`, `-sF`) | `portscan`, stealth noted |
| Slow scan | `sudo nmap -sS -T1 -p 1-50 VICTIM` | **probably missed** (known limitation) |
| UDP scan | `sudo nmap -sU --top-ports 50 VICTIM` | **missed** (no UDP detector yet) |
| ARP sweep | `sudo arp-scan --localnet` or `sudo nmap -sn 192.168.128.0/24` | `hostsweep` |
| Ping sweep (ICMP only) | `sudo nmap -sn -PE --send-ip 192.168.128.0/24` | `hostsweep` |
| ARP spoofing | `sudo bettercap -iface eth0 -eval "set arp.spoof.targets VICTIM; arp.spoof on"` (stop after 60 s) | `arpspoof` |
| Benign baseline | Use the victim normally for 1 h: `apt update`, browsing with `curl`, SSH sessions | **no alerts** is the goal |

Stop tcpdump with `Ctrl-C`, then copy the file to the Mac:

```bash
scp user@VICTIM:~/syn_scan.pcap captures/      # captures/ is git-ignored
uv run netguard analyze captures/syn_scan.pcap
```

> Note: the ARP-spoofing capture must be taken on the **victim** or on a host
> that sees the forged replies. With a host-only bridge, every VM sees
> broadcast ARP, and unicast replies addressed to the victim reach the victim.

## 5. Live mode on the victim

```bash
# On Ubuntu, after installing NetGuard (uv sync)
sudo tcpdump -i enp0s1 -U -w - 'not port 22' | uv run netguard analyze -f jsonl -
```

Filtering out your own SSH session (`not port 22`) keeps the analysis clean.

## 6. Recording results

For each experiment, record the tool version and the exact command, the
packet count, the alerts (`-f json`), and whether the outcome matched the
expectation. Then add a row to `EVALUATION.md § Real captures`. Do **not**
commit captures that contain anything personal. Lab-only pcaps can be shared
once you have checked them.
