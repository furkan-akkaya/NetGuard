#!/usr/bin/env bash
# Capture one lab experiment on the Ubuntu victim VM (docs/LAB_SETUP.md).
#
#   bash victim-capture.sh exp01-syn-scan            # stop with Ctrl-C after the attack
#   bash victim-capture.sh benign-01 3600            # stop automatically after 3600 s
#
# Captures only on the interface that holds a 10.77.0.0/24 address (the
# isolated lab network) and refuses to run otherwise. Writes into
# ~/ng-captures/: NAME.pcap, NAME.sha256 and NAME.meta.txt (tcpdump version,
# interface, UTC start/stop and tcpdump's packet and kernel-drop counts).
set -euo pipefail

LAB_PREFIX="10.77.0."
name="${1:-}"
duration="${2:-}"
[[ "$name" =~ ^[a-z0-9][a-z0-9-]{0,62}$ ]] || { echo "usage: $0 NAME [SECONDS]  (NAME: a-z, 0-9, -)" >&2; exit 2; }
[[ -z "$duration" || "$duration" =~ ^[1-9][0-9]*$ ]] || { echo "SECONDS must be a positive integer" >&2; exit 2; }

iface=$(ip -o -4 addr show | awk -v p="$LAB_PREFIX" 'index($4, p) == 1 {print $2; exit}')
[[ -n "$iface" ]] || { echo "no interface with a ${LAB_PREFIX}x address: not on the lab network, refusing" >&2; exit 1; }

out="$HOME/ng-captures"
mkdir -p "$out"
pcap="$out/$name.pcap"
[[ ! -e "$pcap" ]] || { echo "$pcap exists; choose another NAME" >&2; exit 1; }

meta="$out/$name.meta.txt"
{
  echo "name: $name"
  echo "host: $(hostname) $(. /etc/os-release && echo "$PRETTY_NAME") $(uname -r) $(uname -m)"
  echo "interface: $iface $(ip -o -4 addr show dev "$iface" | awk '{print $4}')"
  echo "tcpdump: $(tcpdump --version 2>&1 | head -1)"
  echo "start_utc: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
} > "$meta"

cmd=(sudo tcpdump -i "$iface" -n -s 0 -Z "${USER:-$(id -un)}" -w "$pcap")
[[ -z "$duration" ]] || cmd=(sudo timeout -s INT "$duration" "${cmd[@]:1}")
echo "Capturing on $iface into $pcap"
echo ">>> Capture is running. Start the experiment on Kali now; press Ctrl-C here when it has finished. <<<"
trap 'true' INT  # Ctrl-C stops tcpdump, not this script
"${cmd[@]}" 2> >(tee "$out/$name.tcpdump.txt" >&2) || true
trap - INT
sleep 1

{
  echo "stop_utc: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  # tcpdump's own summary: "N packets captured", "... received by filter", "... dropped by kernel"
  awk '/packets captured/ {print "captured: " $1} /received by filter/ {print "received_by_filter: " $1}
       /dropped by kernel/ {print "kernel_dropped: " $1}' "$out/$name.tcpdump.txt"
} >> "$meta"
(cd "$out" && sha256sum "$name.pcap" > "$name.sha256")
cat "$meta" "$out/$name.sha256"
echo "Done. Transfer $name.pcap, $name.sha256 and $name.meta.txt from $out to the Mac."
