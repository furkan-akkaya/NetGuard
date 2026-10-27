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

command -v tcpdump > /dev/null || { echo "tcpdump not found: nothing was captured" >&2; exit 1; }

out="$HOME/ng-captures"
mkdir -p "$out"
pcap="$out/$name.pcap"
err="$out/$name.tcpdump.txt"
meta="$out/$name.meta.txt"
[[ ! -e "$pcap" ]] || { echo "$pcap exists; choose another NAME" >&2; exit 1; }

# Ask for the password now, so the prompt is not mixed into tcpdump's output
# and a refusal stops here; tcpdump itself then runs with sudo -n (no prompt).
echo "tcpdump needs sudo; enter your password if asked."
sudo -v || { echo "sudo failed: nothing was captured. Do NOT start the experiment." >&2; exit 1; }

{
  echo "name: $name"
  echo "host: $(hostname) $(. /etc/os-release && echo "$PRETTY_NAME") $(uname -r) $(uname -m)"
  echo "interface: $iface $(ip -o -4 addr show dev "$iface" | awk '{print $4}')"
  echo "tcpdump: $(tcpdump --version 2>&1 | head -1)"
  echo "start_utc: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
} > "$meta"

# --immediate-mode: hand every packet to tcpdump at once; otherwise libpcap's
# ring buffer holds them and Ctrl-C soon after the last packet loses them
# without counting them as kernel drops (seen in testing: 11 received, 0 written).
# -U: write every packet to the file at once.
cmd=(sudo -n tcpdump -i "$iface" -n -s 0 --immediate-mode -U -Z "${USER:-$(id -un)}" -w "$pcap")
[[ -z "$duration" ]] || cmd=(sudo -n timeout -s INT "$duration" "${cmd[@]:2}")

# tcpdump's messages go straight to a file (its final packet and drop counts
# must survive Ctrl-C); background jobs ignore Ctrl-C, so tail keeps showing
# them and the watcher announces readiness only after tcpdump itself reports
# "listening on".
: > "$err"
tail -s 0.1 -n +1 -f "$err" >&2 &
shower=$!
(
  for _ in $(seq 1 100); do
    if grep -q "listening on" "$err"; then
      echo ">>> Capture is running on $iface. Start the experiment on Kali now; press Ctrl-C here when it has finished. <<<"
      exit 0
    fi
    sleep 0.1
  done
  echo "!!! tcpdump has not reported 'listening on' after 10 s: do NOT start the experiment. Press Ctrl-C." >&2
) &
watcher=$!

trap 'true' INT  # Ctrl-C stops tcpdump, not this script
status=0
"${cmd[@]}" 2> "$err" || status=$?
trap - INT
sleep 0.3
kill "$watcher" "$shower" 2> /dev/null || true
wait "$watcher" "$shower" 2> /dev/null || true

if ! grep -q "listening on" "$err" || [[ ! -s "$pcap" ]]; then
  echo "FAILED: tcpdump did not start capturing (exit status $status). Nothing was captured; see $err" >&2
  echo "result: failed (tcpdump exit status $status)" >> "$meta"
  rm -f "$pcap"
  exit 1
fi

{
  echo "stop_utc: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "tcpdump_exit_status: $status"
  # tcpdump's own summary: "N packets captured", "... received by filter", "... dropped by kernel"
  awk '/packets captured/ {print "captured: " $1} /received by filter/ {print "received_by_filter: " $1}
       /dropped by kernel/ {print "kernel_dropped: " $1}' "$err"
} >> "$meta"
(cd "$out" && sha256sum "$name.pcap" > "$name.sha256")
cat "$meta" "$out/$name.sha256"
echo "Done. Transfer $name.pcap, $name.sha256 and $name.meta.txt from $out to the Mac."
