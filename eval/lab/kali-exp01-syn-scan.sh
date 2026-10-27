#!/usr/bin/env bash
# Experiment 01 on the Kali VM: a TCP SYN scan of ports 1-1000 of the Ubuntu
# victim, on the isolated lab network only (docs/LAB_SETUP.md).
#
#   bash kali-exp01-syn-scan.sh
#
# Start victim-capture.sh exp01-syn-scan on Ubuntu FIRST. This script refuses
# to run unless this host is 10.77.0.10, the target answers on the lab
# network, and you confirm that the capture is running. It writes
# ~/ng-experiments/exp01-syn-scan.attack.txt with the tool version, the exact
# command and UTC start/end times, for the manifest.
set -euo pipefail

ATTACKER="10.77.0.10"
TARGET="10.77.0.20"
NAME="exp01-syn-scan"
CMD=(sudo nmap -sS -Pn -n -p 1-1000 --max-retries 1 "$TARGET")

ip -o -4 addr show | awk '{print $4}' | grep -qx "$ATTACKER/[0-9]*" \
  || { echo "this host does not have $ATTACKER: not the lab attacker, refusing" >&2; exit 1; }
[[ "$(ip -o route get "$TARGET" | awk '{for (i = 1; i < NF; i++) if ($i == "src") print $(i + 1)}')" == "$ATTACKER" ]] \
  || { echo "$TARGET is not reached from $ATTACKER on the lab network, refusing" >&2; exit 1; }
ping -c 1 -W 2 "$TARGET" > /dev/null || { echo "$TARGET does not answer ping" >&2; exit 1; }

read -r -p "Is 'victim-capture.sh $NAME' running on Ubuntu? Type 'capture-running': " answer
[[ "$answer" == "capture-running" ]] || { echo "not confirmed; nothing was sent" >&2; exit 1; }

out="$HOME/ng-experiments"
mkdir -p "$out"
log="$out/$NAME.attack.txt"
{
  echo "name: $NAME"
  echo "tool: nmap"
  echo "tool_version: $(nmap --version | head -1)"
  echo "command: ${CMD[*]}"
  echo "start_utc: $(date -u +%Y-%m-%dT%H:%M:%S.%NZ)"
} > "$log"
"${CMD[@]}" -oN "$out/$NAME.nmap.txt"
echo "end_utc: $(date -u +%Y-%m-%dT%H:%M:%S.%NZ)" >> "$log"
cat "$log"
echo "Scan finished. Wait 15 s, then press Ctrl-C in the Ubuntu capture. Transfer $log to the Mac."
