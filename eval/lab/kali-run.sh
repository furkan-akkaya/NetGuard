#!/usr/bin/env bash
# Run one labelled experiment from the Kali VM against the Ubuntu victim, on the
# isolated lab network only (docs/LAB_SETUP.md). Authorized use in a lab you own.
#
#   bash kali-run.sh exp01-syn-scan
#
# Start victim-capture.sh with the SAME name on Ubuntu FIRST, and wait for its
# ">>> Capture is running" line. This script refuses unless it runs on
# 10.77.0.10, the victim answers on the lab network, and you confirm the
# capture is running. Every command is bounded (fixed ports/counts/rates, no
# unbounded flooding) and targets only 10.77.0.20 (or the lab /24 for the
# sweep). It records ~/ng-experiments/NAME.attack.txt (tool, version, exact
# command, UTC start/end) and the tool's own output, for the manifest.
set -euo pipefail

ATTACKER="10.77.0.10"
VICTIM="10.77.0.20"
SUBNET="10.77.0.0/24"
name="${1:-}"

# Each experiment: the tool, the host to reach-check, and the exact command.
# Ground truth (expected detectors) lives in experiments.toml, not here.
tool="nmap"
target="$VICTIM"
case "$name" in
  exp01-syn-scan)    cmd=(sudo nmap -sS -Pn -n -p 1-1000 --max-retries 1 "$VICTIM") ;;
  exp02-connect-scan) cmd=(nmap -sT -Pn -n -p 1-1000 --max-retries 1 "$VICTIM") ;;
  exp03-xmas-scan)   cmd=(sudo nmap -sX -Pn -n -p 1-1000 --max-retries 1 "$VICTIM") ;;
  exp04-fin-scan)    cmd=(sudo nmap -sF -Pn -n -p 1-1000 --max-retries 1 "$VICTIM") ;;
  exp05-null-scan)   cmd=(sudo nmap -sN -Pn -n -p 1-1000 --max-retries 1 "$VICTIM") ;;
  exp06-slow-scan)   cmd=(sudo nmap -sS -Pn -n -T1 -p 1-50 --max-retries 1 "$VICTIM") ;;  # ~12 min
  exp07-udp-scan)    cmd=(sudo nmap -sU -Pn -n --top-ports 100 --max-retries 1 "$VICTIM") ;;
  exp08-ping-sweep)  cmd=(sudo nmap -sn -n "$SUBNET") ;;
  exp09-frag-scan)   cmd=(sudo nmap -sS -f -Pn -n -p 1-100 --max-retries 1 "$VICTIM") ;;
  exp10-syn-burst)
    # Bounded SYN burst to one closed port: 1500 packets at ~100/s (~15 s), no
    # final ACK, so it crosses the synflood threshold (>=500 attempts / 10 s,
    # <=20% completed) without unbounded flooding. The victim just sends RSTs.
    tool="hping3"
    cmd=(sudo hping3 -S -p 9 -i u10000 -c 1500 "$VICTIM") ;;
  "")  echo "usage: $0 NAME   (see experiments.toml / docs/LAB_SETUP.md)" >&2; exit 2 ;;
  *)   echo "unknown experiment: $name (see experiments.toml)" >&2; exit 2 ;;
esac

command -v "$tool" > /dev/null || { echo "$tool is not installed: nothing was sent" >&2; exit 1; }
ip -o -4 addr show | awk '{print $4}' | grep -qx "$ATTACKER/[0-9]*" \
  || { echo "this host does not have $ATTACKER: not the lab attacker, refusing" >&2; exit 1; }
[[ "$(ip -o route get "$VICTIM" | awk '{for (i = 1; i < NF; i++) if ($i == "src") print $(i + 1)}')" == "$ATTACKER" ]] \
  || { echo "$VICTIM is not reached from $ATTACKER on the lab network, refusing" >&2; exit 1; }
ping -c 1 -W 2 "$target" > /dev/null || { echo "$target does not answer ping on the lab network, refusing" >&2; exit 1; }

read -r -p "Is 'victim-capture.sh $name' running on Ubuntu (ready line shown)? Type 'capture-running': " answer
[[ "$answer" == "capture-running" ]] || { echo "not confirmed; nothing was sent" >&2; exit 1; }

out="$HOME/ng-experiments"
mkdir -p "$out"
log="$out/$name.attack.txt"
{
  echo "name: $name"
  echo "tool: $tool"
  echo "tool_version: $("$tool" --version 2>&1 | head -1)"
  echo "command: ${cmd[*]}"
  echo "start_utc: $(date -u +%Y-%m-%dT%H:%M:%S.%NZ)"
} > "$log"
status=0
"${cmd[@]}" > "$out/$name.tool.txt" 2>&1 || status=$?
{
  echo "end_utc: $(date -u +%Y-%m-%dT%H:%M:%S.%NZ)"
  echo "tool_exit_status: $status"
} >> "$log"
cat "$log"
echo "---"
echo "Experiment finished (tool exit $status). Wait ~15 s, then press Ctrl-C in the Ubuntu capture."
echo "Transfer $name.attack.txt and $name.tool.txt (with the pcap/sha256/meta) to the Mac."
