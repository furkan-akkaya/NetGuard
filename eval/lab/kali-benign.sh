#!/usr/bin/env bash
# Generate BENIGN client traffic from Kali to the Ubuntu victim's services, at
# a human pace, for the benign baseline (docs/LAB_SETUP.md). No scanning: this
# is what a normal user looks like, so NetGuard should raise no alerts. Run
# while victim-live-rss.sh captures on Ubuntu.
#
#   bash kali-benign.sh 3600
#
# Refuses unless it runs on 10.77.0.10 and the victim answers. Each cycle makes
# at most one connection every few seconds to ports the victim actually serves
# (probed once at start), so it never looks like a sweep or a port scan.
set -euo pipefail

ATTACKER="10.77.0.10"
VICTIM="10.77.0.20"
duration="${1:-3600}"
[[ "$duration" =~ ^[1-9][0-9]*$ ]] || { echo "usage: $0 SECONDS" >&2; exit 2; }

ip -o -4 addr show | awk '{print $4}' | grep -qx "$ATTACKER/[0-9]*" \
  || { echo "this host does not have $ATTACKER: not the lab attacker, refusing" >&2; exit 1; }
ping -c 1 -W 2 "$VICTIM" > /dev/null || { echo "$VICTIM does not answer ping, refusing" >&2; exit 1; }

# Which services does the victim actually offer? (one-off check, not part of the baseline window)
has_http=0; has_ssh=0
command -v curl > /dev/null && timeout 3 curl -s -o /dev/null "http://$VICTIM/" && has_http=1 || true
timeout 3 bash -c "exec 3<>/dev/tcp/$VICTIM/22" 2>/dev/null && { has_ssh=1; exec 3>&- 3<&-; } || true
echo "victim services seen: http=$has_http ssh=$has_ssh"
[[ "$has_http$has_ssh" == "00" ]] && echo "note: no http/ssh on the victim; only pings will be sent" >&2

end=$(( $(date +%s) + duration ))
cycles=0
while (( $(date +%s) < end )); do
  ping -c 1 -W 2 "$VICTIM" > /dev/null 2>&1 || true
  (( has_http )) && timeout 5 curl -s -o /dev/null "http://$VICTIM/" || true
  (( has_ssh )) && { timeout 3 bash -c "exec 3<>/dev/tcp/$VICTIM/22; head -c 64 <&3 >/dev/null; exec 3>&- 3<&-" 2>/dev/null || true; }
  cycles=$(( cycles + 1 ))
  sleep $(( 4 + RANDOM % 6 ))   # one cycle every 4-9 s
done
echo "benign traffic done: $cycles cycles over ${duration}s to $VICTIM"
