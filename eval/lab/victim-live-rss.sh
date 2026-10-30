#!/usr/bin/env bash
# Run NetGuard live on the Ubuntu victim's lab interface for a fixed time,
# writing the pcap and the JSONL alert stream and sampling the analyser's
# memory (RSS) throughout (docs/LAB_SETUP.md § 7-8). Used for the benign
# baseline, the resource measurement, and the live-vs-offline comparison.
#
#   NETGUARD="python3 /mnt/ng-transfer/netguard-lab.pyz" bash victim-live-rss.sh benign-01 3600
#
# NetGuard runs as your normal user and starts tcpdump via `sudo -n` (--sudo);
# `sudo -v` first caches the credential so the one-time spawn needs no setcap
# and no password prompt mid-run. It changes nothing on the system and
# captures only on the 10.77.0.x interface.
set -euo pipefail

LAB_PREFIX="10.77.0."
SAMPLE_SECONDS=5
PCAP_HEADER_BYTES=24   # a libpcap global header: written once tcpdump opens the device
name="${1:-}"
duration="${2:-3600}"
[[ "$name" =~ ^[a-z0-9][a-z0-9-]{0,62}$ ]] || { echo "usage: $0 NAME [SECONDS]" >&2; exit 2; }
[[ "$duration" =~ ^[1-9][0-9]*$ ]] || { echo "SECONDS must be a positive integer" >&2; exit 2; }
[[ "$(id -un)" != "root" ]] || { echo "run as your normal user, not root (--sudo drops privileges with -Z)" >&2; exit 2; }

# NetGuard runner: $NETGUARD, else the lab .pyz on the share, else netguard in PATH.
if [[ -n "${NETGUARD:-}" ]]; then read -r -a ng <<< "$NETGUARD"
elif [[ -f /mnt/ng-transfer/netguard-lab.pyz ]]; then ng=(python3 /mnt/ng-transfer/netguard-lab.pyz)
elif command -v netguard > /dev/null; then ng=(netguard)
else echo "no NetGuard runner: set NETGUARD, or put netguard-lab.pyz on the share" >&2; exit 1; fi
"${ng[@]}" --version > /dev/null || { echo "NetGuard runner does not work: ${ng[*]}" >&2; exit 1; }
command -v tcpdump > /dev/null || { echo "tcpdump not found" >&2; exit 1; }

iface=$(ip -o -4 addr show | awk -v p="$LAB_PREFIX" 'index($4, p) == 1 {print $2; exit}')
[[ -n "$iface" ]] || { echo "no interface with a ${LAB_PREFIX}x address: not on the lab network, refusing" >&2; exit 1; }

out="$HOME/ng-captures"; mkdir -p "$out"
pcap="$out/$name.pcap"; jsonl="$out/$name.jsonl"; rss="$out/$name.rss.csv"
meta="$out/$name.meta.txt"; mon="$out/$name.monitor.txt"
[[ ! -e "$pcap" ]] || { echo "$pcap exists; choose another NAME" >&2; exit 1; }

echo "tcpdump will be started via sudo; enter your password if asked (once)."
sudo -v || { echo "sudo failed: not starting. Nothing was captured." >&2; exit 1; }

{
  echo "name: $name"
  echo "host: $(hostname) $(. /etc/os-release && echo "$PRETTY_NAME") $(uname -r) $(uname -m)"
  echo "interface: $iface $(ip -o -4 addr show dev "$iface" | awk '{print $4}')"
  echo "netguard: $("${ng[@]}" --version 2>&1 | head -1)"
  echo "tcpdump: $(tcpdump --version 2>&1 | head -1)"
  echo "python: $(python3 --version 2>&1)"
  echo "logical_cpus: $(getconf _NPROCESSORS_ONLN)"
  echo "cpu_ticks_per_second: $(getconf CLK_TCK)"
  echo "memory_kb: $(awk '/^MemTotal:/ {print $2}' /proc/meminfo)"
  echo "config: default CLI settings; no --config argument"
  echo "duration_requested_s: $duration"
  echo "start_utc: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
} > "$meta"

echo "epoch,rss_kb,hwm_kb,cpu_ticks,monotonic_s" > "$rss"
start_mono=$(awk '{print $1; exit}' /proc/uptime)   # CLOCK_MONOTONIC seconds (immune to wall-clock jumps)
"${ng[@]}" monitor -i "$iface" --sudo --duration "$duration" --write "$pcap" -f jsonl > "$jsonl" 2> "$mon" &
ngpid=$!

# Readiness: a failed capture (permission, bad interface, sudo) makes NetGuard
# exit within a second or two (measured: good interface -> tcpdump child in
# ~0.5 s; bad interface -> exit in ~0.8 s). So after a short grace, a still
# running monitor with a live tcpdump capture process means the capture really
# started. The written pcap is buffered by NetGuard and flushed only at the
# end, so its size cannot be polled for readiness.
ready=0
sleep 3
if kill -0 "$ngpid" 2>/dev/null; then
  if pgrep -f "tcpdump.*-i $iface" > /dev/null 2>&1; then
    ready=1
    echo ">>> Capture is running on $iface for ${duration}s. Generate benign traffic from Kali now. <<<"
  else
    echo "!!! NetGuard is running but no tcpdump capture process is present; see $mon. Stopping." >&2
    kill -INT "$ngpid" 2>/dev/null || true
  fi
else
  echo "!!! NetGuard exited before capturing (see $mon). Nothing usable was captured." >&2
fi

# Sample the analyser's memory until it exits. VmHWM is the kernel's own peak
# RSS high-water mark, so it catches a startup peak the 5 s sampling would miss.
while kill -0 "$ngpid" 2>/dev/null; do
  read -r rss_kb hwm_kb < <(awk '/^VmRSS:/ {r=$2} /^VmHWM:/ {h=$2} END {print r+0, h+0}' "/proc/$ngpid/status" 2>/dev/null || echo "0 0")
  cpu_ticks=$(awk '{sub(/^.*\) /, ""); print $12+$13}' "/proc/$ngpid/stat" 2>/dev/null || echo 0)
  mono=$(awk '{print $1; exit}' /proc/uptime)
  [[ "$rss_kb" -gt 0 ]] && echo "$(date +%s),$rss_kb,$hwm_kb,$cpu_ticks,$mono" >> "$rss"
  sleep "$SAMPLE_SECONDS"
done
status=0; wait "$ngpid" || status=$?
now_mono=$(awk '{print $1; exit}' /proc/uptime)
elapsed=$(awk -v a="$start_mono" -v b="$now_mono" 'BEGIN {print int(b - a)}')

sampled_peak=$(awk -F, 'NR > 1 && $2 + 0 > m {m = $2} END {print m + 0}' "$rss")
hwm_peak=$(awk -F, 'NR > 1 && $3 + 0 > m {m = $3} END {print m + 0}' "$rss")
samples=$(( $(wc -l < "$rss") - 1 ))
finals=$(python3 - "$jsonl" <<'PY'
import json, sys
n = 0
try:
    for line in open(sys.argv[1], encoding="utf-8"):
        line = line.strip()
        if line and json.loads(line).get("stage") == "final":
            n += 1
except OSError:
    n = -1
print(n)
PY
)
pcap_bytes=$(stat -c %s "$pcap" 2>/dev/null || echo 0)

# The CLI prints these with spaces, not underscores ("kernel dropped by kernel: N").
# `|| true`: a failed run has no summary, and under `set -e -o pipefail` an
# empty grep would end the script here, before the verdict below.
drops=$(grep -oE 'kernel dropped by kernel: [0-9]+' "$mon" 2>/dev/null | grep -oE '[0-9]+$' | tail -1 || true)
kcap=$(grep -oE 'kernel captured: [0-9]+' "$mon" 2>/dev/null | grep -oE '[0-9]+$' | tail -1 || true)
krecv=$(grep -oE 'kernel received by filter: [0-9]+' "$mon" 2>/dev/null | grep -oE '[0-9]+$' | tail -1 || true)
truncated=no; grep -q 'write truncated' "$mon" 2>/dev/null && truncated=yes

{
  echo "stop_utc: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "measured_elapsed_s_monotonic: $elapsed"
  echo "monitor_exit_status: $status"
  echo "capture_started: $ready"
  echo "pcap_bytes: $pcap_bytes"
  echo "write_truncated: $truncated"
  echo "rss_samples: $samples"
  echo "sampled_peak_rss_kb: $sampled_peak"
  echo "peak_rss_hwm_kb: $hwm_peak"
  echo "final_alert_events: $finals"
  echo "kernel_captured: ${kcap:-unknown}"
  echo "kernel_received_by_filter: ${krecv:-unknown}"
  echo "kernel_dropped_by_kernel: ${drops:-unknown}"
} >> "$meta"

[[ "$pcap_bytes" -ge "$PCAP_HEADER_BYTES" ]] && (cd "$out" && sha256sum "$name.pcap" > "$name.sha256")

echo "--- NetGuard summary:"; tail -2 "$mon" 2>/dev/null || true
echo "--- meta:"; cat "$meta"

# Honest verdict. A run is clean only if tcpdump started, the monitor exited 0,
# RSS was actually sampled (HWM > 0), the run lasted essentially the requested
# time (not 54 min for a 60 min request), the kernel drop count is KNOWN and
# zero, and the written pcap was not truncated.
problems=()
(( ready )) || problems+=("tcpdump never started")
[[ "$status" -eq 0 ]] || problems+=("monitor exit status $status")
[[ "$samples" -ge 1 && "$hwm_peak" -gt 0 ]] || problems+=("no RSS/HWM samples")
[[ "$elapsed" -ge $(( duration - 5 )) ]] || problems+=("ran only ${elapsed}s of requested ${duration}s")
[[ -n "$drops" ]] || problems+=("kernel drop count unknown (could not parse the monitor summary)")
[[ "${drops:-1}" == "0" ]] || problems+=("kernel dropped ${drops:-?} packets")
[[ "$truncated" == "no" ]] || problems+=("written pcap was truncated at the size limit")
if (( ${#problems[@]} )); then
  echo "RESULT: NEEDS REVIEW — $(IFS='; '; echo "${problems[*]}"). Do not record this as a clean run." >&2
  exit 1
fi
echo "RESULT: ran ${elapsed}s (monotonic), peak analyser RSS $((hwm_peak / 1024)) MB (VmHWM), $samples samples, $finals final alert events, kernel drops 0."
echo "Transfer $name.{pcap,sha256,jsonl,meta.txt,rss.csv} to the Mac."
