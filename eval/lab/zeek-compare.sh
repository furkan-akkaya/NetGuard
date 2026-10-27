#!/usr/bin/env bash
# Compare NetGuard's flows with Zeek's for one capture (docs/CAPTURE_EVALUATION.md).
# Runs on the Mac (or any analysis host), never on the lab network. Zeek only
# reads the pcap; it is never pointed at a live interface.
#
#   bash eval/lab/zeek-compare.sh captures/exp01-syn-scan.pcap [eval/reports/exp01.zeek.json]
#
# Needs Zeek (`zeek`) and NetGuard (`uv run netguard` from the repo). If Zeek
# is not installed, it prints how to run it (including via Docker) and stops.
set -euo pipefail

pcap="${1:-}"
out="${2:-}"
[[ -f "$pcap" ]] || { echo "usage: $0 CAPTURE.pcap [OUT.json]" >&2; exit 2; }
[[ -n "$out" ]] || out="${pcap%.pcap}.zeek.json"

if ! command -v zeek > /dev/null; then
  cat >&2 <<EOF
zeek not found. Install it, or run it in a container, then re-run this script:

  docker run --rm -v "\$PWD:/w" -w /tmp zeek/zeek:latest \\
    zeek -r "/w/$pcap" LogAscii::use_json=T && mv /tmp/conn.log "\$PWD/conn.log"

With a local Zeek, in an EMPTY directory:
  zeek -r "$(cd "$(dirname "$pcap")" && pwd)/$(basename "$pcap")" LogAscii::use_json=T
  # add -C if the capture has checksum-offload artefacts (record that you did)
Then:  uv run netguard lab compare-flows "$pcap" conn.log > "$out"
EOF
  exit 1
fi

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
abspcap=$(cd "$(dirname "$pcap")" && pwd)/$(basename "$pcap")
( cd "$work" && zeek -r "$abspcap" LogAscii::use_json=T )
[[ -f "$work/conn.log" ]] || { echo "zeek produced no conn.log (no TCP/UDP in the capture?)" >&2; exit 1; }

echo "zeek version: $(zeek --version 2>&1 | head -1)" >&2
uv run netguard lab compare-flows "$pcap" "$work/conn.log" > "$out"
rc=$?
python3 - "$out" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
print(f"equal={d['equal']} matched={d['matched']} only_netguard={d['only_netguard']} only_zeek={d['only_zeek']}", file=sys.stderr)
PY
echo "wrote $out" >&2
exit $rc
