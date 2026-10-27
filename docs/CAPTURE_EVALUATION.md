# Evaluating labelled captures

The synthetic scorecard is a regression test, not real-network accuracy.
This workflow pins a separate experiment's bytes and expected entities before
running NetGuard, then reports misses and false positives without tuning them away.

## Capture manifest

Copy `eval/captures.example.toml` to `eval/captures.toml`. Replace all placeholders.
Each `[[captures]]` entry requires:

| Field | Meaning |
|---|---|
| `name` | Unique experiment name |
| `path` | Capture file, relative to the manifest (absolute paths also work) |
| `sha256` | SHA-256 of the complete, stopped capture (`shasum -a 256 captures/FILE.pcap`) |
| `kind` | `attack` or `benign` |
| `provenance` | `lab`, `public`, or `synthetic`; each has a separate score |
| `tool`, `tool_version`, `command` | Tool name, its exact version (e.g. `nmap --version`) and the exact experiment command, recorded as text only (never executed) |
| `expected` | Array of `{ detector = "...", entity = "..." }`; `[]` for benign traffic |
| `config` | Optional configuration file, relative to the manifest |
| `note` | Optional sensor position, limitations, dataset license and lab context |

Entity conventions match the synthetic evaluator:

| Detector | Entity |
|---|---|
| `portscan`, `udpscan` | `scanner_ip->target_ip` |
| `synflood` | Target IP |
| `arpspoof` | IP whose ARP binding changed |
| `trw`, `hostsweep`, `dnstunnel`, `nxdomain`, `fragments`, `connrate`, `volume` | Alert source (IP or MAC, depending on the rule) |

Read the corresponding rule page before declaring labels. Write the expected
behavior from the experiment design, not from NetGuard's output. Label separate
files for separate experiments, including benign look-alikes. A manifest may
contain 1–256 files; duplicate names, duplicate file hashes, unknown keys and
unknown detectors are rejected. The manifest itself is limited to 1 MiB.

```bash
netguard lab evaluate --manifest eval/captures.toml
netguard lab evaluate --manifest eval/captures.toml --format json > captures/evaluation.json
netguard lab evaluate --manifest eval/captures.toml --strict
```

Exit codes: **0** means evaluation completed, **1** means `--strict` found
false positives, false negatives or capture-quality warnings, **2** means invalid
input or an operational failure. Without `--strict`, misses are reported but
are not command failures. `lab evaluate` without a manifest keeps its original
synthetic scorecard; `--strict` intentionally fails its known FP/FN cases.

A wrong checksum, a missing, empty, truncated or non-regular file, non-finite
timestamps, or a file that changes during evaluation prevents the score from
being printed (exit 2). Out-of-order timestamps (common in multi-interface
pcapng), malformed or unsupported frames and state evictions produce warnings
and make strict mode fail. Review
these warnings before using any accuracy number.

## Reading the measurements

- TP/FP/FN count distinct `(detector, entity)` pairs per capture. Repeated
  incidents for one entity are one FP, but **raw final alert count** preserves
  the operational noise. Early and final stages do not double the score.
- Precision and recall use `null` / `N/A` when the denominator is zero. A
  quiet benign capture does not have "100% recall".
- Benign alerts/hour uses final incidents divided by first-to-last packet
  duration. A zero-duration capture has no rate. Capture at least one hour of
  representative benign activity; a quiet interface with two distant packets
  is not a representative one-hour baseline. Packet loss can bias this rate.
- Delay is `reported_at - first_seen` with early warnings enabled, during
  **packet-driven offline analysis**. It is not measured live latency, nor an
  attack-start timestamp independently provided by ground truth. End-of-file
  flushing can shorten delays. Use the live JSONL stream to measure actual
  live behavior; keep both results with their scope.
- JSON includes capture SHA-256, effective configuration SHA-256, tool, tool version, command,
  per-entity misses and false alarms, warnings and full final alert evidence.
  `analysis_seconds` is wall-clock processing time including hashing, not a
  detector response delay. Configuration hashes include early warnings enabled.
- `lab`, `public` and `synthetic` are **declared provenance**, not automatically
  authenticated. Never relabel a generated fixture as a real capture. Public
  datasets need independently reviewed labels and license/sensor context.

## Comparing flow states with Zeek

Use the same complete capture for both programs. Record Zeek's version and the
capture hash beside the results. In a separate output directory:

```bash
zeek -r /absolute/path/to/syn_scan.pcap LogAscii::use_json=T
netguard lab compare-flows /absolute/path/to/syn_scan.pcap conn.log > comparison.json
```

Zeek's JSON `conn.log` fields are documented in the
[Book of Zeek](https://docs.zeek.org/en/master/reference/logs/conn.html).
The comparison reads JSON Lines; the default TSV format is rejected with an
explanation. It does not install or execute Zeek. If the capture has checksum
offload artifacts, investigate them before deciding whether to use Zeek's `-C`;
record that choice, because it changes what Zeek accepts.

The comparison counts **directional TCP/UDP five-tuple + state** multisets.
It detects wrong endpoints, orientation, states and connection counts rather
than comparing only histograms. Repeated connections are counted, not collapsed.
Other protocols are counted as ignored. Matching output exits 0, differences
exit 1, invalid/incomplete input exits 2. Logs/captures with no TCP/UDP flows
cannot pass as a vacuous match. Logs are capped at 500,000 rows and 1 MiB per
row; captures at 500,000 compared flows. Split larger experiments.

This is not a full Zeek compatibility claim: start times, packet/byte counts,
history and individual repeated-flow pairing are not compared. Different
flow timeouts can produce real differences that must be investigated rather
than hidden. A matching hand-authored fixture only tests the comparison code;
actual Zeek runs on lab captures remain a separate acceptance step.

## Evidence to retain

For each real experiment keep the complete PCAP, capture hash, manifest,
NetGuard JSON report, Zeek output/comparison where relevant, tool versions,
actual live JSONL output and tcpdump's packet-drop summary. Verify final live
alerts against offline analysis of the same saved capture. Review the confidence
factors against true and false alarms. Add the resulting numbers and limitations
to `docs/EVALUATION.md` only after those runs exist.

Captures, the local manifest and evaluation reports are ignored by Git. Do not
commit traffic or private addresses accidentally. A public result should include
only reviewed, appropriate evidence.
