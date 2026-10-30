# Confidence review · 30 October 2026

The strongest objection is the absence of real benign alerts for comparison.
Seventeen existing lab captures include one benign hour and 21 final alerts from bounded attack experiments.
The benign capture produces zero alerts, so it cannot validate negative confidence factors.
These records were already used in development; they are not independent holdout evidence.
No weights were fitted or changed. Scores remain heuristic evidence summaries, never measured attack probabilities.

## Existing real captures

| Capture | Final rule and score |
|---|---|
| exp01-syn-scan | NG-SCAN-001: 90, NG-SCAN-002: 95 |
| live-syn-01 | NG-SCAN-001: 90, NG-SCAN-002: 95 |
| benign-01 | No alerts (benign) |
| exp02-connect-scan-r02 | NG-SCAN-001: 90, NG-SCAN-002: 95 |
| exp03-xmas-scan | NG-SCAN-001: 95 |
| exp04-fin-scan | NG-SCAN-001: 95 |
| exp05-null-scan | NG-SCAN-001: 95 |
| exp07-udp-scan | NG-SCAN-003: 85 |
| exp08-ping-sweep | NG-SWEEP-001: 80 |
| exp09-frag-scan | NG-FRAG-001: 85 |
| exp10-syn-burst | NG-SYN-001: 60 |
| exp06-slow-scan | NG-SCAN-002: 95 |
| exp11-arp-binding | NG-ARP-001: 65 |
| exp12-dns-nxdomain | NG-DNS-002: 85 |
| exp13-dns-tunnel | NG-DNS-001: 65 |
| live-early-01 | NG-SCAN-001: 90, NG-SCAN-002: 95 |
| exp14-rate-volume-r02 | NG-RATE-001: 30, NG-VOL-001: 45 |

## Factors observed on real wire data

| Rule | Factor | Weight | Alerts containing factor |
|---|---|---:|---:|
| NG-SCAN-001 | at least 90% of probed ports were closed or silent: the source did not know what was there | +20 | 7 |
| NG-SCAN-001 | 100 or more ports on one host | +10 | 7 |
| NG-SCAN-001 | non-SYN probe types (NULL/FIN/XMAS) have no legitimate client use | +15 | 3 |
| NG-SCAN-002 | fewer than 10% of first contacts succeeded | +20 | 5 |
| NG-SCAN-002 | 20 or more failed first contacts | +10 | 5 |
| NG-SCAN-003 | at least 90% of probed UDP ports did not answer or were closed | +20 | 1 |
| NG-SCAN-003 | 100 or more UDP ports on one host | +10 | 1 |
| NG-SWEEP-001 | most probed addresses did not answer: the source was searching for hosts | +15 | 1 |
| NG-SWEEP-001 | 100 or more hosts probed | +10 | 1 |
| NG-FRAG-001 | transport headers split across fragments: no normal stack does this | +25 | 1 |
| NG-SYN-001 | almost no handshake completed | +20 | 1 |
| NG-SYN-001 | the target barely answered: an outage or filtering looks the same | -20 | 1 |
| NG-ARP-001 | unsolicited ARP reply: nobody asked for this IP | +15 | 1 |
| NG-DNS-002 | almost every failed name is a different domain, as a DGA produces | +25 | 1 |
| NG-DNS-002 | random-looking labels | +10 | 1 |
| NG-DNS-001 | high-entropy names, like encoded data | +10 | 1 |
| NG-RATE-001 | short history: the baseline may not capture this host's normal range yet | -10 | 1 |
| NG-VOL-001 | 20 times or more above this host's baseline | +15 | 1 |
| NG-VOL-001 | short history: the baseline may not capture this host's normal range yet | -10 | 1 |

These counts show that a factor activates on observed evidence.
They do not establish its weight, specificity or ability to separate benign activity.
Repeated scan variants from one host pair are dependent samples.

## Unsupported separation claims

- Successful-port suppression, known-inventory suppression, gratuitous-ARP suppression and domain-concentration suppression lack real benign-alert comparisons.
- ARP flip/critical-IP weights, spoofed-source flood weights, tunnel record-type/volume weights and the rate 20× factor lack representative real comparison samples.
- A SYN answer-ratio penalty activates on the lab burst; a service outage can produce the same evidence.
- Rate and volume short-history penalties activate, but their -10 magnitude is a design choice.
- High scores for an authorized scanner do not imply malicious intent.

Twelve synthetic benign look-alikes were also replayed with each scenario’s declared configuration.
Their outputs check implementation consistency; they do not replace real benign traffic.
The known monitoring, DHCP-without-context and search-suffix false positives remain documented.

Further calibration needs independently labelled legitimate bursts, backups, maintenance scans and outages.
Split tuning captures from held-out captures before changing weights.
Do not remove a factor solely because this narrow lab cannot exercise it.

## Reproduce

Run `uv run python eval/lab/review_confidence.py CAPTURE_DIR OTHER_CAPTURE_DIR`. The script verifies pinned hashes and respects each synthetic scenario’s configuration. It lists missing records explicitly. Never commit the capture directories.
