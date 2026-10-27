"""Single-file HTML analysis report: printable, shareable, no JavaScript, no external resources.

Every value that can come from a capture (DNS names, evidence, addresses,
filenames) is attacker-controlled. Everything goes through :func:`esc`
(``html.escape`` with quotes) before it reaches the page, and the page carries
a Content-Security-Policy that forbids scripts entirely, so even an escaping
mistake could not execute code. ``tests/test_report.py`` renders hostile
strings to check this.
"""

from __future__ import annotations

import html
import json
from collections.abc import Iterable, Mapping, Sequence
from typing import Any

from netguard import __version__
from netguard.stats import state_losses

_CSP = "default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'"
_SEVERITY_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}

_STYLE = """
:root { --fg:#1d2433; --muted:#5b6475; --line:#d9dee7; --bg:#ffffff; --panel:#f6f8fb;
        --high:#b42318; --medium:#b54708; --low:#175cd3; --bar:#3b6fd8; }
* { box-sizing: border-box; }
body { font: 14px/1.5 system-ui, -apple-system, "Segoe UI", sans-serif; color: var(--fg);
       background: var(--bg); margin: 0 auto; max-width: 1100px; padding: 24px 16px; }
h1 { font-size: 22px; margin: 0 0 4px; } h2 { font-size: 17px; margin: 28px 0 8px; }
.muted { color: var(--muted); }
code, .mono { font-family: ui-monospace, Menlo, Consolas, monospace; font-size: 12.5px; }
.cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 10px; }
.card { background: var(--panel); border: 1px solid var(--line); border-radius: 8px; padding: 10px 12px; }
.card b { display: block; font-size: 20px; }
table { width: 100%; border-collapse: collapse; margin: 6px 0; }
th, td { text-align: left; padding: 5px 8px; border-bottom: 1px solid var(--line); vertical-align: top; }
th { font-weight: 600; color: var(--muted); font-size: 12px; text-transform: uppercase; letter-spacing: .03em; }
td.num, th.num { text-align: right; font-variant-numeric: tabular-nums; }
.bar { background: var(--bar); height: 8px; border-radius: 4px; min-width: 2px; }
.alert { border: 1px solid var(--line); border-left: 4px solid var(--muted); border-radius: 6px;
         padding: 10px 12px; margin: 10px 0; break-inside: avoid; }
.alert.HIGH { border-left-color: var(--high); } .alert.MEDIUM { border-left-color: var(--medium); }
.alert.LOW { border-left-color: var(--low); }
.sev { font-weight: 700; font-size: 12px; } .sev.HIGH { color: var(--high); } .sev.MEDIUM { color: var(--medium); }
.sev.LOW { color: var(--low); }
details pre { white-space: pre-wrap; word-break: break-word; background: var(--panel); padding: 8px;
              border-radius: 6px; max-height: 360px; overflow: auto; }
footer { margin-top: 32px; font-size: 12px; color: var(--muted); }
@media print { details { display: none; } body { padding: 0; } }
"""


def esc(value: object) -> str:
    return html.escape("" if value is None else str(value), quote=True)


def _num(value: object) -> str:
    return f"{value:,}" if isinstance(value, int) else esc(value)


def _bars(rows: Iterable[tuple[str, int]], label: str, value: str = "Count") -> str:
    rows = list(rows)
    if not rows:
        return '<p class="muted">None.</p>'
    peak = max(n for _, n in rows) or 1
    body = "".join(
        f'<tr><td class="mono">{esc(k)}</td><td class="num">{_num(n)}</td>'
        f'<td style="width:45%"><div class="bar" style="width:{100 * n / peak:.1f}%"></div></td></tr>'
        for k, n in rows
    )
    return f'<table><tr><th>{esc(label)}</th><th class="num">{esc(value)}</th><th></th></tr>{body}</table>'


def _alert_block(a: Mapping[str, Any]) -> str:
    sev = a["severity"] if a["severity"] in _SEVERITY_ORDER else "LOW"
    target = f"{a.get('src') or '?'} → {a['dst']}" if a.get("dst") else (a.get("src") or "?")
    tech = a.get("technique")
    tech_html = f' · <span class="mono">{esc(tech["id"])}</span> {esc(tech["name"])}' if tech else ""
    evidence = json.dumps(a.get("evidence", {}), indent=2, sort_keys=True)
    return (
        f'<div class="alert {sev}"><div><span class="sev {sev}">{esc(sev)}</span> '
        f'<b>{esc(a["title"])}</b> · <span class="mono">{esc(target)}</span>{tech_html}</div>'
        f"<div>{esc(a['summary'])}</div>"
        f'<div class="muted mono">{esc(a["first_seen"])} → {esc(a["last_seen"])} · '
        f"rule {esc(a['rule_id'])} · id {esc(a['alert_id'])}</div>"
        f"<details><summary>Evidence</summary><pre>{esc(evidence)}</pre></details></div>"
    )


def render_report(
    stats: Mapping[str, Any],
    alerts: Sequence[Mapping[str, Any]],
    source: str,
    capture_info: Mapping[str, Any] | None = None,
    meta: Mapping[str, Any] | None = None,
) -> str:
    """Render one analysis. ``stats`` is ``TrafficStats.to_dict()``; ``alerts`` are alert contract dicts."""
    alerts = sorted(alerts, key=lambda a: (_SEVERITY_ORDER.get(a["severity"], 3), a["first_seen"]))
    counts = {s: sum(a["severity"] == s for a in alerts) for s in ("HIGH", "MEDIUM", "LOW")}
    flows = stats.get("flows", {})
    cards = [
        ("Alerts", len(alerts)),
        ("High / Medium / Low", f"{counts['HIGH']} / {counts['MEDIUM']} / {counts['LOW']}"),
        ("Packets", stats.get("packets", 0)),
        ("Bytes", stats.get("bytes", 0)),
        ("Duration (s)", stats.get("duration_seconds", 0)),
        ("Flows", flows.get("total", 0)),
        ("Decode errors", stats.get("decode_errors", 0)),
    ]
    meta_rows = "".join(f"<tr><th>{esc(k)}</th><td>{esc(v)}</td></tr>" for k, v in (meta or {}).items())
    if capture_info:
        meta_rows += f"<tr><th>Capture format</th><td>{esc(capture_info.get('format'))}</td></tr>"
        if capture_info.get("truncated"):
            meta_rows += "<tr><th>Warning</th><td>The capture ends with a truncated record.</td></tr>"
    if flows.get("evicted"):
        meta_rows += (
            f"<tr><th>Warning</th><td>{_num(flows['evicted'])} flows evicted early (flow table full).</td></tr>"
        )
    for name, lost in state_losses(stats.get("detectors", {})).items():
        meta_rows += (
            f"<tr><th>Warning</th><td>Detector {esc(name)} dropped state {_num(lost)} times (table full).</td></tr>"
        )
    endpoints = stats.get("endpoints", {}).get("top_by_bytes", [])
    endpoint_rows = "".join(
        f'<tr><td class="mono">{esc(e["ip"])}</td><td class="num">{_num(e["bytes_sent"])}</td>'
        f'<td class="num">{_num(e["bytes_received"])}</td><td class="num">{_num(e["flows_originated"])}</td></tr>'
        for e in endpoints
    )
    top_flows = "".join(
        f'<tr><td class="mono">{esc(f["proto"])} {esc(f["src_ip"])}:{esc(f["src_port"])} → '
        f"{esc(f['dst_ip'])}:{esc(f['dst_port'])}</td><td>{esc(f['state'])}</td>"
        f'<td class="num">{_num(f["orig_bytes"] + f["resp_bytes"])}</td>'
        f'<td class="num">{esc(f["duration_seconds"])}</td></tr>'
        for f in flows.get("top_by_bytes", [])
    )
    parts = [
        '<!doctype html><html lang="en"><head><meta charset="utf-8">',
        f'<meta http-equiv="Content-Security-Policy" content="{_CSP}">',
        '<meta name="viewport" content="width=device-width, initial-scale=1">',
        f"<title>NetGuard report — {esc(source)}</title><style>{_STYLE}</style></head><body>",
        f'<h1>NetGuard analysis report</h1><div class="muted mono">{esc(source)}</div>',
        f"<table>{meta_rows}</table>" if meta_rows else "",
        '<div class="cards">' + "".join(f'<div class="card">{esc(k)}<b>{_num(v)}</b></div>' for k, v in cards),
        "</div>",
        f"<h2>Alerts ({len(alerts)})</h2>",
        "".join(_alert_block(a) for a in alerts) or '<p class="muted">No alerts.</p>',
        "<h2>Protocols</h2>",
        _bars(stats.get("protocols", {}).items(), "Protocol", "Packets"),
        "<h2>Flow states</h2>",
        _bars(flows.get("states", {}).items(), "State", "Flows"),
        "<h2>Top services</h2>",
        _bars([(s["service"], s["flows"]) for s in flows.get("top_services", [])], "Service", "Flows"),
        "<h2>Top endpoints</h2>",
        (
            '<table><tr><th>IP</th><th class="num">Bytes sent</th><th class="num">Bytes received</th>'
            f'<th class="num">Flows originated</th></tr>{endpoint_rows}</table>'
            if endpoint_rows
            else '<p class="muted">None.</p>'
        ),
        "<h2>Largest flows</h2>",
        (
            '<table><tr><th>Flow</th><th>State</th><th class="num">Bytes</th><th class="num">Duration (s)</th></tr>'
            f"{top_flows}</table>"
            if top_flows
            else '<p class="muted">None.</p>'
        ),
        "<h2>Packet sizes</h2>",
        _bars(stats.get("packet_sizes", {}).items(), "Bytes", "Packets"),
        f"<footer>Generated by NetGuard {esc(__version__)}. Alerts state what was observed and which "
        "threshold was crossed; they indicate suspicious behaviour, not proven intent. Rule documentation: "
        "docs/rules/ in the NetGuard repository.</footer></body></html>",
    ]
    return "".join(parts)
