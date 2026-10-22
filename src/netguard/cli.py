"""Command-line interface.

netguard analyze capture.pcap
netguard analyze --format json capture.pcapng > report.json
sudo tcpdump -i eth0 -U -w - | netguard analyze --format jsonl -
netguard flows --format csv capture.pcap > flows.csv
netguard rules
netguard lab list | generate DIR | evaluate
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections.abc import Sequence
from pathlib import Path

from netguard import __version__
from netguard.config import ConfigError, load_config
from netguard.decode import UnsupportedLinkType
from netguard.detectors import DETECTORS
from netguard.engine import Engine
from netguard.output import FlowWriter, render_json, render_text, use_color, write_jsonl_alert
from netguard.sources import CaptureFormatError, CaptureInfo, open_capture

EXIT_OK, EXIT_ERROR = 0, 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="netguard", description="Network intrusion detection & traffic analyzer.")
    parser.add_argument("--version", action="version", version=f"netguard {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    an = sub.add_parser("analyze", help="analyze a pcap/pcapng file, or '-' for stdin")
    an.add_argument("capture", help="path to a .pcap/.pcapng file, or '-' to read from stdin")
    an.add_argument("-c", "--config", type=Path, help="TOML configuration file")
    an.add_argument(
        "-f",
        "--format",
        choices=("text", "json", "jsonl"),
        default="text",
        help="text report (default), one JSON document, or JSON Lines alerts streamed as they fire",
    )
    an.add_argument("--no-color", action="store_true", help="disable ANSI colors")

    fl = sub.add_parser("flows", help="export the flow (connection) records of a capture")
    fl.add_argument("capture", help="path to a .pcap/.pcapng file, or '-' to read from stdin")
    fl.add_argument("-c", "--config", type=Path, help="TOML configuration file (the [flows] section applies)")
    fl.add_argument(
        "-f", "--format", choices=("csv", "jsonl"), default="csv", help="CSV with a header (default) or JSON Lines"
    )

    ru = sub.add_parser("rules", help="list the detection rules and whether the configuration enables them")
    ru.add_argument("-c", "--config", type=Path, help="TOML configuration file")
    ru.add_argument("-f", "--format", choices=("text", "json"), default="text")

    lab = sub.add_parser("lab", help="synthetic lab scenarios")
    lab_sub = lab.add_subparsers(dest="lab_command", required=True)
    lab_sub.add_parser("list", help="list scenarios")
    gen = lab_sub.add_parser("generate", help="write scenario pcaps to a directory")
    gen.add_argument("outdir", type=Path)
    gen.add_argument("--scenario", action="append", help="only this scenario (repeatable)")
    lab_sub.add_parser("evaluate", help="run all scenarios and print a Markdown scorecard")
    return parser


def _run(engine: Engine, capture: str, info: CaptureInfo) -> None:
    try:
        with open_capture(capture, info) as frames:
            for ts, buf, linktype in frames:
                engine.process_frame(ts, buf, linktype)
    except KeyboardInterrupt:
        print("interrupted, reporting what was seen so far", file=sys.stderr)
    if info.truncated:
        print("netguard: warning: capture ends with a truncated record; analyzed what was complete", file=sys.stderr)


def cmd_analyze(args: argparse.Namespace) -> int:
    config = load_config(args.config)
    stream = args.format == "jsonl"
    engine = Engine(config, on_alert=write_jsonl_alert if stream else None)
    source = "<stdin>" if args.capture == "-" else args.capture
    info = CaptureInfo()
    _run(engine, args.capture, info)
    result = engine.finish()

    if args.format == "text":
        sys.stdout.write(render_text(result, source, color=use_color(sys.stdout) and not args.no_color))
    elif args.format == "json":
        sys.stdout.write(render_json(result, source, info))
    return EXIT_OK


def cmd_flows(args: argparse.Namespace) -> int:
    config = load_config(args.config)
    writer = FlowWriter(args.format)
    # Flows only: no detectors, so exporting is as fast as possible.
    engine = Engine(config, detectors=[], on_flow=writer.write)
    _run(engine, args.capture, CaptureInfo())
    engine.finish()
    return EXIT_OK


def cmd_rules(args: argparse.Namespace) -> int:
    config = load_config(args.config)
    rows = [
        {
            "rule_id": rule.rule_id,
            "detector": det.name,
            "enabled": getattr(config, det.name).enabled,
            "title": rule.title,
            "technique": rule.technique.id if rule.technique else None,
            "doc": f"docs/rules/{rule.rule_id}.md",
        }
        for det in DETECTORS
        for rule in det.rules
    ]
    if args.format == "json":
        print(json.dumps(rows, indent=2))
        return EXIT_OK
    for r in rows:
        state = "on " if r["enabled"] else "off"
        print(f"{r['rule_id']:<13} {state} {r['detector']:<10} {r['technique'] or '-':<10} {r['title']}")
    return EXIT_OK


def cmd_lab(args: argparse.Namespace) -> int:
    from netguard.lab import evaluate, scenarios, synth

    if args.lab_command == "list":
        for sc in scenarios.SCENARIOS:
            print(f"{sc.name:<32} {sc.kind:<7} {sc.description.splitlines()[0] if sc.description else ''}")
    elif args.lab_command == "generate":
        args.outdir.mkdir(parents=True, exist_ok=True)
        chosen = [scenarios.get(n) for n in args.scenario] if args.scenario else scenarios.SCENARIOS
        for sc in chosen:
            path = args.outdir / f"{sc.name}.pcap"
            n = synth.write_pcap(path, sc.build())
            print(f"wrote {path} ({n} packets)")
    elif args.lab_command == "evaluate":
        print(evaluate.render_markdown(evaluate.run_all()))
    return EXIT_OK


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "analyze":
            return cmd_analyze(args)
        if args.command == "flows":
            return cmd_flows(args)
        if args.command == "rules":
            return cmd_rules(args)
        return cmd_lab(args)
    except (ConfigError, CaptureFormatError, UnsupportedLinkType, KeyError) as exc:
        print(f"netguard: error: {exc}", file=sys.stderr)
        return EXIT_ERROR
    except BrokenPipeError:
        # The reader went away (e.g. `netguard flows x.pcap | head`): not an error.
        # Point stdout at devnull so the interpreter's final flush stays quiet.
        os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        return EXIT_OK
    except OSError as exc:
        print(f"netguard: error: {exc.strerror or exc}: {exc.filename or ''}".rstrip(": "), file=sys.stderr)
        return EXIT_ERROR


if __name__ == "__main__":
    raise SystemExit(main())
