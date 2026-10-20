"""Command-line interface.

netguard analyze capture.pcap
netguard analyze --format json capture.pcapng > report.json
sudo tcpdump -i eth0 -U -w - | netguard analyze --format jsonl -
netguard lab list | generate DIR | evaluate
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path

from netguard import __version__
from netguard.config import ConfigError, load_config
from netguard.decode import UnsupportedLinkType
from netguard.engine import Engine
from netguard.output import render_json, render_text, use_color, write_jsonl_alert
from netguard.sources import CaptureFormatError, open_capture

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

    lab = sub.add_parser("lab", help="synthetic lab scenarios")
    lab_sub = lab.add_subparsers(dest="lab_command", required=True)
    lab_sub.add_parser("list", help="list scenarios")
    gen = lab_sub.add_parser("generate", help="write scenario pcaps to a directory")
    gen.add_argument("outdir", type=Path)
    gen.add_argument("--scenario", action="append", help="only this scenario (repeatable)")
    lab_sub.add_parser("evaluate", help="run all scenarios and print a Markdown scorecard")
    return parser


def cmd_analyze(args: argparse.Namespace) -> int:
    config = load_config(args.config)
    stream = args.format == "jsonl"
    engine = Engine(config, on_alert=write_jsonl_alert if stream else None)
    source = "<stdin>" if args.capture == "-" else args.capture
    try:
        with open_capture(args.capture) as frames:
            for ts, buf, linktype in frames:
                engine.process_frame(ts, buf, linktype)
    except KeyboardInterrupt:
        print("interrupted, reporting what was seen so far", file=sys.stderr)
    result = engine.finish()

    if args.format == "text":
        sys.stdout.write(render_text(result, source, color=use_color(sys.stdout) and not args.no_color))
    elif args.format == "json":
        sys.stdout.write(render_json(result, source))
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
        return cmd_lab(args)
    except (ConfigError, CaptureFormatError, UnsupportedLinkType, KeyError) as exc:
        print(f"netguard: error: {exc}", file=sys.stderr)
        return EXIT_ERROR
    except OSError as exc:
        print(f"netguard: error: {exc.strerror or exc}: {exc.filename or ''}".rstrip(": "), file=sys.stderr)
        return EXIT_ERROR


if __name__ == "__main__":
    raise SystemExit(main())
