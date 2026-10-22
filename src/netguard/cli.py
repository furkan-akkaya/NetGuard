"""Command-line interface.

netguard analyze capture.pcap
netguard analyze --format json capture.pcapng > report.json
netguard analyze --format html capture.pcap > report.html
sudo tcpdump -i eth0 -U -w - | netguard analyze --format jsonl -
netguard flows --format csv capture.pcap > flows.csv
netguard rules
netguard serve --data-dir ./netguard-data          # REST API on 127.0.0.1:8000
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
from netguard.report import render_report
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
        choices=("text", "json", "jsonl", "html"),
        default="text",
        help="text report (default), one JSON document, JSON Lines alerts streamed as they fire, "
        "or a single-file HTML report",
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

    sv = sub.add_parser("serve", help="run the REST API (needs: pip install 'netguard[web]')")
    sv.add_argument("--data-dir", type=Path, default=Path("netguard-data"), help="database and stored captures")
    sv.add_argument("--host", default="127.0.0.1", help="bind address (default: 127.0.0.1, local only)")
    sv.add_argument("--port", type=int, default=8000)
    sv.add_argument("-c", "--config", type=Path, help="base TOML configuration for analyses")
    sv.add_argument("--max-upload-mb", type=int, default=256)
    sv.add_argument("--job-timeout", type=float, default=600.0, help="seconds per analysis")
    sv.add_argument("--job-memory-mb", type=int, default=1024, help="worker memory limit (enforced on Linux)")
    sv.add_argument("--max-stored-flows", type=int, default=500_000, help="flow rows kept per analysis")
    sv.add_argument(
        "--insecure-no-auth",
        action="store_true",
        help="allow a non-loopback --host without NETGUARD_API_TOKEN (only behind another auth layer)",
    )

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
    elif args.format == "html":
        alerts = [a.to_dict() for a in result.alerts]
        sys.stdout.write(render_report(result.stats.to_dict(), alerts, source, info.to_dict()))
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


def cmd_serve(args: argparse.Namespace) -> int:
    try:
        import uvicorn

        from netguard.jobs import JobLimits
        from netguard.web.app import create_app
        from netguard.web.settings import TOKEN_ENV, ServerSettings, SettingsError
    except ImportError:
        print("netguard: error: the API needs the web extra: pip install 'netguard[web]'", file=sys.stderr)
        return EXIT_ERROR
    settings = ServerSettings(
        data_dir=args.data_dir,
        host=args.host,
        port=args.port,
        token=os.environ.get(TOKEN_ENV) or None,
        allow_remote_without_token=args.insecure_no_auth,
        max_upload_bytes=args.max_upload_mb * 1024 * 1024,
        analysis_config=load_config(args.config),
        jobs=JobLimits(
            timeout_seconds=args.job_timeout, memory_mb=args.job_memory_mb, max_stored_flows=args.max_stored_flows
        ),
    )
    try:
        app = create_app(settings)
    except SettingsError as exc:
        print(f"netguard: error: {exc}", file=sys.stderr)
        return EXIT_ERROR
    auth = "token required" if settings.token else "no token (local only)"
    print(f"NetGuard API on http://{args.host}:{args.port}/api/v1/docs  data: {args.data_dir}  auth: {auth}")
    uvicorn.run(app, host=args.host, port=args.port, log_level="info", server_header=False)
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
        if args.command == "serve":
            return cmd_serve(args)
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
