"""Command-line interface.

netguard analyze capture.pcap
netguard analyze --format json capture.pcapng > report.json
netguard analyze --format html capture.pcap > report.html
sudo tcpdump -i eth0 -U -w - | netguard analyze --format jsonl -
netguard flows --format csv capture.pcap > flows.csv
netguard rules
netguard monitor -i en0 --filter 'not port 22' --duration 600   # live, via tcpdump
netguard replay capture.pcap --speed 10
netguard serve --data-dir ./netguard-data          # REST API on 127.0.0.1:8000
netguard lab list | generate DIR | evaluate
"""

from __future__ import annotations

import argparse
import json
import os
import signal
import sys
from collections.abc import Sequence
from pathlib import Path

from netguard import __version__
from netguard.config import ConfigError, config_to_mapping, load_config, to_toml
from netguard.decode import UnsupportedLinkType
from netguard.detectors import DETECTORS
from netguard.engine import Engine
from netguard.models import Alert
from netguard.output import FlowWriter, format_alert, render_json, render_text, use_color, write_jsonl_alert
from netguard.report import render_report
from netguard.sources import CaptureFormatError, CaptureInfo, open_capture

EXIT_OK, EXIT_ERROR = 0, 2


def _session_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("-c", "--config", type=Path, help="TOML configuration file")
    p.add_argument("-f", "--format", choices=("text", "jsonl"), default="text", help="alert output format")
    p.add_argument("--no-early-warning", action="store_true", help="report incidents only when they close")
    p.add_argument("--status-every", type=float, default=30.0, help="status line interval in seconds (0 = off)")
    p.add_argument("--no-color", action="store_true", help="disable ANSI colors")


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

    cf = sub.add_parser("config", help="print the effective configuration as TOML (defaults merged with -c)")
    cf.add_argument("-c", "--config", type=Path, help="TOML configuration file to merge over the defaults")

    ru = sub.add_parser("rules", help="list the detection rules and whether the configuration enables them")
    ru.add_argument("-c", "--config", type=Path, help="TOML configuration file")
    ru.add_argument("-f", "--format", choices=("text", "json"), default="text")

    mo = sub.add_parser("monitor", help="analyse live traffic from one network interface (via tcpdump)")
    mo.add_argument("-i", "--interface", help="interface to capture on (required; see --list)")
    mo.add_argument("--list", action="store_true", help="list capture interfaces and exit")
    mo.add_argument("--filter", default="", help="BPF capture filter, e.g. 'not port 22'")
    mo.add_argument("--duration", type=float, help="stop after this many seconds")
    mo.add_argument("--count", type=int, help="stop after this many packets")
    mo.add_argument("--snaplen", type=int, default=262_144, help="bytes captured per packet")
    mo.add_argument("--write", type=Path, help="also save the capture to this pcap file (mode 0600)")
    mo.add_argument("--write-limit-mb", type=int, default=1024, help="stop writing the pcap beyond this size")
    mo.add_argument("--sudo", action="store_true", help="run tcpdump via `sudo -n` (drops to your user with -Z)")
    _session_args(mo)

    rp = sub.add_parser("replay", help="feed a capture through the live pipeline at its recorded pace")
    rp.add_argument("capture", type=Path)
    rp.add_argument("--speed", type=float, default=1.0, help="pace multiplier (1 = real time, 0 = as fast as possible)")
    rp.add_argument("--duration", type=float, help="stop after this many seconds")
    _session_args(rp)

    sv = sub.add_parser("serve", help="run the REST API (needs: pip install 'netguard[web]')")
    sv.add_argument("--data-dir", type=Path, default=Path("netguard-data"), help="database and stored captures")
    sv.add_argument("--host", default="127.0.0.1", help="bind address (default: 127.0.0.1, local only)")
    sv.add_argument("--port", type=int, default=8000)
    sv.add_argument("-c", "--config", type=Path, help="base TOML configuration for analyses")
    sv.add_argument("--max-upload-mb", type=int, default=256)
    sv.add_argument("--max-storage-gb", type=float, default=10.0, help="quota for all stored captures")
    sv.add_argument(
        "--allowed-host",
        action="append",
        default=[],
        help="extra host name clients may use (e.g. behind a reverse proxy); repeatable",
    )
    sv.add_argument(
        "--allowed-origin",
        action="append",
        default=[],
        help="browser origin allowed to change data besides the server's own, e.g. https://netguard.lab "
        "behind a TLS proxy; repeatable",
    )
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


def cmd_config(args: argparse.Namespace) -> int:
    header = f"NetGuard {__version__} effective configuration" + (f" ({args.config})" if args.config else " (defaults)")
    sys.stdout.write(to_toml(config_to_mapping(load_config(args.config)), header))
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


def _run_session(args: argparse.Namespace, source: object, clock_rate: float) -> int:
    from netguard.live import LiveSession, ReplaySource, SourceError, TcpdumpSource

    assert isinstance(source, TcpdumpSource | ReplaySource)
    config = load_config(args.config)
    config.alerts.early_warning = not args.no_early_warning
    color = use_color(sys.stdout) and not args.no_color

    def show(alert: Alert) -> None:
        if args.format == "jsonl":
            write_jsonl_alert(alert)
        else:
            print(format_alert(alert, color) + "\n", flush=True)

    def status(engine: Engine) -> None:
        s = engine.stats
        print(
            f"[status] packets {s.packets:,}  bytes {s.bytes:,}  active flows {len(engine.flows):,}  "
            f"alerts {s.alert_events_total:,}",
            file=sys.stderr,
            flush=True,
        )

    session = LiveSession(
        source,
        config,
        on_alert=show,
        duration=args.duration,
        clock_rate=clock_rate,
        on_status=status,
        status_every=args.status_every or None,
    )

    def request_stop(signum: int, frame: object) -> None:
        session.stop()

    previous = {sig: signal.signal(sig, request_stop) for sig in (signal.SIGINT, signal.SIGTERM)}
    try:
        outcome = session.run()
    except SourceError as exc:
        print(f"netguard: error: {exc}", file=sys.stderr)
        return EXIT_ERROR
    finally:
        for sig, handler in previous.items():
            signal.signal(sig, handler)
    if outcome.error:
        print(f"netguard: error: {outcome.error}", file=sys.stderr)
        return EXIT_ERROR
    s = outcome.result.stats
    finals = [a for a in outcome.result.alerts if a.stage == "final"]
    # Detection delay: from the incident's first packet to its *first* alert
    # (the early warning when there was one); stages share the alert_id.
    first_report: dict[str, float] = {}
    for a in outcome.result.alerts:
        if a.reported_at is not None:
            first_report[a.alert_id] = min(first_report.get(a.alert_id, a.reported_at), a.reported_at)
    delays = [first_report[a.alert_id] - a.first_seen for a in finals if a.alert_id in first_report]
    summary = (
        f"{outcome.source['source']}: {outcome.stopped_by} after {outcome.seconds:.1f}s; "
        f"{s.packets:,} packets, {s.flows_total:,} flows, {s.final_alerts_total} alerts"
    )
    if delays and not s.alert_history_dropped:
        summary += f" (detection delay median {sorted(delays)[len(delays) // 2]:.1f}s, max {max(delays):.1f}s)"
    if s.alert_history_dropped:
        summary += f"; {s.alert_history_dropped:,} older alert events not kept in memory (all were printed)"
    extra = {k: v for k, v in outcome.source.items() if k != "source"}
    if extra:
        summary += "; " + ", ".join(f"{k.replace('_', ' ')}: {v}" for k, v in extra.items())
    print(summary, file=sys.stderr)
    return EXIT_OK


def cmd_monitor(args: argparse.Namespace) -> int:
    from netguard.live import CaptureSpec, SourceError, TcpdumpSource, list_interfaces

    if args.list:
        for line in list_interfaces():
            print(line)
        return EXIT_OK
    if not args.interface:
        print("netguard: error: name the interface to capture on with -i (see --list)", file=sys.stderr)
        return EXIT_ERROR
    if os.geteuid() == 0:
        print(
            "netguard: error: do not run NetGuard as root. It parses untrusted traffic; give tcpdump the "
            "capture permission instead, or use --sudo (see docs/LIVE_CAPTURE.md).",
            file=sys.stderr,
        )
        return EXIT_ERROR
    spec = CaptureSpec(args.interface, args.filter, args.snaplen, args.count, args.sudo)
    try:
        source = TcpdumpSource(spec, args.write, args.write_limit_mb * 1024 * 1024)
    except SourceError as exc:
        print(f"netguard: error: {exc}", file=sys.stderr)
        return EXIT_ERROR
    target = f"{args.interface}" + (f" (filter: {args.filter})" if args.filter else "")
    print(
        f"Capturing on {target}. Only monitor networks you own or are authorised to assess. Ctrl-C to stop.",
        file=sys.stderr,
    )
    return _run_session(args, source, clock_rate=1.0)


def cmd_replay(args: argparse.Namespace) -> int:
    from netguard.live import ReplaySource, SourceError

    try:
        source = ReplaySource(args.capture, args.speed)
        return _run_session(args, source, clock_rate=args.speed)
    except SourceError as exc:
        print(f"netguard: error: {exc}", file=sys.stderr)
        return EXIT_ERROR


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
        allowed_hosts=args.allowed_host,
        allowed_origins=args.allowed_origin,
        max_upload_bytes=args.max_upload_mb * 1024 * 1024,
        max_storage_bytes=int(args.max_storage_gb * 1024**3),
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


def _dispatch(args: argparse.Namespace) -> int:
    commands = {
        "analyze": cmd_analyze,
        "flows": cmd_flows,
        "rules": cmd_rules,
        "config": cmd_config,
        "serve": cmd_serve,
        "monitor": cmd_monitor,
        "replay": cmd_replay,
        "lab": cmd_lab,
    }
    return commands[args.command](args)


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        code = _dispatch(args)
        # Flush here, inside the handler: otherwise a reader that went away after
        # the last write is only noticed at interpreter exit (exit code 120).
        sys.stdout.flush()
        return code
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
