"""Command line: phonecheck devices | scan | remove | capture | serve | diff | history."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import TextIO

from . import __version__, lists
from .adb import AdbError, Device, RecordingDevice, list_devices
from .collector import collect
from .compare import CompareError, compare, load_report, render_comparison
from .history import ENV_VAR, HistoryError, default_path, open_history
from .models import Level, Report
from .removal import RemovalRefused, remove_packages
from .report import USB_REMINDER, format_finding, render_html, render_json, render_text
from .rules import Context, analyze, build_context
from .source import DEMO_NAMES, DeviceSource

DEFAULT_HTML_NAME = "phonecheck-report.html"


class CliError(Exception):
    """A problem the user can fix; printed as 'error: ...' without a traceback."""


@dataclass
class Io:
    out: TextIO
    err: TextIO
    input_fn: Callable[[str], str]

    def say(self, text: str = "") -> None:
        print(text, file=self.out)

    def warn(self, text: str) -> None:
        print(text, file=self.err)


# --------------------------------------------------------------------------
# shared helpers
# --------------------------------------------------------------------------


def _add_source_args(parser: argparse.ArgumentParser) -> None:
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--demo", choices=DEMO_NAMES, help="use a bundled synthetic phone (no hardware needed)")
    group.add_argument("--fixture", metavar="DIR", help="replay a folder saved by `phonecheck capture`")
    group.add_argument("--serial", help="which phone to use when several are connected")
    parser.add_argument("--adb", default="adb", help="path to the adb program (default: adb)")


def _add_list_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--junk-list", action="append", default=[], metavar="FILE", help="extra known-junk packages")
    parser.add_argument("--trusted-list", action="append", default=[], metavar="FILE", help="extra trusted packages")


def _add_save_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--save", action="store_true",
        help="add this scan to the local history (flagged apps and phone model only; see `phonecheck history`)",
    )
    _add_db_arg(parser)


def _add_db_arg(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--db", metavar="FILE", help=f"history database (default: ${ENV_VAR} or {default_path()})")


def _save(report: Report, args: argparse.Namespace, io: Io) -> None:
    if not args.save:
        return
    with open_history(args.db) as history:
        scan_id = history.record(report)
    # stderr, so `scan --format json --save` still prints clean JSON
    io.warn(f"Saved to history as scan #{scan_id}.")


def _context(args: argparse.Namespace) -> Context:
    extra_junk: set[str] = set()
    extra_trusted: set[str] = set()
    for path in args.junk_list:
        extra_junk |= lists.load_file(path)
    for path in args.trusted_list:
        extra_trusted |= lists.load_file(path)
    return build_context(extra_junk=extra_junk, extra_trusted=extra_trusted)


def _scan(source: DeviceSource, args: argparse.Namespace, io: Io) -> tuple[Report, Device]:
    device = source.open()
    show_progress = io.err.isatty()

    def progress(done: int, total: int) -> None:
        if show_progress:
            print(f"\rReading apps: {done}/{total}", end="", file=io.err, flush=True)

    snapshot = collect(device, progress=progress)
    if show_progress:
        print(file=io.err)
    return analyze(snapshot, _context(args)), device


# --------------------------------------------------------------------------
# commands
# --------------------------------------------------------------------------


def cmd_devices(args: argparse.Namespace, io: Io) -> int:
    entries = list_devices(args.adb)
    if not entries:
        io.say("No phones found. Plug one in with a data cable and turn on USB debugging.")
        return 1
    hints = {
        "device": "ready",
        "unauthorized": "unlock the phone and tap Allow on the USB debugging prompt",
        "offline": "unplug it, plug it back in, and unlock the screen",
    }
    for entry in entries:
        io.say(f"{entry.serial}  {entry.state}  ({hints.get(entry.state, 'not ready')})  {entry.description}".rstrip())
    return 0


def cmd_scan(args: argparse.Namespace, io: Io) -> int:
    source = DeviceSource.from_args(args)
    report, _ = _scan(source, args, io)
    _save(report, args, io)

    if args.format == "text":
        text = render_text(report)
    elif args.format == "json":
        text = render_json(report)
    else:
        text = render_html(report)

    destination = args.out or (DEFAULT_HTML_NAME if args.format == "html" else None)
    if destination:
        Path(destination).write_text(text, encoding="utf-8")
        io.say(f"Report saved to {destination}")
    else:
        io.out.write(text)
    return 0


def parse_selection(answer: str, count: int) -> list[int]:
    """'1,3' / '2-4' / 'all' -> zero-based indexes, in order, without duplicates."""
    answer = answer.strip().lower()
    if answer == "all":
        return list(range(count))
    chosen: list[int] = []
    for part in answer.replace(" ", "").split(","):
        if not part:
            continue
        try:
            if "-" in part:
                low, high = (int(x) for x in part.split("-", 1))
                numbers: Iterable[int] = range(low, high + 1)
            else:
                numbers = [int(part)]
        except ValueError:
            raise CliError(f"Could not understand {part!r}. Use numbers like 1,3 or 2-4, or the word all.") from None
        for number in numbers:
            if not 1 <= number <= count:
                raise CliError(f"There is no app numbered {number}.")
            if number - 1 not in chosen:
                chosen.append(number - 1)
    if not chosen:
        raise CliError("No apps were selected.")
    return chosen


def cmd_remove(args: argparse.Namespace, io: Io) -> int:
    source = DeviceSource.from_args(args)
    report, device = _scan(source, args, io)
    _save(report, args, io)
    level = Level(args.min_level)
    candidates = list(report.at_level(level))

    if not candidates:
        io.say(f"Nothing to remove: no installed app reached the '{level.value}' level.")
        return 0

    io.say(f"Apps that reached '{level.value}' or higher on {report.device.display_name}:")
    io.say()
    for number, finding in enumerate(candidates, start=1):
        for line in format_finding(finding, number):
            io.say(line)
        io.say()

    if args.dry_run:
        io.say("Dry run: nothing was removed.")
        return 0

    try:
        answer = io.input_fn("Remove which? Numbers like 1,3 or 2-4, 'all', or press Enter to cancel: ")
    except EOFError:
        answer = ""
    if not answer.strip():
        io.say("Cancelled. Nothing was removed.")
        return 0
    chosen = [candidates[i] for i in parse_selection(answer, len(candidates))]

    io.say()
    io.say("About to remove:")
    for finding in chosen:
        io.say(f"  - {finding.app.package}")
    try:
        confirmation = io.input_fn("Type 'remove' to confirm: ")
    except EOFError:
        confirmation = ""
    if confirmation.strip().lower() != "remove":
        io.say("Cancelled. Nothing was removed.")
        return 0

    results = remove_packages(device, [f.app.package for f in chosen])
    io.say()
    for result in results:
        io.say(f"  {'removed' if result.ok else 'FAILED '}  {result.package}" + ("" if result.ok else f"  ({result.message})"))
        if result.hint:
            io.say(f"           {result.hint}")

    after, _ = _scan(source, args, io)
    remaining = len(after.at_level(level))
    io.say()
    io.say(f"Rescanned: {remaining} app{'s' if remaining != 1 else ''} still at '{level.value}' or higher.")
    io.say(USB_REMINDER)
    return 0 if all(r.ok for r in results) else 1


def cmd_capture(args: argparse.Namespace, io: Io) -> int:
    out_dir = Path(args.out)
    if out_dir.exists() and any(out_dir.iterdir()):
        raise CliError(f"{out_dir} is not empty. Choose a new folder.")
    source = DeviceSource.from_args(args)
    recorder = RecordingDevice(source.open(), out_dir)
    snapshot = collect(recorder)
    recorder.save()
    io.say(f"Saved {len(snapshot.apps)} apps' worth of recordings to {out_dir}.")
    io.say("These files list every app on that phone. Do not publish captures from a customer's phone.")
    return 0


def cmd_serve(args: argparse.Namespace, io: Io) -> int:
    from .server import serve

    history_path = (Path(args.db) if args.db else default_path()) if args.save else None
    if history_path:
        open_history(history_path).close()  # fail now, not on the first click, if the database is unusable
        io.say(f"Saving every scan to {history_path}.")
    return serve(
        DeviceSource.from_args(args), _context(args),
        port=args.port, open_browser=not args.no_browser, io=io, history_path=history_path,
    )


def cmd_diff(args: argparse.Namespace, io: Io) -> int:
    result = compare(load_report(args.before), load_report(args.after))
    io.out.write(render_comparison(result))
    return 1 if args.fail_on_new and (result.new or result.worse) else 0


def _parse_since(value: str | None) -> datetime | None:
    if value is None:
        return None
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        raise CliError(f"Could not understand the date {value!r}. Use YYYY-MM-DD.") from None


def cmd_history_list(args: argparse.Namespace, io: Io) -> int:
    with open_history(args.db) as history:
        scans = history.recent(args.limit)
    if not scans:
        io.say("No saved scans yet. Add one with `phonecheck scan --save`.")
        return 0
    io.say(f"{'#':>4}  {'when':<16}  {'phone':<24} {'android':>7}  {'apps':>4}  {'likely':>6}  {'look':>4}")
    for scan in scans:
        io.say(
            f"{scan.id:>4}  {scan.scanned_at:%Y-%m-%d %H:%M}  {scan.phone[:24]:<24} {scan.android[:7]:>7}  "
            f"{scan.apps_checked:>4}  {scan.high:>6}  {scan.medium:>4}"
        )
    return 0


def cmd_history_stats(args: argparse.Namespace, io: Io) -> int:
    since = _parse_since(args.since)
    with open_history(args.db) as history:
        total = history.scan_count()
        top = history.top_packages(args.top, since=since)
        rules = history.rule_frequency(since=since)
    scope = f" since {args.since}" if since else ""
    if not top:
        io.say(f"No flagged apps in the saved scans{scope}.")
        return 0
    io.say(f"Most often flagged apps ({total} saved scan{'s' if total != 1 else ''}{scope}):")
    io.say()
    io.say(f"  {'app':<40} {'scans':>6}  {'likely':>6}  {'avg':>5}  last seen")
    for stat in top:
        io.say(f"  {stat.package[:40]:<40} {stat.scans:>6}  {stat.high:>6}  {stat.average_score:>5.1f}  {stat.last_seen:%Y-%m-%d}")
    io.say()
    io.say("Rules behind the flags:")
    for rule in rules:
        io.say(f"  {rule.rule:<24} {rule.findings:>5}  ({rule.share:.0%} of flagged apps)")
    io.say()
    io.say("Apps that keep coming back are good candidates for a --junk-list file.")
    return 0


def cmd_history_export(args: argparse.Namespace, io: Io) -> int:
    since = _parse_since(args.since)
    with open_history(args.db) as history:
        if args.out:
            with open(args.out, "w", encoding="utf-8", newline="") as handle:
                rows = history.export_csv(handle, since=since)
            io.say(f"Wrote {rows} row{'s' if rows != 1 else ''} to {args.out}.")
        else:
            history.export_csv(io.out, since=since)
    return 0


# --------------------------------------------------------------------------
# parser and entry point
# --------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="phonecheck",
        description="Read-only junk-app and health checkup for Android phones, over ADB.",
        epilog="No phone handy? Try:  phonecheck scan --demo messy",
    )
    parser.add_argument("--version", action="version", version=f"phonecheck {__version__}")
    commands = parser.add_subparsers(dest="command", required=True, metavar="command")

    p = commands.add_parser("devices", help="list phones adb can see")
    p.add_argument("--adb", default="adb", help="path to the adb program")
    p.set_defaults(func=cmd_devices)

    p = commands.add_parser("scan", help="check a phone and print a report (changes nothing)")
    _add_source_args(p)
    _add_list_args(p)
    _add_save_args(p)
    p.add_argument("--format", choices=("text", "json", "html"), default="text")
    p.add_argument("--out", metavar="FILE", help=f"write the report to a file (html defaults to {DEFAULT_HTML_NAME})")
    p.set_defaults(func=cmd_scan)

    p = commands.add_parser("remove", help="scan, then remove the apps you choose (asks twice)")
    _add_source_args(p)
    _add_list_args(p)
    _add_save_args(p)
    p.add_argument("--min-level", choices=("high", "medium"), default="high", help="lowest level to offer (default: high)")
    p.add_argument("--dry-run", action="store_true", help="show what would be offered and stop")
    p.set_defaults(func=cmd_remove)

    p = commands.add_parser("capture", help="save a phone's raw answers to a folder (for tests or bug reports)")
    _add_source_args(p)
    p.add_argument("--out", required=True, metavar="DIR", help="new folder to write into")
    p.set_defaults(func=cmd_capture)

    p = commands.add_parser("serve", help="run the checkup as a local web page")
    _add_source_args(p)
    _add_list_args(p)
    _add_save_args(p)
    p.add_argument("--port", type=int, default=8765)
    p.add_argument("--no-browser", action="store_true", help="do not open a browser window")
    p.set_defaults(func=cmd_serve)

    p = commands.add_parser("diff", help="compare two JSON reports of a phone: new, gone, worse, improved")
    p.add_argument("before", help="the earlier report (from `scan --format json --out FILE`)")
    p.add_argument("after", help="the later report")
    p.add_argument("--fail-on-new", action="store_true", help="exit with status 1 if anything is new or got worse")
    p.set_defaults(func=cmd_diff)

    p = commands.add_parser("history", help="saved scans: list, stats, export")
    _add_db_arg(p)
    p.set_defaults(func=cmd_history_list, limit=20)
    actions = p.add_subparsers(dest="action", metavar="action")

    a = actions.add_parser("list", help="most recent saved scans (the default)")
    a.add_argument("--limit", type=int, default=20)
    _add_db_arg(a)
    a.set_defaults(func=cmd_history_list)

    a = actions.add_parser("stats", help="which apps and rules come up most often")
    a.add_argument("--top", type=int, default=10, help="how many apps to list (default: 10)")
    a.add_argument("--since", metavar="DATE", help="only scans on or after this date (YYYY-MM-DD)")
    _add_db_arg(a)
    a.set_defaults(func=cmd_history_stats)

    a = actions.add_parser("export", help="CSV, one row per flagged app per scan")
    a.add_argument("--out", metavar="FILE", help="write to a file instead of the screen")
    a.add_argument("--since", metavar="DATE", help="only scans on or after this date (YYYY-MM-DD)")
    _add_db_arg(a)
    a.set_defaults(func=cmd_history_export)
    return parser


def main(
    argv: list[str] | None = None,
    *,
    input_fn: Callable[[str], str] = input,
    stdout: TextIO | None = None,
    stderr: TextIO | None = None,
) -> int:
    io = Io(out=stdout or sys.stdout, err=stderr or sys.stderr, input_fn=input_fn)
    args = build_parser().parse_args(argv)
    try:
        code: int = args.func(args, io)
        return code
    except (AdbError, CliError, CompareError, HistoryError, RemovalRefused, ValueError) as exc:
        io.warn(f"error: {exc}")
        return 1
    except KeyboardInterrupt:
        io.warn("\ncancelled")
        return 130


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
