"""Command line: phonecheck devices | scan | remove | capture | serve."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import TextIO

from . import __version__, lists
from .adb import AdbError, Device, RecordingDevice, list_devices
from .collector import collect
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

    return serve(DeviceSource.from_args(args), _context(args), port=args.port, open_browser=not args.no_browser, io=io)


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
    p.add_argument("--format", choices=("text", "json", "html"), default="text")
    p.add_argument("--out", metavar="FILE", help=f"write the report to a file (html defaults to {DEFAULT_HTML_NAME})")
    p.set_defaults(func=cmd_scan)

    p = commands.add_parser("remove", help="scan, then remove the apps you choose (asks twice)")
    _add_source_args(p)
    _add_list_args(p)
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
    p.add_argument("--port", type=int, default=8765)
    p.add_argument("--no-browser", action="store_true", help="do not open a browser window")
    p.set_defaults(func=cmd_serve)
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
    except (AdbError, CliError, RemovalRefused, ValueError) as exc:
        io.warn(f"error: {exc}")
        return 1
    except KeyboardInterrupt:
        io.warn("\ncancelled")
        return 130


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
