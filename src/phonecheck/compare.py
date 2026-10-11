"""Compare two saved reports of the same phone: what is new, what is gone, what got worse.

Works on the JSON that `phonecheck scan --format json` writes, so a report
saved at drop-off can be checked against one taken at pick-up (or next
month) without keeping anything else. A report file is untrusted input, so
it is validated before use and a malformed one is a clear error, not a
traceback.
"""

from __future__ import annotations

import json
import textwrap
from dataclasses import dataclass
from pathlib import Path
from typing import Any

LEVEL_NAMES = {"high": "likely junk", "medium": "worth a look"}


class CompareError(ValueError):
    """A report file could not be used; the message names the file and the problem."""


@dataclass(frozen=True)
class Flag:
    """One flagged app as recorded in a report."""

    package: str
    level: str
    score: int
    rules: frozenset[str]

    @property
    def level_name(self) -> str:
        return LEVEL_NAMES[self.level]


@dataclass(frozen=True)
class Change:
    before: Flag
    after: Flag

    @property
    def package(self) -> str:
        return self.after.package

    @property
    def new_rules(self) -> frozenset[str]:
        return self.after.rules - self.before.rules

    @property
    def dropped_rules(self) -> frozenset[str]:
        return self.before.rules - self.after.rules


@dataclass(frozen=True)
class Comparison:
    phone_before: str
    phone_after: str
    taken_before: str | None
    taken_after: str | None
    new: tuple[Flag, ...]
    resolved: tuple[Flag, ...]
    worse: tuple[Change, ...]
    better: tuple[Change, ...]
    unchanged: int

    @property
    def same_phone(self) -> bool:
        return self.phone_before == self.phone_after

    @property
    def has_changes(self) -> bool:
        return bool(self.new or self.resolved or self.worse or self.better)


# --------------------------------------------------------------------------
# loading
# --------------------------------------------------------------------------


def _flag(raw: Any, source: str) -> Flag:
    if not isinstance(raw, dict):
        raise CompareError(f"{source}: a finding is not an object")
    package, level, score = raw.get("package"), raw.get("level"), raw.get("score")
    if not isinstance(package, str) or level not in LEVEL_NAMES or not isinstance(score, int) or isinstance(score, bool):
        raise CompareError(f"{source}: a finding is missing its package, level or score")
    signals = raw.get("signals", [])
    if not isinstance(signals, list):
        raise CompareError(f"{source}: signals for {package} are not a list")
    rules = frozenset(s["rule"] for s in signals if isinstance(s, dict) and isinstance(s.get("rule"), str))
    return Flag(package, level, score, rules)


def parse_report(data: Any, source: str = "report") -> tuple[str, str | None, dict[str, Flag]]:
    """Validate a report dict -> (phone name, scan time, flags by package)."""
    if not isinstance(data, dict) or data.get("tool") != "phonecheck":
        raise CompareError(f"{source}: not a phonecheck JSON report (make one with `phonecheck scan --format json`)")
    device = data.get("device")
    findings = data.get("findings")
    if not isinstance(device, dict) or not isinstance(findings, list):
        raise CompareError(f"{source}: the report has no device or findings section")
    phone = f"{device.get('manufacturer', 'unknown')} {device.get('model', 'unknown')}".strip()
    taken = device.get("scanned_at") if isinstance(device.get("scanned_at"), str) else None
    flags: dict[str, Flag] = {}
    for raw in findings:
        flag = _flag(raw, source)
        flags[flag.package] = flag
    return phone, taken, flags


def load_report(path: str | Path) -> tuple[str, str | None, dict[str, Flag]]:
    path = Path(path)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise CompareError(f"Could not read {path}: {exc.strerror or exc}") from exc
    except ValueError as exc:
        raise CompareError(f"{path} is not valid JSON: {exc}") from exc
    return parse_report(data, source=str(path))


# --------------------------------------------------------------------------
# comparing
# --------------------------------------------------------------------------


def _rank(flag: Flag) -> tuple[int, int]:
    return (2 if flag.level == "high" else 1, flag.score)


def compare(
    before: tuple[str, str | None, dict[str, Flag]],
    after: tuple[str, str | None, dict[str, Flag]],
) -> Comparison:
    phone_before, taken_before, old = before
    phone_after, taken_after, new = after
    worse, better, unchanged = [], [], 0
    for package in sorted(old.keys() & new.keys()):
        change = Change(old[package], new[package])
        if _rank(change.after) > _rank(change.before):
            worse.append(change)
        elif _rank(change.after) < _rank(change.before):
            better.append(change)
        else:
            unchanged += 1

    def by_severity(flags: list[Flag]) -> tuple[Flag, ...]:
        return tuple(sorted(flags, key=lambda f: (-_rank(f)[0], -f.score, f.package)))

    return Comparison(
        phone_before=phone_before,
        phone_after=phone_after,
        taken_before=taken_before,
        taken_after=taken_after,
        new=by_severity([new[p] for p in new.keys() - old.keys()]),
        resolved=by_severity([old[p] for p in old.keys() - new.keys()]),
        worse=tuple(sorted(worse, key=lambda c: (-c.after.score, c.package))),
        better=tuple(sorted(better, key=lambda c: (c.after.score, c.package))),
        unchanged=unchanged,
    )


# --------------------------------------------------------------------------
# rendering
# --------------------------------------------------------------------------


def _wrap(text: str) -> list[str]:
    return textwrap.wrap(text, width=78, initial_indent="      ", subsequent_indent="      ", break_on_hyphens=False)


def render_comparison(result: Comparison) -> str:
    when = f"{result.taken_before or 'earlier scan'} -> {result.taken_after or 'later scan'}"
    lines = [f"Comparing {result.phone_after}: {when}"]
    if not result.same_phone:
        lines.append(f"Warning: these reports are from different phones ({result.phone_before} and {result.phone_after}).")
    lines.append("")

    if not result.has_changes:
        lines.append("No change: the same apps are flagged at the same level and score.")
        lines.append("")

    if result.new:
        lines.append(f"NEW SINCE LAST TIME ({len(result.new)})")
        for flag in result.new:
            lines.append(f"  + {flag.package}   {flag.level_name}, score {flag.score}")
            if flag.rules:
                lines.extend(_wrap("because: " + ", ".join(sorted(flag.rules))))
        lines.append("")
    if result.worse:
        lines.append(f"GOT WORSE ({len(result.worse)})")
        for change in result.worse:
            lines.append(_change_line("^", change))
            if change.new_rules:
                lines.extend(_wrap("new signals: " + ", ".join(sorted(change.new_rules))))
        lines.append("")
    if result.better:
        lines.append(f"IMPROVED ({len(result.better)})")
        for change in result.better:
            lines.append(_change_line("v", change))
            if change.dropped_rules:
                lines.extend(_wrap("no longer: " + ", ".join(sorted(change.dropped_rules))))
        lines.append("")
    if result.resolved:
        lines.append(f"GONE ({len(result.resolved)})")
        for flag in result.resolved:
            lines.append(f"  - {flag.package}   was {flag.level_name}, score {flag.score}")
        lines.append("")

    if result.unchanged:
        lines.append(f"Unchanged: {result.unchanged} flagged app{'s' if result.unchanged != 1 else ''}.")
    return "\n".join(lines).rstrip("\n") + "\n"


def _change_line(marker: str, change: Change) -> str:
    level = (
        f"  ({change.before.level_name} -> {change.after.level_name})"
        if change.before.level != change.after.level
        else ""
    )
    return f"  {marker} {change.package}   score {change.before.score} -> {change.after.score}{level}"
