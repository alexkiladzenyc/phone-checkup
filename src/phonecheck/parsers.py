"""Turn raw `adb shell` text into structured data.

Every function here is pure (text in, data out) and tolerant: unexpected or
empty input yields an empty/None result rather than an exception, because
Android's dumpsys output differs between versions and makers. The formats
handled here are the commonly documented ones; if a real phone prints
something different, `phonecheck capture` saves the raw text so a parser (and
a test) can be added for it.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime
from typing import Iterator

# Android package names: dot-separated segments, first character a letter.
PACKAGE_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z0-9_]+)+$")

_PKG_LOOSE = re.compile(r"[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z0-9_]+)+")


def is_valid_package(name: str) -> bool:
    return bool(PACKAGE_RE.fullmatch(name))


# --------------------------------------------------------------------------
# pm list packages -3 -i
# --------------------------------------------------------------------------

_PKG_LINE = re.compile(r"^package:(?P<pkg>[^\s=]+)(?P<rest>.*)$")
_INSTALLER = re.compile(r"installer=(?P<inst>\S+)")


def parse_package_list(text: str) -> list[tuple[str, str | None]]:
    """`package:com.foo  installer=com.android.vending` -> [("com.foo", "com.android.vending")]."""
    result: list[tuple[str, str | None]] = []
    for line in text.splitlines():
        match = _PKG_LINE.match(line.strip())
        if not match:
            continue
        installer = None
        inst = _INSTALLER.search(match.group("rest"))
        if inst and inst.group("inst") != "null":
            installer = inst.group("inst")
        result.append((match.group("pkg"), installer))
    return result


# --------------------------------------------------------------------------
# dumpsys package <name>
# --------------------------------------------------------------------------


def _indent(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


def _sections(lines: list[str], header: re.Pattern[str]) -> Iterator[str]:
    """Yield the stripped lines of every indented block under a matching header.

    dumpsys output is a tree expressed purely through indentation, so a block
    ends at the first non-blank line that is not indented deeper than its header.
    """
    i, n = 0, len(lines)
    while i < n:
        if header.fullmatch(lines[i].strip()):
            base = _indent(lines[i])
            i += 1
            while i < n:
                line = lines[i]
                if line.strip() and _indent(line) <= base:
                    break
                if line.strip():
                    yield line.strip()
                i += 1
        else:
            i += 1


@dataclass(frozen=True)
class PackageDump:
    version_name: str | None = None
    first_install: datetime | None = None
    installer: str | None = None
    requested: frozenset[str] = frozenset()
    granted: frozenset[str] = frozenset()


_REQUESTED = re.compile(r"requested permissions:")
_GRANTED_HEADERS = re.compile(r"(install|runtime) permissions:")


def _field(pattern: str, text: str) -> str | None:
    match = re.search(pattern, text, re.MULTILINE)
    return match.group(1) if match else None


def parse_package_dump(text: str) -> PackageDump:
    lines = text.splitlines()

    first_install = None
    raw = _field(r"^\s*firstInstallTime=(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})", text)
    if raw:
        first_install = datetime.strptime(raw, "%Y-%m-%d %H:%M:%S")

    installer = _field(r"^\s*installerPackageName=(\S+)", text)
    if installer in (None, "null"):
        installer = _field(r"^\s*installInitiatingPackageName=(\S+)", text)
    if installer == "null":
        installer = None

    requested = {
        line.split(":")[0].strip()
        for line in _sections(lines, _REQUESTED)
        if "." in line.split(":")[0]
    }
    granted = {
        line.split(":")[0].strip()
        for line in _sections(lines, _GRANTED_HEADERS)
        if "granted=true" in line
    }
    return PackageDump(
        version_name=_field(r"^\s*versionName=(.*?)\s*$", text),
        first_install=first_install,
        installer=installer,
        requested=frozenset(requested),
        granted=frozenset(granted),
    )


# --------------------------------------------------------------------------
# device-level readings
# --------------------------------------------------------------------------

_BATTERY_FIELD = re.compile(r"^\s*(level|health|temperature):\s*(-?\d+)\s*$")


def parse_battery(text: str) -> dict[str, int]:
    """`dumpsys battery` -> {"level": 87, "health": 2, "temperature": 301} (first occurrence wins)."""
    values: dict[str, int] = {}
    for line in text.splitlines():
        match = _BATTERY_FIELD.match(line)
        if match and match.group(1) not in values:
            values[match.group(1)] = int(match.group(2))
    return values


def parse_df(text: str, mount: str = "/data") -> tuple[int, float] | None:
    """`df /data` -> (percent used, free GB), or None if the line isn't there."""
    for line in text.splitlines():
        parts = line.split()
        if len(parts) >= 6 and parts[-1] == mount:
            try:
                available_kb = int(parts[3])
                percent = int(parts[4].rstrip("%"))
            except ValueError:
                continue
            return percent, available_kb / (1024 * 1024)
    return None


def parse_accessibility(text: str) -> set[str]:
    """`settings get secure enabled_accessibility_services` -> packages with a service switched on."""
    value = text.strip()
    if not value or value == "null":
        return set()
    packages = set()
    for component in value.split(":"):
        package = component.split("/")[0].strip()
        if is_valid_package(package):
            packages.add(package)
    return packages


_ADMIN_HEADER = re.compile(r"Enabled Device Admins.*:")
_ADMIN_ENTRY = re.compile(r"^([A-Za-z][A-Za-z0-9_.]*)/\S+:$")


def parse_device_admins(text: str) -> set[str]:
    """`dumpsys device_policy` -> packages that are active device administrators."""
    admins = set()
    for line in _sections(text.splitlines(), _ADMIN_HEADER):
        match = _ADMIN_ENTRY.match(line)
        if match and is_valid_package(match.group(1)):
            admins.add(match.group(1))
    return admins


def parse_overlay_packages(text: str) -> set[str]:
    """`cmd appops query-op SYSTEM_ALERT_WINDOW allow` -> packages allowed to draw over other apps.

    Output wording differs between Android versions, so this just collects
    anything shaped like a package name from each line.
    """
    packages = set()
    for line in text.splitlines():
        for token in _PKG_LOOSE.findall(line):
            if is_valid_package(token):
                packages.add(token)
    return packages


def parse_device_time(text: str) -> datetime | None:
    try:
        return datetime.strptime(text.strip(), "%Y-%m-%dT%H:%M:%S")
    except ValueError:
        return None
