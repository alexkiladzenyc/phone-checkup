"""Talking to a phone.

Three interchangeable "devices" share one tiny interface (shell + uninstall):

* AdbDevice      - a real phone through the `adb` program
* FixtureDevice  - replays text files recorded earlier (tests, demo, emulator captures)
* RecordingDevice- wraps another device and saves every answer to disk

Everything above this layer only sees the interface, which is why the whole
tool can be tested and demoed without hardware.

Security: arguments reach a shell *on the phone*, so every argument is checked
against a strict allowlist of characters before anything is sent. Nothing a
phone reports can become part of a later command unless it also passes
`is_valid_package`.
"""

from __future__ import annotations

import json
import re
import subprocess
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from .parsers import is_valid_package, parse_package_list

# The one command whose answer changes when something is uninstalled.
LIST_USER_APPS = ("pm", "list", "packages", "-3", "-i")

_SAFE_ARG = re.compile(r"^[A-Za-z0-9_.:/+%=@-]+$")


class AdbError(RuntimeError):
    """Anything that went wrong talking to a phone, with a message fit to show a person."""


def check_shell_args(args: tuple[str, ...]) -> None:
    if not args:
        raise ValueError("empty shell command")
    for arg in args:
        if not _SAFE_ARG.fullmatch(arg):
            raise ValueError(f"refusing unsafe shell argument: {arg!r}")


class Device(Protocol):
    def shell(self, *args: str) -> str: ...

    def uninstall(self, package: str) -> tuple[bool, str]: ...


def _explain(stderr: str, command: tuple[str, ...]) -> str:
    text = stderr.strip()
    lowered = text.lower()
    if "no devices" in lowered or "device not found" in lowered:
        return "No phone found. Plug it in with a data cable and turn on USB debugging."
    if "unauthorized" in lowered:
        return "The phone has not approved this computer. Unlock it and tap Allow on the USB debugging prompt."
    if "more than one device" in lowered:
        return "More than one phone is connected. Choose one with --serial."
    if "offline" in lowered:
        return "The phone shows as offline. Unplug it, plug it back in, and unlock the screen."
    return f"adb failed running '{' '.join(command)}': {text or 'no details'}"


class AdbDevice:
    def __init__(self, serial: str | None = None, adb_path: str = "adb", timeout: float = 30.0):
        self.serial = serial
        self.adb_path = adb_path
        self.timeout = timeout

    def _run(self, args: list[str]) -> subprocess.CompletedProcess[str]:
        command = [self.adb_path]
        if self.serial:
            command += ["-s", self.serial]
        command += args
        try:
            return subprocess.run(
                command,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=self.timeout,
                check=False,
            )
        except FileNotFoundError as exc:
            raise AdbError(
                f"Could not run '{self.adb_path}'. Install Android platform-tools and make sure adb is on your PATH."
            ) from exc
        except subprocess.TimeoutExpired as exc:
            raise AdbError(f"adb did not answer within {self.timeout:.0f} seconds.") from exc

    def shell(self, *args: str) -> str:
        check_shell_args(args)
        proc = self._run(["shell", *args])
        if proc.returncode != 0:
            raise AdbError(_explain(proc.stderr or proc.stdout, args))
        return proc.stdout

    def uninstall(self, package: str) -> tuple[bool, str]:
        if not is_valid_package(package):
            raise ValueError(f"not a valid package name: {package!r}")
        # Read stdout whatever the exit code: failures print "Failure [REASON]".
        proc = self._run(["shell", "pm", "uninstall", package])
        message = (proc.stdout or proc.stderr).strip() or "no output"
        return message.startswith("Success"), message


@dataclass(frozen=True)
class AdbDeviceEntry:
    serial: str
    state: str  # "device" (ready), "unauthorized", "offline", ...
    description: str


def list_devices(adb_path: str = "adb", timeout: float = 15.0) -> list[AdbDeviceEntry]:
    """Phones currently visible to adb (`adb devices -l`)."""
    probe = AdbDevice(adb_path=adb_path, timeout=timeout)
    proc = probe._run(["devices", "-l"])
    if proc.returncode != 0:
        raise AdbError(_explain(proc.stderr or proc.stdout, ("devices",)))
    entries = []
    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line or line.startswith(("List of devices", "*")):
            continue
        parts = line.split()
        if len(parts) >= 2:
            entries.append(AdbDeviceEntry(parts[0], parts[1], " ".join(parts[2:])))
    return entries


# --------------------------------------------------------------------------
# Recording and replay
# --------------------------------------------------------------------------


def _slug(key: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", key).strip("_")[:100] or "command"


class RecordingDevice:
    """Wraps a device and saves each command's output as a text file plus a manifest.

    Read-only by design: uninstalling through a recorder is refused.
    """

    def __init__(self, inner: Device, out_dir: str | Path):
        self.inner = inner
        self.out_dir = Path(out_dir)
        self.out_dir.mkdir(parents=True, exist_ok=True)
        self._commands: dict[str, str] = {}
        self._errors: dict[str, str] = {}
        self._used_names: set[str] = set()
        self._lock = threading.Lock()

    def shell(self, *args: str) -> str:
        key = " ".join(args)
        try:
            output = self.inner.shell(*args)
        except AdbError as exc:
            with self._lock:
                self._errors[key] = str(exc)
            raise
        with self._lock:
            name = _slug(key)
            candidate, counter = f"{name}.txt", 1
            while candidate in self._used_names:
                counter += 1
                candidate = f"{name}_{counter}.txt"
            self._used_names.add(candidate)
            (self.out_dir / candidate).write_text(output, encoding="utf-8")
            self._commands[key] = candidate
        return output

    def uninstall(self, package: str) -> tuple[bool, str]:
        raise NotImplementedError("capture is read-only")

    def save(self) -> None:
        manifest = {"format": 1, "commands": self._commands, "errors": self._errors, "uninstall": {}}
        (self.out_dir / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")


class FixtureDevice:
    """Replays a directory written by RecordingDevice (or by tools/make_demo_phones.py).

    Uninstalls are simulated in memory, so a rescan after "removing" an app
    behaves like a real phone would. `manifest["uninstall"]` can force a
    failure message for a package (used to demonstrate device-admin apps).
    """

    def __init__(self, directory: str | Path):
        self.directory = Path(directory).resolve()
        try:
            manifest = json.loads((self.directory / "manifest.json").read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise AdbError(f"Could not read a fixture at {self.directory}: {exc}") from exc
        self._commands: dict[str, str] = manifest.get("commands", {})
        self._errors: dict[str, str] = manifest.get("errors", {})
        self._uninstall: dict[str, str] = manifest.get("uninstall", {})
        self._removed: set[str] = set()
        self._lock = threading.Lock()

    def _read(self, filename: str) -> str:
        path = (self.directory / filename).resolve()
        if self.directory not in path.parents:
            raise AdbError(f"Fixture file escapes its directory: {filename}")
        return path.read_text(encoding="utf-8")

    def shell(self, *args: str) -> str:
        check_shell_args(args)
        key = " ".join(args)
        if key in self._errors:
            raise AdbError(self._errors[key])
        if key not in self._commands:
            raise AdbError(f"fixture has no recording for: {key}")
        text = self._read(self._commands[key])
        with self._lock:
            removed = set(self._removed)
        if args == LIST_USER_APPS:
            kept = []
            for line in text.splitlines():
                first = line.split()[0] if line.split() else ""
                if first.startswith("package:") and first[len("package:"):] in removed:
                    continue
                kept.append(line)
            text = "".join(line + "\n" for line in kept)
        elif args[:2] == ("dumpsys", "package") and len(args) == 3 and args[2] in removed:
            return f"Unable to find package: {args[2]}\n"
        return text

    def uninstall(self, package: str) -> tuple[bool, str]:
        if not is_valid_package(package):
            raise ValueError(f"not a valid package name: {package!r}")
        installed = {pkg for pkg, _ in parse_package_list(self.shell(*LIST_USER_APPS))}
        if package not in installed:
            return False, "Failure [DELETE_FAILED_INTERNAL_ERROR]"
        result = self._uninstall.get(package, "Success")
        if result.startswith("Success"):
            with self._lock:
                self._removed.add(package)
        return result.startswith("Success"), result
