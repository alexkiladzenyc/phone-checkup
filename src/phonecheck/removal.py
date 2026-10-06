"""Removing apps: the only part of phonecheck that changes a phone.

It is deliberately narrow. A package is removed only if it
  1. passes the package-name check,
  2. is in the phone's *current* list of user-installed apps (so system apps,
     typos and stale data can never be targeted), and
  3. was explicitly chosen by a person upstream.
Nothing here decides *what* to remove; that is the caller's job.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from .adb import LIST_USER_APPS, Device
from .parsers import is_valid_package, parse_package_list


class RemovalRefused(Exception):
    """Raised before anything is removed, when a request breaks a safety rule."""


@dataclass(frozen=True)
class RemovalResult:
    package: str
    ok: bool
    message: str
    hint: str | None = None


def _hint(message: str) -> str | None:
    if "DEVICE_POLICY_MANAGER" in message:
        return "Switch off this app's device administrator rights in Settings, then try again."
    if "not installed" in message.lower() or "INTERNAL_ERROR" in message:
        return "The phone says the app is not installed (it may already be gone)."
    return None


def remove_packages(device: Device, packages: Iterable[str]) -> list[RemovalResult]:
    requested = list(dict.fromkeys(packages))  # drop duplicates, keep order
    if not requested:
        raise RemovalRefused("No apps were selected.")

    invalid = [p for p in requested if not is_valid_package(p)]
    if invalid:
        raise RemovalRefused(f"Not valid package names: {', '.join(repr(p) for p in invalid)}")

    installed = {pkg for pkg, _ in parse_package_list(device.shell(*LIST_USER_APPS))}
    unknown = [p for p in requested if p not in installed]
    if unknown:
        raise RemovalRefused(
            "Refusing to remove apps that are not user-installed apps on this phone: " + ", ".join(unknown)
        )

    results = []
    for package in requested:
        ok, message = device.uninstall(package)
        results.append(RemovalResult(package=package, ok=ok, message=message, hint=None if ok else _hint(message)))
    return results
