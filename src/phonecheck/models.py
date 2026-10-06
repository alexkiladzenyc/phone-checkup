"""Plain data types shared by every layer.

Nothing in here talks to a phone or decides anything; it only describes what
was read (AppInfo, DeviceInfo, Snapshot) and what was concluded (Signal,
Finding, Report). Keeping these dumb makes the rules easy to test.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum


class Level(str, Enum):
    HIGH = "high"      # very likely junk: review for removal
    MEDIUM = "medium"  # worth a look, not enough evidence on its own

    @property
    def rank(self) -> int:
        return 2 if self is Level.HIGH else 1


@dataclass(frozen=True)
class AppInfo:
    """Everything we read about one user-installed app."""

    package: str
    installer: str | None = None            # package that installed it (None = unknown/adb/file)
    version_name: str | None = None
    first_install: datetime | None = None   # device-local time, as printed by Android
    requested_permissions: frozenset[str] = frozenset()
    granted_permissions: frozenset[str] = frozenset()
    has_overlay: bool = False               # allowed to draw over other apps
    is_accessibility_service: bool = False  # has an accessibility service switched on
    is_device_admin: bool = False           # is an active device administrator


@dataclass(frozen=True)
class DeviceInfo:
    manufacturer: str = "unknown"
    model: str = "unknown"
    android_release: str = "unknown"
    sdk: int | None = None
    battery_level: int | None = None
    battery_health: int | None = None       # Android BatteryManager code; 2 means "good"
    battery_temp_c: float | None = None
    storage_used_pct: int | None = None
    storage_free_gb: float | None = None
    taken_at: datetime | None = None        # the phone's own clock when we scanned

    @property
    def display_name(self) -> str:
        return f"{self.manufacturer} {self.model}".strip()


@dataclass(frozen=True)
class Snapshot:
    """A read-only picture of one phone at one moment."""

    device: DeviceInfo
    apps: tuple[AppInfo, ...] = ()


@dataclass(frozen=True)
class Signal:
    """One reason an app looks suspicious, with the weight it carries."""

    rule: str
    points: int
    reason: str  # plain English, written for the customer standing at the counter


@dataclass(frozen=True)
class Finding:
    app: AppInfo
    score: int
    level: Level
    signals: tuple[Signal, ...]
    removal_note: str | None = None


@dataclass(frozen=True)
class Report:
    device: DeviceInfo
    scanned: int
    findings: tuple[Finding, ...] = ()
    device_notes: tuple[str, ...] = field(default_factory=tuple)

    def at_level(self, minimum: Level) -> tuple[Finding, ...]:
        return tuple(f for f in self.findings if f.level.rank >= minimum.rank)
