"""Read a phone and build a Snapshot.

This is the only module that decides *which* commands to run. It never
changes anything on the phone; every command below only reads.
"""

from __future__ import annotations

import threading
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from typing import TypeVar

from .adb import LIST_USER_APPS, AdbError, Device
from .models import AppInfo, DeviceInfo, Snapshot
from .parsers import (
    is_valid_package,
    parse_battery,
    parse_component_setting,
    parse_device_admins,
    parse_device_time,
    parse_df,
    parse_idle_whitelist,
    parse_launcher_packages,
    parse_overlay_packages,
    parse_package_dump,
    parse_package_list,
)

OVERLAY_PERMISSION = "android.permission.SYSTEM_ALERT_WINDOW"
LAUNCHER_QUERY = (
    "cmd", "package", "query-activities", "--brief",
    "-a", "android.intent.action.MAIN", "-c", "android.intent.category.LAUNCHER",
)

T = TypeVar("T")


def _optional(read: Callable[[], T], default: T) -> T:
    """Run a non-essential read; if the phone refuses or lacks it, carry on with a default."""
    try:
        return read()
    except AdbError:
        return default


def _read_device_info(device: Device) -> DeviceInfo:
    def prop(name: str) -> str:
        return _optional(lambda: device.shell("getprop", name).strip(), "") or "unknown"

    sdk_text = prop("ro.build.version.sdk")
    battery = parse_battery(_optional(lambda: device.shell("dumpsys", "battery"), ""))
    storage = parse_df(_optional(lambda: device.shell("df", "/data"), ""))
    temperature = battery.get("temperature")  # reported in tenths of a degree Celsius
    return DeviceInfo(
        manufacturer=prop("ro.product.manufacturer"),
        model=prop("ro.product.model"),
        android_release=prop("ro.build.version.release"),
        sdk=int(sdk_text) if sdk_text.isdigit() else None,
        battery_level=battery.get("level"),
        battery_health=battery.get("health"),
        battery_temp_c=temperature / 10 if temperature is not None else None,
        storage_used_pct=storage[0] if storage else None,
        storage_free_gb=storage[1] if storage else None,
        taken_at=parse_device_time(_optional(lambda: device.shell("date", "+%Y-%m-%dT%H:%M:%S"), "")),
    )


def collect(
    device: Device,
    *,
    workers: int = 4,
    progress: Callable[[int, int], None] | None = None,
) -> Snapshot:
    """Read device facts and every user-installed app (system apps are deliberately skipped)."""
    info = _read_device_info(device)

    # Without the app list there is nothing to do, so this one is allowed to fail loudly.
    listed = [
        (package, installer)
        for package, installer in parse_package_list(device.shell(*LIST_USER_APPS))
        if is_valid_package(package)
    ]

    def secure_setting(name: str) -> set[str]:
        return _optional(lambda: parse_component_setting(device.shell("settings", "get", "secure", name)), set())

    accessibility = secure_setting("enabled_accessibility_services")
    listeners = secure_setting("enabled_notification_listeners")
    admins: set[str] = _optional(lambda: parse_device_admins(device.shell("dumpsys", "device_policy")), set())
    battery_exempt: set[str] = _optional(lambda: parse_idle_whitelist(device.shell("dumpsys", "deviceidle", "whitelist")), set())
    # None means "could not ask", which differs from "asked and nobody has it".
    overlay: set[str] | None = _optional(
        lambda: parse_overlay_packages(device.shell("cmd", "appops", "query-op", "SYSTEM_ALERT_WINDOW", "allow")),
        None,
    )
    # Every phone has *some* launcher apps (Settings, at least), so an empty answer
    # means the output was not understood; treat that as "unknown" rather than
    # "no app has an icon", which would flag everything.
    launchable: set[str] | None = _optional(lambda: parse_launcher_packages(device.shell(*LAUNCHER_QUERY)), None) or None

    done = 0
    done_lock = threading.Lock()

    def inspect(item: tuple[str, str | None]) -> AppInfo:
        nonlocal done
        package, installer = item
        dump = parse_package_dump(_optional(lambda: device.shell("dumpsys", "package", package), ""))
        granted_overlay = OVERLAY_PERMISSION in dump.granted
        app = AppInfo(
            package=package,
            installer=installer or dump.installer,
            version_name=dump.version_name,
            first_install=dump.first_install,
            requested_permissions=dump.requested,
            granted_permissions=dump.granted,
            has_overlay=(package in overlay) if overlay is not None else granted_overlay,
            is_accessibility_service=package in accessibility,
            is_device_admin=package in admins,
            is_notification_listener=package in listeners,
            is_battery_exempt=package in battery_exempt,
            has_launcher_icon=(package in launchable) if launchable is not None else None,
        )
        with done_lock:
            done += 1
            if progress:
                progress(done, len(listed))
        return app

    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        apps = tuple(pool.map(inspect, listed))
    return Snapshot(device=info, apps=apps)
