"""Read a phone and build a Snapshot.

This is the only module that decides *which* commands to run. It never
changes anything on the phone; every command below only reads.
"""

from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor
from typing import Callable, TypeVar

from .adb import LIST_USER_APPS, AdbError, Device
from .models import AppInfo, DeviceInfo, Snapshot
from .parsers import (
    is_valid_package,
    parse_accessibility,
    parse_battery,
    parse_device_admins,
    parse_device_time,
    parse_df,
    parse_overlay_packages,
    parse_package_dump,
    parse_package_list,
)

OVERLAY_PERMISSION = "android.permission.SYSTEM_ALERT_WINDOW"

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

    accessibility = _optional(
        lambda: parse_accessibility(device.shell("settings", "get", "secure", "enabled_accessibility_services")),
        set(),
    )
    admins = _optional(lambda: parse_device_admins(device.shell("dumpsys", "device_policy")), set())
    # None means "could not ask", which differs from "asked and nobody has it".
    overlay: set[str] | None = _optional(
        lambda: parse_overlay_packages(device.shell("cmd", "appops", "query-op", "SYSTEM_ALERT_WINDOW", "allow")),
        None,
    )

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
        )
        with done_lock:
            done += 1
            if progress:
                progress(done, len(listed))
        return app

    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        apps = tuple(pool.map(inspect, listed))
    return Snapshot(device=info, apps=apps)
