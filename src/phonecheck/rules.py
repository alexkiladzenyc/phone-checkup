"""The rule engine: decide which apps deserve a human's attention, and say why.

Design in one paragraph: every rule is a small pure function from
(app, context) to either nothing or a Signal carrying points and a reason in
plain English. An app's score is the sum of its signals' points. No single weak
signal (a junk-sounding name, a missing store) can flag an app as "likely junk"
on its own; the strong signals (accessibility service, device administrator,
overlay) are what push an app over the line. The engine never removes anything;
it only produces Findings for a person to review.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass, replace
from datetime import datetime

from . import lists
from .models import AppInfo, DeviceInfo, Finding, Level, Report, Signal, Snapshot

# Installers we treat as "a real app store". Anything else (None, a file
# manager, adb, an unknown package) counts as "not from a store".
STORE_INSTALLERS = frozenset(
    {
        "com.android.vending",              # Google Play
        "com.sec.android.app.samsungapps",  # Samsung Galaxy Store
        "com.amazon.venezia",               # Amazon Appstore
    }
)

NAME_KEYWORDS = (
    "cleaner", "booster", "speedup", "antivirus", "virus", "junk",
    "cooler", "optimizer", "batterysaver", "ramclean", "phoneclean",
)

_P = "android.permission."
CLEANER_PERMISSIONS = frozenset(
    _P + name
    for name in (
        "KILL_BACKGROUND_PROCESSES", "CLEAR_APP_CACHE", "GET_TASKS",
        "REQUEST_DELETE_PACKAGES", "PACKAGE_USAGE_STATS",
    )
)
BOOT_PERMISSION = _P + "RECEIVE_BOOT_COMPLETED"

# Granted permissions grouped by what they mean to a customer.
SENSITIVE_ACCESS = {
    _P + "READ_SMS": "texts",
    _P + "RECEIVE_SMS": "texts",
    _P + "SEND_SMS": "texts",
    _P + "READ_CONTACTS": "contacts",
    _P + "READ_CALL_LOG": "call history",
    _P + "WRITE_CALL_LOG": "call history",
    _P + "RECORD_AUDIO": "microphone",
    _P + "CALL_PHONE": "making calls",
    _P + "ANSWER_PHONE_CALLS": "making calls",
}

MEDIUM_AT = 3  # score at which an app is worth a look
HIGH_AT = 6    # score at which an app is very likely junk
RECENT_DAYS = 7


@dataclass(frozen=True)
class Context:
    now: datetime | None
    junk: frozenset[str]
    trusted: frozenset[str]
    store_installers: frozenset[str] = STORE_INSTALLERS


def build_context(
    *,
    extra_junk: Iterable[str] = (),
    extra_trusted: Iterable[str] = (),
    now: datetime | None = None,
) -> Context:
    return Context(
        now=now,
        junk=lists.load_bundled("known_junk.txt") | frozenset(extra_junk),
        trusted=lists.load_bundled("trusted_apps.txt") | frozenset(extra_trusted),
    )


# --------------------------------------------------------------------------
# Rules. Each returns a Signal, or None when it has nothing to say.
# --------------------------------------------------------------------------

Rule = Callable[[AppInfo, Context], "Signal | None"]


def known_junk(app: AppInfo, ctx: Context) -> Signal | None:
    if app.package in ctx.junk:
        return Signal("known_junk", 8, "It is on the list of apps already known to be junk.")
    return None


def junk_name(app: AppInfo, ctx: Context) -> Signal | None:
    name = app.package.lower()
    if any(keyword in name for keyword in NAME_KEYWORDS):
        return Signal(
            "junk_name", 3,
            "Its name sounds like a cleaner, booster or antivirus tool, a common disguise for scareware.",
        )
    return None


def not_from_store(app: AppInfo, ctx: Context) -> Signal | None:
    if app.installer in ctx.store_installers:
        return None
    source = "a file or a computer" if app.installer is None else app.installer
    return Signal("not_from_store", 2, f"It was not installed from a known app store (it came from {source}).")


def overlay(app: AppInfo, ctx: Context) -> Signal | None:
    if app.has_overlay:
        return Signal("overlay", 2, "It can draw on top of other apps, which is how fake 'virus found' pop-ups appear.")
    return None


def accessibility_service(app: AppInfo, ctx: Context) -> Signal | None:
    if app.is_accessibility_service:
        return Signal(
            "accessibility_service", 4,
            "It has an accessibility service switched on, so it can read the screen and tap for you. "
            "Normal for screen readers and password managers, unusual for anything else.",
        )
    return None


def device_admin(app: AppInfo, ctx: Context) -> Signal | None:
    if app.is_device_admin:
        return Signal("device_admin", 4, "It is a device administrator, which lets an app lock the phone and resist removal.")
    return None


def boot_start(app: AppInfo, ctx: Context) -> Signal | None:
    if BOOT_PERMISSION in app.requested_permissions:
        return Signal("boot_start", 1, "It starts itself every time the phone turns on.")
    return None


def cleaner_permissions(app: AppInfo, ctx: Context) -> Signal | None:
    if len(app.requested_permissions & CLEANER_PERMISSIONS) >= 2:
        return Signal(
            "cleaner_permissions", 2,
            "It asks for the permissions fake 'cleaners' use to look busy: closing other apps, clearing caches, watching app usage.",
        )
    return None


def sensitive_access(app: AppInfo, ctx: Context) -> Signal | None:
    areas = sorted({SENSITIVE_ACCESS[p] for p in app.granted_permissions if p in SENSITIVE_ACCESS})
    if len(areas) >= 3:
        return Signal("sensitive_access", 2, f"It has been given access to {', '.join(areas)}.")
    return None


def recently_installed(app: AppInfo, ctx: Context) -> Signal | None:
    if app.first_install is None or ctx.now is None:
        return None
    days = (ctx.now - app.first_install).days
    if 0 <= days <= RECENT_DAYS:
        when = "today" if days == 0 else f"{days} day{'s' if days != 1 else ''} ago"
        return Signal("recently_installed", 1, f"It was installed {when}. Ask the owner whether they remember installing it.")
    return None


RULES: tuple[Rule, ...] = (
    known_junk,
    junk_name,
    not_from_store,
    overlay,
    accessibility_service,
    device_admin,
    boot_start,
    cleaner_permissions,
    sensitive_access,
    recently_installed,
)


# --------------------------------------------------------------------------
# Putting it together
# --------------------------------------------------------------------------


def is_trusted(app: AppInfo, ctx: Context) -> bool:
    """Trusted means a well-known name *and* a real store installer.

    The installer check matters: a package name is just a string, so a
    sideloaded look-alike (or a modified copy) can reuse a famous name.
    Putting a package on the junk list overrides trust.
    """
    return (
        app.package in ctx.trusted
        and app.installer in ctx.store_installers
        and app.package not in ctx.junk
    )


def removal_note(app: AppInfo) -> str | None:
    if app.is_device_admin:
        return (
            "This app is a device administrator, so the phone will refuse to remove it until its admin rights are "
            "switched off in Settings (usually under Security, then Device admin apps; the name varies by phone maker)."
        )
    return None


def evaluate(app: AppInfo, ctx: Context) -> Finding | None:
    if is_trusted(app, ctx):
        return None
    signals = [signal for rule in RULES if (signal := rule(app, ctx)) is not None]
    score = sum(signal.points for signal in signals)
    if score < MEDIUM_AT:
        return None
    signals.sort(key=lambda s: (-s.points, s.rule))
    level = Level.HIGH if score >= HIGH_AT else Level.MEDIUM
    return Finding(app=app, score=score, level=level, signals=tuple(signals), removal_note=removal_note(app))


def device_notes(info: DeviceInfo) -> tuple[str, ...]:
    """Problems with the phone itself rather than with one app."""
    notes: list[str] = []
    if info.storage_used_pct is not None and info.storage_used_pct >= 90:
        free = f" ({info.storage_free_gb:.1f} GB free)" if info.storage_free_gb is not None else ""
        notes.append(f"Storage is {info.storage_used_pct}% full{free}. A nearly full phone runs slowly and can fail to update.")
    battery_problems = {
        3: "overheating", 4: "dead", 5: "over voltage", 6: "failing", 7: "too cold",
    }
    if info.battery_health in battery_problems:
        notes.append(f"Android reports the battery as {battery_problems[info.battery_health]}.")
    if info.battery_temp_c is not None and info.battery_temp_c >= 45:
        notes.append(f"The battery is warm ({info.battery_temp_c:.1f} C). Check again once the phone has cooled down.")
    if info.sdk is not None and info.sdk <= 30:
        notes.append(
            f"Android {info.android_release} is old; the maker may no longer send security updates. "
            "Check Settings for a software update."
        )
    return tuple(notes)


def analyze(snapshot: Snapshot, ctx: Context) -> Report:
    """Score every app in a snapshot. Judged against the phone's own clock when it reported one."""
    ctx = replace(ctx, now=snapshot.device.taken_at or ctx.now or datetime.now())
    findings = [finding for app in snapshot.apps if (finding := evaluate(app, ctx)) is not None]
    findings.sort(key=lambda f: (-f.score, f.app.package))
    return Report(
        device=snapshot.device,
        scanned=len(snapshot.apps),
        findings=tuple(findings),
        device_notes=device_notes(snapshot.device),
    )
