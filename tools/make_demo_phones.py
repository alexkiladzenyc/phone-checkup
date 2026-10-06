#!/usr/bin/env python3
"""Generate the two synthetic demo phones bundled with phonecheck.

Everything here is invented: made-up apps, a made-up "DemoCorp" device, no real
customer data. The point is a reproducible phone that exercises every rule
(and a clean one that exercises none).

The script feeds scripted phone answers through the *real* collector and a
RecordingDevice, so the saved files always match exactly what the collector
asks a phone for. A test regenerates them and fails if the committed copies
have drifted.

    python tools/make_demo_phones.py            # rewrite src/phonecheck/demo_data/
    python tools/make_demo_phones.py --out DIR  # write somewhere else
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from phonecheck.adb import AdbError, RecordingDevice  # noqa: E402
from phonecheck.collector import collect  # noqa: E402

P = "android.permission."
PLAY = "com.android.vending"
BOOT = P + "RECEIVE_BOOT_COMPLETED"
OVERLAY = P + "SYSTEM_ALERT_WINDOW"
INTERNET = P + "INTERNET"


@dataclass
class DemoApp:
    package: str
    version: str
    installed: str                      # "YYYY-MM-DD HH:MM:SS"
    installer: str | None = PLAY
    requested: tuple[str, ...] = (INTERNET,)
    install_granted: tuple[str, ...] = (INTERNET,)
    runtime_granted: tuple[str, ...] = ()
    overlay: bool = False
    accessibility: bool = False
    admin: bool = False


@dataclass
class DemoPhone:
    props: dict[str, str]
    battery: dict[str, int]
    storage_used_pct: int
    storage_total_kb: int
    clock: str
    apps: list[DemoApp] = field(default_factory=list)
    uninstall_overrides: dict[str, str] = field(default_factory=dict)


def package_dump(app: DemoApp) -> str:
    lines = [
        "Packages:",
        f"  Package [{app.package}] (4f2a9c1):",
        "    userId=10234",
        "    versionCode=100 minSdk=24 targetSdk=33",
        f"    versionName={app.version}",
        f"    firstInstallTime={app.installed}",
        f"    lastUpdateTime={app.installed}",
        f"    installerPackageName={app.installer or 'null'}",
        "    requested permissions:",
        *[f"      {p}" for p in app.requested],
        "    install permissions:",
        *[f"      {p}: granted=true" for p in app.install_granted],
        "    User 0: ceDataInode=1234 installed=true hidden=false suspended=false",
        "      runtime permissions:",
        *[f"        {p}: granted=true, flags=[ USER_SET]" for p in app.runtime_granted],
    ]
    return "\n".join(lines) + "\n"


class ScriptedPhone:
    """Answers the collector's questions from a DemoPhone description."""

    def __init__(self, phone: DemoPhone):
        self.phone = phone
        self.answers = self._build()

    def _build(self) -> dict[str, str]:
        phone = self.phone
        used = phone.storage_total_kb * phone.storage_used_pct // 100
        answers = {
            "dumpsys battery": "Current Battery Service state:\n"
            + "".join(f"  {k}: {v}\n" for k, v in phone.battery.items()),
            "df /data": "Filesystem       1K-blocks     Used Available Use% Mounted on\n"
            f"/dev/block/dm-9  {phone.storage_total_kb} {used} {phone.storage_total_kb - used}  {phone.storage_used_pct}% /data\n",
            "date +%Y-%m-%dT%H:%M:%S": phone.clock + "\n",
            "pm list packages -3 -i": "".join(
                f"package:{a.package}  installer={a.installer or 'null'}\n" for a in phone.apps
            ),
        }
        for name, value in phone.props.items():
            answers[f"getprop {name}"] = value + "\n"

        services = [f"{a.package}/{a.package}.AccessService" for a in phone.apps if a.accessibility]
        answers["settings get secure enabled_accessibility_services"] = ":".join(services) + "\n" if services else "null\n"

        admin_lines = "".join(
            f"  {a.package}/{a.package}.AdminReceiver:\n    uid=10345\n    testOnlyAdmin=false\n"
            for a in phone.apps
            if a.admin
        )
        answers["dumpsys device_policy"] = (
            "Policy for user 0:\n"
            "Enabled Device Admins (User 0, provisioningState: 0):\n"
            f"{admin_lines}\n"
            "Encryption Status: ACTIVE_PER_USER\n"
        )
        overlay_apps = [a.package for a in phone.apps if a.overlay]
        answers["cmd appops query-op SYSTEM_ALERT_WINDOW allow"] = (
            "Uid mode: SYSTEM_ALERT_WINDOW: allow\n" + "".join(f"{p}\n" for p in overlay_apps)
        )
        for app in phone.apps:
            answers[f"dumpsys package {app.package}"] = package_dump(app)
        return answers

    def shell(self, *args: str) -> str:
        key = " ".join(args)
        if key not in self.answers:
            raise AdbError(f"scripted phone cannot answer: {key}")
        return self.answers[key]

    def uninstall(self, package: str) -> tuple[bool, str]:  # pragma: no cover - never used
        raise NotImplementedError


def messy_phone() -> DemoPhone:
    sensitive = (P + "READ_CONTACTS", P + "READ_SMS", P + "READ_CALL_LOG")
    return DemoPhone(
        props={
            "ro.product.manufacturer": "DemoCorp",
            "ro.product.model": "Demo A1",
            "ro.build.version.release": "13",
            "ro.build.version.sdk": "33",
        },
        battery={"status": 3, "health": 2, "level": 38, "temperature": 436},
        storage_used_pct=93,
        storage_total_kb=115234816,
        clock="2026-10-06T14:05:00",
        uninstall_overrides={"com.virusshield.antivirus.free": "Failure [DELETE_FAILED_DEVICE_POLICY_MANAGER]"},
        apps=[
            # A sideloaded "cleaner" that does nearly everything scareware does.
            DemoApp(
                "com.fastphone.supercleaner.pro", "4.2.1", "2026-10-04 18:20:11", installer=None,
                requested=(INTERNET, OVERLAY, BOOT, P + "KILL_BACKGROUND_PROCESSES", P + "CLEAR_APP_CACHE", P + "PACKAGE_USAGE_STATS"),
                install_granted=(INTERNET, BOOT, OVERLAY, P + "KILL_BACKGROUND_PROCESSES"),
                overlay=True, accessibility=True,
            ),
            # A "free antivirus" from the store that is also a device administrator.
            DemoApp(
                "com.virusshield.antivirus.free", "2.9.0", "2026-09-28 11:02:45",
                requested=(INTERNET, OVERLAY, BOOT) + sensitive,
                install_granted=(INTERNET, BOOT, OVERLAY),
                runtime_granted=sensitive,
                overlay=True, admin=True,
            ),
            # Store-installed, junk-sounding name, not much else: worth a look only.
            DemoApp(
                "com.fastcharge.batterysaver.cooler", "1.8.0", "2026-08-30 20:15:00",
                requested=(INTERNET, BOOT, P + "KILL_BACKGROUND_PROCESSES"),
                install_granted=(INTERNET, BOOT),
            ),
            # A game installed from outside any store.
            DemoApp(
                "com.freegames.puzzle.colorblast", "0.9.7", "2026-09-18 16:40:09", installer=None,
                requested=(INTERNET, BOOT), install_granted=(INTERNET, BOOT),
            ),
            # Well-known package name, but not installed from a store and with
            # accessibility + overlay: the trusted-name exemption must NOT apply.
            DemoApp(
                "com.instagram.android", "330.0.0.1", "2026-10-02 08:30:00", installer=None,
                requested=(INTERNET, OVERLAY, BOOT), install_granted=(INTERNET, BOOT, OVERLAY),
                overlay=True, accessibility=True,
            ),
            # Normal apps. WhatsApp has enough permissions to be flagged if it weren't trusted.
            DemoApp(
                "com.whatsapp", "2.26.30.1", "2025-03-12 09:00:00",
                requested=(INTERNET, BOOT) + sensitive + (P + "RECORD_AUDIO",),
                install_granted=(INTERNET, BOOT),
                runtime_granted=sensitive + (P + "RECORD_AUDIO",),
            ),
            DemoApp("com.spotify.music", "9.0.50", "2025-01-20 19:30:00", requested=(INTERNET, BOOT), install_granted=(INTERNET, BOOT)),
            DemoApp("com.facebook.katana", "510.0.0.1", "2025-02-02 12:00:00", requested=(INTERNET, BOOT), install_granted=(INTERNET, BOOT)),
            DemoApp("com.demo.weather.today", "3.4.1", "2025-06-10 07:45:00", requested=(INTERNET, P + "ACCESS_COARSE_LOCATION"), runtime_granted=(P + "ACCESS_COARSE_LOCATION",)),
            DemoApp("com.demo.notes.simple", "1.2.0", "2025-04-04 21:10:00"),
            DemoApp("com.demo.bank.mobile", "8.1.0", "2025-05-15 10:00:00", requested=(INTERNET, P + "USE_BIOMETRIC"), install_granted=(INTERNET, P + "USE_BIOMETRIC")),
            DemoApp("org.demo.pdfviewer", "2.0.3", "2025-07-01 15:20:00"),
            DemoApp("com.demo.fitness.steps", "5.6.0", "2025-08-08 06:30:00", requested=(INTERNET, P + "ACTIVITY_RECOGNITION"), runtime_granted=(P + "ACTIVITY_RECOGNITION",)),
        ],
    )


def clean_phone() -> DemoPhone:
    return DemoPhone(
        props={
            "ro.product.manufacturer": "DemoCorp",
            "ro.product.model": "Demo B2",
            "ro.build.version.release": "15",
            "ro.build.version.sdk": "35",
        },
        battery={"status": 3, "health": 2, "level": 82, "temperature": 301},
        storage_used_pct=52,
        storage_total_kb=115234816,
        clock="2026-10-06T14:05:00",
        apps=[
            DemoApp("com.whatsapp", "2.26.30.1", "2025-03-12 09:00:00", requested=(INTERNET, BOOT), install_granted=(INTERNET, BOOT)),
            DemoApp("com.spotify.music", "9.0.50", "2025-01-20 19:30:00", requested=(INTERNET, BOOT), install_granted=(INTERNET, BOOT)),
            DemoApp("com.demo.weather.today", "3.4.1", "2025-06-10 07:45:00", requested=(INTERNET, P + "ACCESS_COARSE_LOCATION"), runtime_granted=(P + "ACCESS_COARSE_LOCATION",)),
            DemoApp("com.demo.notes.simple", "1.2.0", "2025-04-04 21:10:00"),
            DemoApp("com.demo.bank.mobile", "8.1.0", "2025-05-15 10:00:00", requested=(INTERNET, P + "USE_BIOMETRIC"), install_granted=(INTERNET, P + "USE_BIOMETRIC")),
            DemoApp("org.demo.pdfviewer", "2.0.3", "2025-07-01 15:20:00"),
            DemoApp("com.demo.fitness.steps", "5.6.0", "2025-08-08 06:30:00", requested=(INTERNET, P + "ACTIVITY_RECOGNITION"), runtime_granted=(P + "ACTIVITY_RECOGNITION",)),
            DemoApp("com.demo.maps.local", "11.2.0", "2025-09-09 13:00:00", requested=(INTERNET, P + "ACCESS_FINE_LOCATION"), runtime_granted=(P + "ACCESS_FINE_LOCATION",)),
        ],
    )


PHONES = {"messy": messy_phone, "clean": clean_phone}


def write_phone(name: str, destination: Path) -> None:
    phone = PHONES[name]()
    if destination.exists():
        shutil.rmtree(destination)
    recorder = RecordingDevice(ScriptedPhone(phone), destination)
    collect(recorder, workers=1)
    recorder.save()
    manifest_path = destination / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["uninstall"] = phone.uninstall_overrides
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--out", type=Path, default=ROOT / "src" / "phonecheck" / "demo_data")
    args = parser.parse_args(argv)
    for name in PHONES:
        write_phone(name, args.out / name)
        print(f"wrote {args.out / name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
