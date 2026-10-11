from datetime import datetime

from phonecheck.parsers import (
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

DUMP = """\
Packages:
  Package [com.example.cleaner] (a1b2c3):
    userId=10234
    versionCode=42 minSdk=24 targetSdk=33
    versionName=3.1.4
    declared permissions:
      com.example.cleaner.permission.PRIVATE: prot=signature
    requested permissions:
      android.permission.INTERNET
      android.permission.SYSTEM_ALERT_WINDOW
      android.permission.RECEIVE_BOOT_COMPLETED
      android.permission.READ_SMS: restricted=true
    firstInstallTime=2026-10-04 09:12:31
    lastUpdateTime=2026-10-04 09:12:31
    installerPackageName=com.android.vending
    install permissions:
      android.permission.INTERNET: granted=true
      android.permission.RECEIVE_BOOT_COMPLETED: granted=true
      android.permission.SYSTEM_ALERT_WINDOW: granted=false
    User 0: ceDataInode=1234 installed=true hidden=false
      runtime permissions:
        android.permission.READ_SMS: granted=true, flags=[ USER_SET]
        android.permission.CAMERA: granted=false, flags=[ ]
"""


class TestPackageList:
    def test_with_and_without_installer(self):
        text = (
            "package:com.a.one  installer=com.android.vending\n"
            "package:com.b.two  installer=null\n"
            "package:com.c.three\n"
        )
        assert parse_package_list(text) == [
            ("com.a.one", "com.android.vending"),
            ("com.b.two", None),
            ("com.c.three", None),
        ]

    def test_ignores_noise_and_blank_lines(self):
        assert parse_package_list("\nWARNING: linker\npackage:com.x.y\n") == [("com.x.y", None)]

    def test_empty(self):
        assert parse_package_list("") == []


class TestPackageDump:
    def test_basic_fields(self):
        dump = parse_package_dump(DUMP)
        assert dump.version_name == "3.1.4"
        assert dump.installer == "com.android.vending"
        assert dump.first_install == datetime(2026, 10, 4, 9, 12, 31)

    def test_requested_permissions_stop_at_next_section(self):
        dump = parse_package_dump(DUMP)
        assert dump.requested == {
            "android.permission.INTERNET",
            "android.permission.SYSTEM_ALERT_WINDOW",
            "android.permission.RECEIVE_BOOT_COMPLETED",
            "android.permission.READ_SMS",
        }
        # declared permissions belong to the app, not requests it makes
        assert "com.example.cleaner.permission.PRIVATE" not in dump.requested

    def test_granted_combines_install_and_runtime_and_skips_denied(self):
        dump = parse_package_dump(DUMP)
        assert dump.granted == {
            "android.permission.INTERNET",
            "android.permission.RECEIVE_BOOT_COMPLETED",
            "android.permission.READ_SMS",
        }

    def test_installer_null_is_none(self):
        assert parse_package_dump("    installerPackageName=null\n").installer is None

    def test_falls_back_to_initiating_installer(self):
        text = "    installerPackageName=null\n    installInitiatingPackageName=com.sec.android.app.samsungapps\n"
        assert parse_package_dump(text).installer == "com.sec.android.app.samsungapps"

    def test_garbage_gives_empty_result(self):
        dump = parse_package_dump("Unable to find package: com.gone.app\n")
        assert dump.version_name is None
        assert dump.requested == frozenset()
        assert dump.granted == frozenset()


class TestDeviceReadings:
    def test_battery(self):
        text = "Current Battery Service state:\n  AC powered: false\n  status: 3\n  health: 2\n  level: 87\n  temperature: 301\n"
        assert parse_battery(text) == {"health": 2, "level": 87, "temperature": 301}

    def test_battery_first_occurrence_wins(self):
        assert parse_battery("  level: 50\n  level: 99\n") == {"level": 50}

    def test_df(self):
        text = (
            "Filesystem       1K-blocks     Used Available Use% Mounted on\n"
            "/dev/block/dm-9  115234816 98234112  16900704  86% /data\n"
        )
        percent, free_gb = parse_df(text)
        assert percent == 86
        assert round(free_gb, 1) == 16.1

    def test_df_missing_mount(self):
        assert parse_df("Filesystem 1K-blocks Used Available Use% Mounted on\n") is None

    def test_df_ignores_non_numeric(self):
        assert parse_df("x y z w v /data\n") is None

    def test_device_time(self):
        assert parse_device_time("2026-10-06T14:00:00\n") == datetime(2026, 10, 6, 14, 0, 0)
        assert parse_device_time("not a date") is None


class TestSettingsAndPolicy:
    def test_accessibility_null_and_empty(self):
        assert parse_component_setting("null\n") == set()
        assert parse_component_setting("") == set()

    def test_accessibility_multiple_services(self):
        text = "com.a.one/com.a.one.Service:com.b.two/.Short\n"
        assert parse_component_setting(text) == {"com.a.one", "com.b.two"}

    def test_accessibility_ignores_junk_tokens(self):
        assert parse_component_setting("not a package/Svc;rm -rf") == set()

    def test_device_admins(self):
        text = (
            "Policy for user 0\n"
            "Enabled Device Admins (User 0, provisioningState: 0):\n"
            "  com.shield.antivirus/com.shield.antivirus.AdminReceiver:\n"
            "    uid=10123\n"
            "    testOnlyAdmin=false\n"
            "Some other section:\n"
            "  com.not.admin/com.not.admin.Thing:\n"
        )
        assert parse_device_admins(text) == {"com.shield.antivirus"}

    def test_no_device_admins(self):
        assert parse_device_admins("Enabled Device Admins (User 0, provisioningState: 0):\n\nOther:\n") == set()

    def test_overlay_packages_tolerates_formats(self):
        text = "Uid mode: SYSTEM_ALERT_WINDOW: allow\ncom.a.one\npackage:com.b.two\nPackage com.c.three: allow\n"
        assert parse_overlay_packages(text) == {"com.a.one", "com.b.two", "com.c.three"}


class TestLauncherAndBattery:
    BRIEF = (
        "3 activities found:\n"
        "  Activity #0:\n"
        "    priority=0 preferredOrder=0 match=0x108000 specificIndex=-1 isDefault=false\n"
        "    com.android.settings/.Settings\n"
        "  Activity #1:\n"
        "    com.example.app/com.example.app.ui.MainActivity\n"
        "  Activity #2:\n"
        "    org.demo.x/.Main\n"
    )

    def test_launcher_packages_from_brief_output(self):
        assert parse_launcher_packages(self.BRIEF) == {"com.android.settings", "com.example.app", "org.demo.x"}

    def test_launcher_ignores_echoed_intent_names(self):
        # Some versions echo the query; an action or category name is not an app.
        text = "Query: android.intent.action.MAIN android.intent.category.LAUNCHER\n  com.a.b/.Main\n"
        assert parse_launcher_packages(text) == {"com.a.b"}

    def test_launcher_rejects_injection_shaped_tokens(self):
        assert parse_launcher_packages("x;reboot/.Main\n  com.ok.app/.Main\n") == {"com.ok.app"}
        assert parse_launcher_packages("") == set()

    def test_idle_whitelist_keeps_only_user_entries(self):
        text = (
            "system-excidle,com.android.phone,1001\n"
            "system,com.google.android.gms,10123\n"
            "user,com.example.tracker,10234\n"
            "user,not a package,10235\n"
            "garbage line\n"
        )
        assert parse_idle_whitelist(text) == {"com.example.tracker"}

    def test_idle_whitelist_empty(self):
        assert parse_idle_whitelist("") == set()

    def test_notification_listeners_share_the_component_format(self):
        text = "com.watch.companion/com.watch.companion.NotificationService:com.spy.thing/.L\n"
        assert parse_component_setting(text) == {"com.watch.companion", "com.spy.thing"}


def test_is_valid_package():
    assert is_valid_package("com.example.app")
    assert is_valid_package("org.thoughtcrime.securesms")
    for bad in ["", "nodots", "com..double", "com.ex ample", "com.example;ls", "1com.example", "com.example.\n"]:
        assert not is_valid_package(bad), bad
