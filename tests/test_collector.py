from datetime import datetime

import pytest

from phonecheck.adb import AdbError, FixtureDevice
from phonecheck.collector import collect


def by_package(snapshot):
    return {app.package: app for app in snapshot.apps}


class TestDeviceInfo:
    def test_reads_device_facts(self, messy_snapshot):
        info = messy_snapshot.device
        assert info.manufacturer == "DemoCorp"
        assert info.model == "Demo A1"
        assert info.android_release == "13"
        assert info.sdk == 33
        assert info.battery_level == 38
        assert info.battery_health == 2
        assert info.battery_temp_c == pytest.approx(43.6)
        assert info.storage_used_pct == 93
        assert info.storage_free_gb == pytest.approx(7.7, abs=0.1)
        assert info.taken_at == datetime(2026, 10, 6, 14, 5, 0)


class TestApps:
    def test_counts_only_user_installed_apps(self, messy_snapshot, clean_snapshot):
        assert len(messy_snapshot.apps) == 13
        assert len(clean_snapshot.apps) == 8

    def test_sideloaded_cleaner_has_every_risky_trait(self, messy_snapshot):
        app = by_package(messy_snapshot)["com.fastphone.supercleaner.pro"]
        assert app.installer is None
        assert app.has_overlay and app.is_accessibility_service
        assert not app.is_device_admin
        assert "android.permission.KILL_BACKGROUND_PROCESSES" in app.requested_permissions
        assert app.first_install == datetime(2026, 10, 4, 18, 20, 11)
        assert app.version_name == "4.2.1"

    def test_device_admin_detected(self, messy_snapshot):
        apps = by_package(messy_snapshot)
        assert apps["com.virusshield.antivirus.free"].is_device_admin
        assert not apps["com.whatsapp"].is_device_admin

    def test_store_installer_read_from_package_list(self, messy_snapshot):
        assert by_package(messy_snapshot)["com.whatsapp"].installer == "com.android.vending"

    def test_runtime_permissions_counted_as_granted(self, messy_snapshot):
        assert "android.permission.READ_SMS" in by_package(messy_snapshot)["com.virusshield.antivirus.free"].granted_permissions

    def test_clean_phone_has_no_risky_traits(self, clean_snapshot):
        for app in clean_snapshot.apps:
            assert not (app.has_overlay or app.is_accessibility_service or app.is_device_admin), app.package
            assert app.installer == "com.android.vending"


class TestResilience:
    def test_progress_reports_every_app(self, messy_device):
        seen = []
        collect(messy_device, workers=1, progress=lambda done, total: seen.append((done, total)))
        assert seen[-1] == (13, 13)
        assert len(seen) == 13

    def test_missing_optional_reads_do_not_break_the_scan(self, tmp_path, demo_dir):
        # Drop the optional answers from a copy of the messy phone.
        import json
        import shutil

        copy = tmp_path / "copy"
        shutil.copytree(demo_dir / "messy", copy)
        manifest = json.loads((copy / "manifest.json").read_text())
        for key in [
            "dumpsys battery",
            "df /data",
            "dumpsys device_policy",
            "cmd appops query-op SYSTEM_ALERT_WINDOW allow",
            "settings get secure enabled_accessibility_services",
        ]:
            del manifest["commands"][key]
        (copy / "manifest.json").write_text(json.dumps(manifest))

        snapshot = collect(FixtureDevice(copy))
        assert len(snapshot.apps) == 13
        assert snapshot.device.battery_level is None
        assert snapshot.device.storage_used_pct is None
        assert not any(app.is_device_admin or app.is_accessibility_service for app in snapshot.apps)
        # without appops, overlay falls back to the permission being granted in dumpsys
        assert by_package(snapshot)["com.fastphone.supercleaner.pro"].has_overlay

    def test_unreadable_app_list_is_a_hard_error(self, tmp_path, demo_dir):
        import json
        import shutil

        copy = tmp_path / "copy"
        shutil.copytree(demo_dir / "clean", copy)
        manifest = json.loads((copy / "manifest.json").read_text())
        del manifest["commands"]["pm list packages -3 -i"]
        (copy / "manifest.json").write_text(json.dumps(manifest))
        with pytest.raises(AdbError):
            collect(FixtureDevice(copy))

    def test_package_names_that_fail_validation_are_skipped(self, tmp_path, demo_dir):
        import shutil

        copy = tmp_path / "copy"
        shutil.copytree(demo_dir / "clean", copy)
        listing = copy / "pm_list_packages_-3_-i.txt"
        listing.write_text(listing.read_text() + "package:evil;reboot  installer=null\n")
        snapshot = collect(FixtureDevice(copy))
        assert all(";" not in app.package for app in snapshot.apps)
        assert len(snapshot.apps) == 8
