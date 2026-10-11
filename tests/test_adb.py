import json
import subprocess

import pytest

from phonecheck import adb
from phonecheck.adb import (
    LIST_USER_APPS,
    AdbDevice,
    AdbError,
    FixtureDevice,
    RecordingDevice,
    check_shell_args,
    list_devices,
)


class TestShellArgumentAllowlist:
    @pytest.mark.parametrize(
        "args",
        [
            ("pm", "list", "packages", "-3", "-i"),
            ("dumpsys", "package", "com.example.app"),
            ("date", "+%Y-%m-%dT%H:%M:%S"),
            ("df", "/data"),
            ("settings", "get", "secure", "enabled_accessibility_services"),
        ],
    )
    def test_allows_what_the_collector_sends(self, args):
        check_shell_args(args)

    @pytest.mark.parametrize(
        "arg",
        ["a;b", "a b", "a|b", "a&b", "$(id)", "`id`", "a>b", "a<b", "a\nb", "'a'", '"a"', "a*", "", "a\\b", "a(b)"],
    )
    def test_rejects_shell_metacharacters(self, arg):
        with pytest.raises(ValueError):
            check_shell_args(("echo", arg))

    def test_rejects_empty_command(self):
        with pytest.raises(ValueError):
            check_shell_args(())


class FakeRun:
    def __init__(self, returncode=0, stdout="", stderr=""):
        self.calls = []
        self._result = subprocess.CompletedProcess([], returncode, stdout, stderr)

    def __call__(self, command, **kwargs):
        self.calls.append((command, kwargs))
        return self._result


class TestAdbDevice:
    def test_builds_command_with_serial(self, monkeypatch):
        fake = FakeRun(stdout="ok\n")
        monkeypatch.setattr(adb.subprocess, "run", fake)
        out = AdbDevice(serial="ABC123", adb_path="/opt/adb").shell("getprop", "ro.product.model")
        assert out == "ok\n"
        command, kwargs = fake.calls[0]
        assert command == ["/opt/adb", "-s", "ABC123", "shell", "getprop", "ro.product.model"]
        assert kwargs["timeout"] == 30.0
        # never a local shell: arguments stay a list
        assert "shell" not in kwargs or kwargs["shell"] is False

    def test_no_serial_flag_when_not_given(self, monkeypatch):
        fake = FakeRun()
        monkeypatch.setattr(adb.subprocess, "run", fake)
        AdbDevice().shell("date")
        assert fake.calls[0][0] == ["adb", "shell", "date"]

    def test_unsafe_argument_never_reaches_subprocess(self, monkeypatch):
        fake = FakeRun()
        monkeypatch.setattr(adb.subprocess, "run", fake)
        with pytest.raises(ValueError):
            AdbDevice().shell("dumpsys", "package", "com.x;reboot")
        assert fake.calls == []

    def test_missing_adb_gives_helpful_error(self, monkeypatch):
        def boom(*a, **k):
            raise FileNotFoundError("adb")

        monkeypatch.setattr(adb.subprocess, "run", boom)
        with pytest.raises(AdbError, match="platform-tools"):
            AdbDevice().shell("date")

    def test_timeout_gives_helpful_error(self, monkeypatch):
        def boom(*a, **k):
            raise subprocess.TimeoutExpired("adb", 1)

        monkeypatch.setattr(adb.subprocess, "run", boom)
        with pytest.raises(AdbError, match="did not answer"):
            AdbDevice(timeout=1).shell("date")

    @pytest.mark.parametrize(
        "stderr,expected",
        [
            ("error: no devices/emulators found", "No phone found"),
            ("error: device unauthorized.", "tap Allow"),
            ("error: more than one device/emulator", "--serial"),
            ("error: device offline", "offline"),
            ("weird failure", "weird failure"),
        ],
    )
    def test_failures_are_translated(self, monkeypatch, stderr, expected):
        monkeypatch.setattr(adb.subprocess, "run", FakeRun(returncode=1, stderr=stderr))
        with pytest.raises(AdbError, match=expected):
            AdbDevice().shell("date")

    def test_uninstall_success_and_failure(self, monkeypatch):
        monkeypatch.setattr(adb.subprocess, "run", FakeRun(stdout="Success\n"))
        assert AdbDevice().uninstall("com.x.y") == (True, "Success")
        monkeypatch.setattr(
            adb.subprocess, "run", FakeRun(returncode=1, stdout="Failure [DELETE_FAILED_DEVICE_POLICY_MANAGER]\n")
        )
        ok, message = AdbDevice().uninstall("com.x.y")
        assert ok is False and "DEVICE_POLICY_MANAGER" in message

    def test_uninstall_rejects_bad_package_name(self, monkeypatch):
        fake = FakeRun()
        monkeypatch.setattr(adb.subprocess, "run", fake)
        with pytest.raises(ValueError):
            AdbDevice().uninstall("com.x.y; rm -rf /")
        assert fake.calls == []


class TestListDevices:
    def test_parses_adb_devices_output(self, monkeypatch):
        out = (
            "* daemon not running; starting now at tcp:5037\n"
            "* daemon started successfully\n"
            "List of devices attached\n"
            "R58M123ABC             device usb:1-1 product:a54x model:SM_A546U device:a54x transport_id:1\n"
            "emulator-5554          unauthorized transport_id:2\n"
            "\n"
        )
        monkeypatch.setattr(adb.subprocess, "run", FakeRun(stdout=out))
        entries = list_devices()
        assert [(e.serial, e.state) for e in entries] == [("R58M123ABC", "device"), ("emulator-5554", "unauthorized")]
        assert "SM_A546U" in entries[0].description

    def test_no_devices(self, monkeypatch):
        monkeypatch.setattr(adb.subprocess, "run", FakeRun(stdout="List of devices attached\n\n"))
        assert list_devices() == []


def make_fixture(tmp_path, commands, errors=None, uninstall=None):
    directory = tmp_path / "fx"
    directory.mkdir()
    manifest = {"format": 1, "commands": {}, "errors": errors or {}, "uninstall": uninstall or {}}
    for index, (key, text) in enumerate(commands.items()):
        name = f"f{index}.txt"
        (directory / name).write_text(text, encoding="utf-8")
        manifest["commands"][key] = name
    (directory / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    return directory


class TestFixtureDevice:
    def test_replays_recorded_output(self, tmp_path):
        directory = make_fixture(tmp_path, {"getprop ro.product.model": "Demo-A1\n"})
        assert FixtureDevice(directory).shell("getprop", "ro.product.model") == "Demo-A1\n"

    def test_unrecorded_command_is_an_error(self, tmp_path):
        directory = make_fixture(tmp_path, {})
        with pytest.raises(AdbError, match="no recording"):
            FixtureDevice(directory).shell("getprop", "x.y")

    def test_recorded_errors_replay(self, tmp_path):
        directory = make_fixture(tmp_path, {}, errors={"cmd appops query-op X allow": "not supported"})
        with pytest.raises(AdbError, match="not supported"):
            FixtureDevice(directory).shell("cmd", "appops", "query-op", "X", "allow")

    def test_missing_manifest(self, tmp_path):
        with pytest.raises(AdbError, match="Could not read a fixture"):
            FixtureDevice(tmp_path)

    def test_manifest_cannot_escape_its_directory(self, tmp_path):
        (tmp_path / "secret.txt").write_text("secret", encoding="utf-8")
        directory = make_fixture(tmp_path, {"date": "x"})
        manifest = json.loads((directory / "manifest.json").read_text())
        manifest["commands"]["date"] = "../secret.txt"
        (directory / "manifest.json").write_text(json.dumps(manifest))
        with pytest.raises(AdbError, match="escapes"):
            FixtureDevice(directory).shell("date")

    def test_uninstall_removes_from_listing_and_dump(self, tmp_path):
        listing = "package:com.a.one  installer=null\npackage:com.b.two  installer=null\n"
        directory = make_fixture(
            tmp_path,
            {
                " ".join(LIST_USER_APPS): listing,
                "dumpsys package com.a.one": "versionName=1\n",
            },
        )
        device = FixtureDevice(directory)
        assert device.uninstall("com.a.one") == (True, "Success")
        remaining = device.shell(*LIST_USER_APPS)
        assert "com.a.one" not in remaining and "com.b.two" in remaining
        assert "Unable to find package" in device.shell("dumpsys", "package", "com.a.one")

    def test_prefix_of_another_package_is_not_removed(self, tmp_path):
        listing = "package:com.a.one  installer=null\npackage:com.a.one.extra  installer=null\n"
        device = FixtureDevice(make_fixture(tmp_path, {" ".join(LIST_USER_APPS): listing}))
        device.uninstall("com.a.one")
        remaining = device.shell(*LIST_USER_APPS)
        assert "com.a.one.extra" in remaining
        assert "package:com.a.one " not in remaining

    def test_forced_failure_keeps_the_app(self, tmp_path):
        listing = "package:com.a.one  installer=null\n"
        directory = make_fixture(
            tmp_path,
            {" ".join(LIST_USER_APPS): listing},
            uninstall={"com.a.one": "Failure [DELETE_FAILED_DEVICE_POLICY_MANAGER]"},
        )
        device = FixtureDevice(directory)
        ok, message = device.uninstall("com.a.one")
        assert not ok and "DEVICE_POLICY_MANAGER" in message
        assert "com.a.one" in device.shell(*LIST_USER_APPS)

    def test_uninstalling_something_not_installed_fails(self, tmp_path):
        device = FixtureDevice(make_fixture(tmp_path, {" ".join(LIST_USER_APPS): "package:com.a.one\n"}))
        ok, _ = device.uninstall("com.zzz.none")
        assert ok is False


class TestRecordingDevice:
    def test_records_and_replays_identically(self, tmp_path):
        source = FixtureDevice(
            make_fixture(tmp_path, {"getprop ro.product.model": "Demo\n", "dumpsys battery": "  level: 5\n"})
        )
        out_dir = tmp_path / "rec"
        recorder = RecordingDevice(source, out_dir)
        recorder.shell("getprop", "ro.product.model")
        recorder.shell("dumpsys", "battery")
        recorder.save()

        replay = FixtureDevice(out_dir)
        assert replay.shell("getprop", "ro.product.model") == "Demo\n"
        assert replay.shell("dumpsys", "battery") == "  level: 5\n"

    def test_failures_are_recorded_and_replayed(self, tmp_path):
        source = FixtureDevice(make_fixture(tmp_path, {}))
        recorder = RecordingDevice(source, tmp_path / "rec")
        with pytest.raises(AdbError):
            recorder.shell("dumpsys", "nothing")
        recorder.save()
        with pytest.raises(AdbError, match="no recording"):
            FixtureDevice(tmp_path / "rec").shell("dumpsys", "nothing")

    def test_is_read_only(self, tmp_path):
        recorder = RecordingDevice(FixtureDevice(make_fixture(tmp_path, {})), tmp_path / "rec")
        with pytest.raises(NotImplementedError):
            recorder.uninstall("com.a.one")

    def test_colliding_filenames_do_not_overwrite(self, tmp_path):
        source = FixtureDevice(make_fixture(tmp_path, {"a b": "one", "a_b": "two"}))
        recorder = RecordingDevice(source, tmp_path / "rec")
        # "a b" can't pass the shell allowlist, so use two safe keys that slug the same
        source._commands.update({"a:b": source._commands["a b"], "a_b": source._commands["a_b"]})
        recorder.shell("a:b")
        recorder.shell("a_b")
        recorder.save()
        manifest = json.loads((tmp_path / "rec" / "manifest.json").read_text())
        assert len(set(manifest["commands"].values())) == 2
