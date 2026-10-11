import pytest

from phonecheck.adb import LIST_USER_APPS
from phonecheck.collector import collect
from phonecheck.removal import RemovalRefused, remove_packages
from phonecheck.rules import analyze, build_context


def installed(device):
    return {app.package for app in collect(device).apps}


def test_removes_a_chosen_app_and_it_is_gone_on_rescan(messy_device):
    results = remove_packages(messy_device, ["com.fastphone.supercleaner.pro"])
    assert [(r.package, r.ok) for r in results] == [("com.fastphone.supercleaner.pro", True)]
    assert "com.fastphone.supercleaner.pro" not in installed(messy_device)
    assert len(installed(messy_device)) == 12


def test_only_the_chosen_apps_are_removed(messy_device):
    before = installed(messy_device)
    remove_packages(messy_device, ["com.freegames.puzzle.colorblast", "com.fastcharge.batterysaver.cooler"])
    assert before - installed(messy_device) == {"com.freegames.puzzle.colorblast", "com.fastcharge.batterysaver.cooler"}


def test_duplicates_are_removed_once(messy_device):
    results = remove_packages(messy_device, ["com.freegames.puzzle.colorblast"] * 3)
    assert len(results) == 1


def test_device_admin_app_fails_with_a_useful_hint(messy_device):
    (result,) = remove_packages(messy_device, ["com.virusshield.antivirus.free"])
    assert not result.ok
    assert "DEVICE_POLICY_MANAGER" in result.message
    assert "device administrator" in result.hint
    assert "com.virusshield.antivirus.free" in installed(messy_device)  # still there


def test_one_failure_does_not_stop_the_others(messy_device):
    results = remove_packages(messy_device, ["com.virusshield.antivirus.free", "com.freegames.puzzle.colorblast"])
    assert [r.ok for r in results] == [False, True]


def test_rescan_after_removal_changes_the_report(messy_device):
    ctx = build_context()
    before = analyze(collect(messy_device), ctx)
    remove_packages(messy_device, ["com.fastphone.supercleaner.pro", "com.instagram.android"])
    after = analyze(collect(messy_device), ctx)
    assert len(before.findings) - len(after.findings) == 2
    assert next(f.app.package for f in after.findings) == "com.virusshield.antivirus.free"


class TestRefusals:
    @pytest.mark.parametrize(
        "bad",
        ["", "nodots", "com.x.y; rm -rf /", "com.x.y && reboot", "$(id)", "com.x.y\n", "../../etc/passwd"],
    )
    def test_invalid_package_names(self, messy_device, bad):
        with pytest.raises(RemovalRefused, match="Not valid package names"):
            remove_packages(messy_device, [bad])

    def test_system_app_is_refused_because_it_is_not_in_the_user_list(self, messy_device):
        with pytest.raises(RemovalRefused, match="not user-installed"):
            remove_packages(messy_device, ["com.android.systemui"])

    def test_nothing_is_removed_if_any_request_is_refused(self, messy_device):
        before = installed(messy_device)
        with pytest.raises(RemovalRefused):
            remove_packages(messy_device, ["com.freegames.puzzle.colorblast", "com.android.systemui"])
        assert installed(messy_device) == before

    def test_empty_selection(self, messy_device):
        with pytest.raises(RemovalRefused, match="No apps were selected"):
            remove_packages(messy_device, [])

    def test_list_command_is_the_one_the_guard_trusts(self):
        assert LIST_USER_APPS == ("pm", "list", "packages", "-3", "-i")
