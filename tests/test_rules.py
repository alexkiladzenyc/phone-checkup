from dataclasses import replace
from datetime import datetime, timedelta

import pytest

from phonecheck import rules
from phonecheck.models import AppInfo, DeviceInfo, Level, Snapshot
from phonecheck.rules import (
    BOOT_PERMISSION,
    STORE_INSTALLERS,
    Context,
    analyze,
    build_context,
    device_notes,
    evaluate,
)

PLAY = "com.android.vending"
NOW = datetime(2026, 10, 6, 14, 0, 0)
P = "android.permission."


def ctx(**overrides) -> Context:
    base = Context(now=NOW, junk=frozenset(), trusted=frozenset())
    return replace(base, **overrides)


def app(package="com.example.plain", **fields) -> AppInfo:
    fields.setdefault("installer", PLAY)
    return AppInfo(package=package, **fields)


def rule_names(finding) -> set[str]:
    return {s.rule for s in finding.signals}


class TestIndividualRules:
    def test_known_junk_is_high_on_its_own(self):
        finding = evaluate(app("com.bad.thing"), ctx(junk=frozenset({"com.bad.thing"})))
        assert finding.level is Level.HIGH and finding.score == 8
        assert rule_names(finding) == {"known_junk"}

    def test_name_alone_is_never_high(self):
        # A junk-sounding name is only "worth a look"; it takes behaviour to reach "likely junk".
        finding = evaluate(app("com.some.phonecleaner"), ctx())
        assert finding.level is Level.MEDIUM and finding.score == 3
        assert rule_names(finding) == {"junk_name"}

    def test_name_plus_boot_is_only_worth_a_look(self):
        finding = evaluate(app("com.some.phonecleaner", requested_permissions=frozenset({BOOT_PERMISSION})), ctx())
        assert finding.level is Level.MEDIUM and finding.score == 4

    def test_sideloading_alone_is_not_enough(self):
        assert evaluate(app(installer=None), ctx()) is None

    def test_sideloaded_plus_boot_reaches_medium(self):
        finding = evaluate(app(installer=None, requested_permissions=frozenset({BOOT_PERMISSION})), ctx())
        assert finding.level is Level.MEDIUM and finding.score == 3

    @pytest.mark.parametrize("installer", sorted(STORE_INSTALLERS))
    def test_every_known_store_counts_as_a_store(self, installer):
        assert rules.not_from_store(app(installer=installer), ctx()) is None

    def test_unknown_installer_is_named_in_the_reason(self):
        signal = rules.not_from_store(app(installer="com.shady.installer"), ctx())
        assert "com.shady.installer" in signal.reason

    def test_accessibility_service_is_strong(self):
        finding = evaluate(app(is_accessibility_service=True, installer=None), ctx())
        assert finding.level is Level.HIGH  # 4 + 2
        assert "accessibility_service" in rule_names(finding)

    def test_device_admin_gets_a_removal_note(self):
        finding = evaluate(app(is_device_admin=True, has_overlay=True), ctx())
        assert finding.level is Level.HIGH
        assert "device administrator" in finding.removal_note

    def test_no_removal_note_for_ordinary_apps(self):
        finding = evaluate(app(installer=None, has_overlay=True, is_accessibility_service=True), ctx())
        assert finding.removal_note is None

    def test_cleaner_permissions_need_two(self):
        one = app(requested_permissions=frozenset({P + "KILL_BACKGROUND_PROCESSES"}))
        two = app(requested_permissions=frozenset({P + "KILL_BACKGROUND_PROCESSES", P + "CLEAR_APP_CACHE"}))
        assert rules.cleaner_permissions(one, ctx()) is None
        assert rules.cleaner_permissions(two, ctx()) is not None

    def test_sensitive_access_counts_areas_not_permissions(self):
        sms_only = app(granted_permissions=frozenset({P + "READ_SMS", P + "SEND_SMS", P + "RECEIVE_SMS"}))
        assert rules.sensitive_access(sms_only, ctx()) is None  # three permissions, one area
        broad = app(granted_permissions=frozenset({P + "READ_SMS", P + "READ_CONTACTS", P + "RECORD_AUDIO"}))
        signal = rules.sensitive_access(broad, ctx())
        assert "contacts" in signal.reason and "microphone" in signal.reason and "texts" in signal.reason

    @pytest.mark.parametrize(
        "age,expected",
        [(timedelta(hours=3), "today"), (timedelta(days=1), "1 day ago"), (timedelta(days=7), "7 days ago")],
    )
    def test_recent_install_wording(self, age, expected):
        signal = rules.recently_installed(app(first_install=NOW - age), ctx())
        assert expected in signal.reason

    def test_old_install_and_unknown_time_are_ignored(self):
        assert rules.recently_installed(app(first_install=NOW - timedelta(days=8)), ctx()) is None
        assert rules.recently_installed(app(first_install=None), ctx()) is None
        assert rules.recently_installed(app(first_install=NOW), ctx(now=None)) is None

    def test_install_time_in_the_future_is_ignored(self):
        assert rules.recently_installed(app(first_install=NOW + timedelta(days=2)), ctx()) is None


class TestTrust:
    def trusted_ctx(self, **kw):
        return ctx(trusted=frozenset({"com.whatsapp"}), **kw)

    def loud(self, installer):
        return app(
            "com.whatsapp", installer=installer, has_overlay=True, is_accessibility_service=True,
            requested_permissions=frozenset({BOOT_PERMISSION}),
        )

    def test_trusted_app_from_a_store_is_skipped_however_loud(self):
        assert evaluate(self.loud(PLAY), self.trusted_ctx()) is None

    def test_trusted_name_from_a_sideload_is_not_exempt(self):
        finding = evaluate(self.loud(None), self.trusted_ctx())
        assert finding is not None and finding.level is Level.HIGH

    def test_trusted_name_from_an_unknown_installer_is_not_exempt(self):
        assert evaluate(self.loud("com.shady.installer"), self.trusted_ctx()) is not None

    def test_junk_list_overrides_trust(self):
        context = self.trusted_ctx(junk=frozenset({"com.whatsapp"}))
        assert evaluate(self.loud(PLAY), context).level is Level.HIGH


class TestScoring:
    def test_thresholds(self):
        assert rules.MEDIUM_AT == 3 and rules.HIGH_AT == 6

    def test_signals_are_ordered_strongest_first(self):
        finding = evaluate(app(installer=None, has_overlay=True, is_accessibility_service=True), ctx())
        points = [s.points for s in finding.signals]
        assert points == sorted(points, reverse=True)

    def test_score_is_the_sum_of_signal_points(self):
        finding = evaluate(app(installer=None, has_overlay=True, is_accessibility_service=True), ctx())
        assert finding.score == sum(s.points for s in finding.signals) == 8

    def test_every_reason_is_plain_english_text(self):
        finding = evaluate(
            app(
                "com.x.cleaner", installer=None, has_overlay=True, is_accessibility_service=True, is_device_admin=True,
                requested_permissions=frozenset({BOOT_PERMISSION, P + "KILL_BACKGROUND_PROCESSES", P + "CLEAR_APP_CACHE"}),
                first_install=NOW,
            ),
            ctx(junk=frozenset({"com.x.cleaner"})),
        )
        assert len(finding.signals) == 9
        for signal in finding.signals:
            assert signal.reason.endswith(".") and len(signal.reason) > 20


class TestDemoPhones:
    def test_messy_phone_findings(self, messy_snapshot):
        report = analyze(messy_snapshot, build_context())
        summary = [(f.app.package, f.level.value, f.score) for f in report.findings]
        assert summary == [
            ("com.fastphone.supercleaner.pro", "high", 15),
            ("com.virusshield.antivirus.free", "high", 12),
            ("com.instagram.android", "high", 10),
            ("com.fastcharge.batterysaver.cooler", "medium", 4),
            ("com.freegames.puzzle.colorblast", "medium", 3),
        ]
        assert report.scanned == 13

    def test_messy_phone_does_not_flag_normal_apps(self, messy_snapshot):
        flagged = {f.app.package for f in analyze(messy_snapshot, build_context()).findings}
        assert flagged.isdisjoint({"com.spotify.music", "com.demo.notes.simple", "com.demo.bank.mobile", "com.whatsapp"})

    def test_trust_list_is_what_protects_whatsapp(self, messy_snapshot):
        no_trust = replace(build_context(), trusted=frozenset())
        flagged = {f.app.package: f for f in analyze(messy_snapshot, no_trust).findings}
        assert flagged["com.whatsapp"].level is Level.MEDIUM

    def test_lookalike_instagram_is_flagged_despite_the_trust_list(self, messy_snapshot):
        report = analyze(messy_snapshot, build_context())
        lookalike = next(f for f in report.findings if f.app.package == "com.instagram.android")
        assert "not_from_store" in rule_names(lookalike)

    def test_antivirus_explains_why_removal_will_fail(self, messy_snapshot):
        report = analyze(messy_snapshot, build_context())
        antivirus = next(f for f in report.findings if f.app.package == "com.virusshield.antivirus.free")
        assert antivirus.removal_note and "device administrator" in antivirus.removal_note

    def test_clean_phone_has_nothing(self, clean_snapshot):
        report = analyze(clean_snapshot, build_context())
        assert report.findings == () and report.device_notes == () and report.scanned == 8

    def test_judged_by_the_phones_clock(self, messy_snapshot):
        # Same phone, host clock far in the future: install dates must still be judged against the phone's own date.
        report = analyze(messy_snapshot, build_context(now=datetime(2030, 1, 1)))
        assert report.findings[0].app.package == "com.fastphone.supercleaner.pro"
        assert "recently_installed" in rule_names(report.findings[0])

    def test_at_level_filters(self, messy_snapshot):
        report = analyze(messy_snapshot, build_context())
        assert len(report.at_level(Level.HIGH)) == 3
        assert len(report.at_level(Level.MEDIUM)) == 5


class TestDeviceNotes:
    def test_full_storage(self):
        notes = device_notes(DeviceInfo(storage_used_pct=93, storage_free_gb=7.7))
        assert len(notes) == 1 and "93% full" in notes[0] and "7.7 GB" in notes[0]

    def test_storage_threshold(self):
        assert device_notes(DeviceInfo(storage_used_pct=89)) == ()
        assert device_notes(DeviceInfo(storage_used_pct=90)) != ()

    def test_battery_health_codes(self):
        assert device_notes(DeviceInfo(battery_health=2)) == ()
        assert "overheating" in device_notes(DeviceInfo(battery_health=3))[0]
        assert "dead" in device_notes(DeviceInfo(battery_health=4))[0]

    def test_warm_battery(self):
        assert device_notes(DeviceInfo(battery_temp_c=44.9)) == ()
        assert "46.0 C" in device_notes(DeviceInfo(battery_temp_c=46.0))[0]

    def test_old_android(self):
        notes = device_notes(DeviceInfo(sdk=30, android_release="11"))
        assert "Android 11" in notes[0] and "may no longer" in notes[0]
        assert device_notes(DeviceInfo(sdk=31)) == ()

    def test_unknown_readings_produce_no_notes(self):
        assert device_notes(DeviceInfo()) == ()


class TestLists:
    def test_extra_lists_are_merged_with_the_bundled_ones(self):
        context = build_context(extra_junk=["com.new.junk"], extra_trusted=["com.my.app"])
        assert "com.new.junk" in context.junk
        assert "com.my.app" in context.trusted and "com.whatsapp" in context.trusted

    def test_bundled_lists_parse(self):
        context = build_context()
        assert context.trusted and "com.whatsapp" in context.trusted
        assert context.junk == frozenset()  # ships empty on purpose

    def test_snapshot_without_apps(self):
        report = analyze(Snapshot(device=DeviceInfo()), build_context())
        assert report.scanned == 0 and report.findings == ()
