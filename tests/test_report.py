import json
from dataclasses import replace
from datetime import datetime

from phonecheck.models import AppInfo, DeviceInfo, Finding, Level, Report, Signal
from phonecheck.report import (
    NOTHING_FOUND,
    format_finding,
    render_html,
    render_json,
    render_text,
    to_dict,
)
from phonecheck.rules import analyze, build_context


def messy_report(messy_snapshot):
    return analyze(messy_snapshot, build_context())


def clean_report(clean_snapshot):
    return analyze(clean_snapshot, build_context())


class TestText:
    def test_messy_phone_report(self, messy_snapshot):
        text = render_text(messy_report(messy_snapshot))
        assert "Phone checkup: DemoCorp Demo A1 (Android 13)" in text
        assert "battery 38%, storage 93% full" in text
        assert "Checked 13 user-installed apps" in text
        assert "LIKELY JUNK (3)" in text and "WORTH A LOOK (2)" in text
        assert "com.fastphone.supercleaner.pro" in text
        assert "ABOUT THE PHONE" in text and "93% full" in text
        assert "turn USB debugging off" in text

    def test_numbering_runs_across_both_groups(self, messy_snapshot):
        text = render_text(messy_report(messy_snapshot))
        for number in range(1, 6):
            assert f"\n {number}. " in text

    def test_removal_note_is_shown(self, messy_snapshot):
        assert "device administrator" in render_text(messy_report(messy_snapshot))

    def test_clean_phone_says_so_without_overclaiming(self, clean_snapshot):
        text = " ".join(render_text(clean_report(clean_snapshot)).split())  # ignore line wrapping
        assert "Nothing suspicious found" in text
        assert "not proof the phone is clean" in text
        assert "LIKELY JUNK" not in text

    def test_lines_stay_narrow(self, messy_snapshot):
        for line in render_text(messy_report(messy_snapshot)).splitlines():
            assert len(line) <= 100, line

    def test_format_finding_shape(self, messy_snapshot):
        finding = messy_report(messy_snapshot).findings[0]
        lines = format_finding(finding, 1)
        assert lines[0].startswith(" 1. com.fastphone.supercleaner.pro")
        assert "score 15" in lines[0]
        assert "version 4.2.1" in lines[1] and "installed 2026-10-04" in lines[1]


class TestJson:
    def test_is_valid_json_with_expected_shape(self, messy_snapshot):
        data = json.loads(render_json(messy_report(messy_snapshot)))
        assert data["tool"] == "phonecheck"
        assert data["scanned_apps"] == 13
        assert [f["level"] for f in data["findings"]] == ["high", "high", "high", "medium", "medium"]
        top = data["findings"][0]
        assert top["package"] == "com.fastphone.supercleaner.pro"
        assert top["installer"] is None and top["installed"] == "2026-10-04"
        assert {s["rule"] for s in top["signals"]} >= {"accessibility_service", "overlay", "junk_name"}
        assert data["device"]["model"] == "Demo A1"
        assert data["device_notes"]

    def test_contains_no_identifiers_of_the_phone_or_owner(self, messy_snapshot):
        text = render_json(messy_report(messy_snapshot)).lower()
        for forbidden in ("serial", "imei", "email", "phone_number", "account"):
            assert forbidden not in text

    def test_clean_phone(self, clean_snapshot):
        data = to_dict(clean_report(clean_snapshot))
        assert data["findings"] == [] and data["device_notes"] == []


class TestHtml:
    def test_is_a_standalone_page(self, messy_snapshot):
        page = render_html(messy_report(messy_snapshot))
        assert page.startswith("<!doctype html>")
        assert "<script" not in page.lower()
        assert "http://" not in page and "https://" not in page  # no external requests
        assert "3 apps very likely to be junk" in page
        assert "com.fastphone.supercleaner.pro" in page

    def test_clean_banner(self, clean_snapshot):
        page = render_html(clean_report(clean_snapshot))
        assert 'class="banner ok"' in page and "Nothing suspicious found" in page
        assert NOTHING_FOUND.split(".")[0] in page

    def test_singular_wording(self):
        app = AppInfo(package="com.a.b", installer=None)
        finding = Finding(app, 8, Level.HIGH, (Signal("known_junk", 8, "Known junk."),))
        page = render_html(Report(DeviceInfo(), 1, (finding,), ()))
        assert "1 app very likely to be junk" in page

    def test_every_phone_supplied_string_is_escaped(self):
        evil = "<script>alert(1)</script>"
        app = AppInfo(
            package="com.evil.app",
            installer='"><img src=x onerror=alert(1)>',
            version_name=evil,
            first_install=datetime(2026, 1, 1),
        )
        finding = Finding(app, 9, Level.HIGH, (Signal("x", 9, f"reason {evil}"),), removal_note=evil)
        device = DeviceInfo(manufacturer=evil, model=evil, android_release=evil)
        page = render_html(Report(device, 1, (finding,), (evil,)))
        assert "<script>" not in page
        assert "<img" not in page
        assert "&lt;script&gt;" in page

    def test_text_report_does_not_choke_on_odd_strings(self):
        app = AppInfo(package="com.evil.app", version_name="\x1b[31mred\x1b[0m")
        finding = Finding(app, 9, Level.HIGH, (Signal("x", 9, "Reason."),))
        assert "com.evil.app" in render_text(Report(DeviceInfo(), 1, (finding,), ()))


def test_report_with_unknown_device_facts_still_renders():
    report = Report(DeviceInfo(), 0, (), ())
    assert "Checked 0 user-installed apps" in render_text(report)
    assert "0 apps checked" in render_html(report)
    assert replace(report, scanned=2).scanned == 2
