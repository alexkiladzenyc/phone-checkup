import json

import pytest

from phonecheck.compare import CompareError, compare, load_report, parse_report, render_comparison
from phonecheck.report import to_dict
from phonecheck.rules import analyze, build_context


def report(*findings, model="Demo A1", when="2026-10-06T14:05:00"):
    return {
        "tool": "phonecheck",
        "device": {"manufacturer": "DemoCorp", "model": model, "scanned_at": when},
        "findings": [
            {"package": p, "level": level, "score": score, "signals": [{"rule": r} for r in rules]}
            for p, level, score, rules in findings
        ],
    }


def diff(before, after):
    return compare(parse_report(before), parse_report(after))


class TestCompare:
    def test_identical_reports(self):
        same = report(("com.a.b", "high", 8, ["overlay"]))
        result = diff(same, same)
        assert not result.has_changes and result.unchanged == 1
        assert "No change" in render_comparison(result)

    def test_new_and_resolved(self):
        result = diff(
            report(("com.old.junk", "high", 9, ["overlay"])),
            report(("com.new.junk", "medium", 4, ["junk_name", "boot_start"])),
        )
        assert [f.package for f in result.new] == ["com.new.junk"]
        assert [f.package for f in result.resolved] == ["com.old.junk"]
        text = render_comparison(result)
        assert "+ com.new.junk   worth a look, score 4" in text
        assert "because: boot_start, junk_name" in text
        assert "- com.old.junk   was likely junk, score 9" in text

    def test_worse_names_the_new_signals(self):
        result = diff(
            report(("com.a.b", "medium", 4, ["junk_name", "boot_start"])),
            report(("com.a.b", "high", 7, ["junk_name", "boot_start", "hidden_icon"])),
        )
        [change] = result.worse
        assert change.new_rules == {"hidden_icon"}
        text = render_comparison(result)
        assert "^ com.a.b   score 4 -> 7  (worth a look -> likely junk)" in text
        assert "new signals: hidden_icon" in text

    def test_better_names_the_dropped_signals(self):
        result = diff(
            report(("com.a.b", "high", 8, ["overlay", "accessibility_service", "not_from_store"])),
            report(("com.a.b", "high", 6, ["accessibility_service", "not_from_store"])),
        )
        [change] = result.better
        assert change.dropped_rules == {"overlay"}
        assert "no longer: overlay" in render_comparison(result)

    def test_level_outranks_score(self):
        # Reports can come from phonecheck versions with different thresholds. The level is what a person
        # acts on, so it is compared before the score.
        result = diff(report(("com.a.b", "high", 6, [])), report(("com.a.b", "medium", 9, [])))
        assert len(result.better) == 1 and not result.worse

    def test_different_phones_are_called_out(self):
        result = diff(report(model="Demo A1"), report(model="Demo B2"))
        assert not result.same_phone
        assert "different phones" in render_comparison(result)

    def test_new_findings_sorted_most_severe_first(self):
        result = diff(
            report(),
            report(("com.m.m", "medium", 5, []), ("com.h.low", "high", 6, []), ("com.h.top", "high", 12, [])),
        )
        assert [f.package for f in result.new] == ["com.h.top", "com.h.low", "com.m.m"]


class TestDemoPhones:
    def test_removing_junk_shows_up_as_gone(self, messy_device, messy_snapshot):
        from phonecheck.collector import collect
        from phonecheck.removal import remove_packages

        before = to_dict(analyze(messy_snapshot, build_context()))
        remove_packages(messy_device, ["com.fastphone.supercleaner.pro", "com.sysupdate.service.helper"])
        after = to_dict(analyze(collect(messy_device), build_context()))
        result = compare(parse_report(before), parse_report(after))
        assert {f.package for f in result.resolved} == {"com.fastphone.supercleaner.pro", "com.sysupdate.service.helper"}
        assert not result.new and result.unchanged == 4


class TestValidation:
    @pytest.mark.parametrize(
        "data",
        [
            [],
            {"tool": "something-else"},
            {"tool": "phonecheck"},
            {"tool": "phonecheck", "device": {}, "findings": "nope"},
            {"tool": "phonecheck", "device": {}, "findings": [{"package": "com.a.b", "level": "extreme", "score": 1}]},
            {"tool": "phonecheck", "device": {}, "findings": [{"package": "com.a.b", "level": "high", "score": "9"}]},
            {"tool": "phonecheck", "device": {}, "findings": [{"package": "com.a.b", "level": "high", "score": True}]},
            {"tool": "phonecheck", "device": {}, "findings": [{"package": "com.a.b", "level": "high", "score": 9, "signals": 3}]},
            {"tool": "phonecheck", "device": {}, "findings": ["com.a.b"]},
        ],
    )
    def test_malformed_reports_are_clear_errors(self, data):
        with pytest.raises(CompareError):
            parse_report(data, "x.json")

    def test_odd_signal_entries_are_skipped(self):
        data = report(("com.a.b", "high", 9, ["overlay"]))
        data["findings"][0]["signals"].extend([{"rule": 5}, "text", {}])
        _, _, flags = parse_report(data)
        assert flags["com.a.b"].rules == {"overlay"}

    def test_missing_and_invalid_files(self, tmp_path):
        with pytest.raises(CompareError, match="Could not read"):
            load_report(tmp_path / "missing.json")
        bad = tmp_path / "bad.json"
        bad.write_text("{not json", encoding="utf-8")
        with pytest.raises(CompareError, match="not valid JSON"):
            load_report(bad)

    def test_round_trip_through_a_file(self, tmp_path, messy_snapshot):
        path = tmp_path / "r.json"
        path.write_text(json.dumps(to_dict(analyze(messy_snapshot, build_context()))), encoding="utf-8")
        phone, taken, flags = load_report(path)
        assert phone == "DemoCorp Demo A1" and taken == "2026-10-06T14:05:00" and len(flags) == 6
