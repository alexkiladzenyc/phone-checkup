import io
import json

import pytest

from phonecheck import cli
from phonecheck.cli import CliError, main, parse_selection


def run(argv, answers=(), tmp_cwd=None):
    """Run the CLI with scripted keyboard answers; returns (exit_code, stdout, stderr)."""
    out, err = io.StringIO(), io.StringIO()
    queue = list(answers)

    def fake_input(prompt=""):
        out.write(prompt)
        if not queue:
            raise EOFError
        return queue.pop(0)

    code = main(argv, input_fn=fake_input, stdout=out, stderr=err)
    return code, out.getvalue(), err.getvalue()


class TestScan:
    def test_text_report(self):
        code, out, err = run(["scan", "--demo", "messy"])
        assert code == 0 and err == ""
        assert "LIKELY JUNK (4)" in out and "com.fastphone.supercleaner.pro" in out

    def test_clean_phone(self):
        code, out, _ = run(["scan", "--demo", "clean"])
        assert code == 0 and "Nothing suspicious found" in " ".join(out.split())

    def test_json_format_is_valid(self):
        code, out, _ = run(["scan", "--demo", "messy", "--format", "json"])
        assert code == 0
        assert json.loads(out)["scanned_apps"] == 14

    def test_html_goes_to_a_file(self, tmp_path):
        target = tmp_path / "r.html"
        code, out, _ = run(["scan", "--demo", "messy", "--format", "html", "--out", str(target)])
        assert code == 0 and str(target) in out
        assert target.read_text(encoding="utf-8").startswith("<!doctype html>")

    def test_html_default_filename(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        code, _out, _ = run(["scan", "--demo", "clean", "--format", "html"])
        assert code == 0 and (tmp_path / cli.DEFAULT_HTML_NAME).exists()

    def test_fixture_directory(self, demo_dir):
        code, out, _ = run(["scan", "--fixture", str(demo_dir / "messy")])
        assert code == 0 and "com.instagram.android" in out

    def test_extra_junk_list_changes_the_result(self, tmp_path):
        junk = tmp_path / "junk.txt"
        junk.write_text("com.demo.notes.simple  # innocent app, but the user says it's junk\n")
        code, out, _ = run(["scan", "--demo", "clean", "--junk-list", str(junk)])
        assert code == 0 and "com.demo.notes.simple" in out and "LIKELY JUNK (1)" in out

    def test_extra_trusted_list_changes_the_result(self, tmp_path):
        trusted = tmp_path / "trusted.txt"
        trusted.write_text("com.fastcharge.batterysaver.cooler\n")
        _code, out, _ = run(["scan", "--demo", "messy", "--trusted-list", str(trusted)])
        assert "batterysaver" not in out

    def test_bad_list_file_is_a_clean_error(self, tmp_path):
        bad = tmp_path / "bad.txt"
        bad.write_text("this is not a package\n")
        code, _out, err = run(["scan", "--demo", "messy", "--junk-list", str(bad)])
        assert code == 1 and "error:" in err and "line 1" in err

    def test_unknown_fixture_is_a_clean_error(self, tmp_path):
        code, _, err = run(["scan", "--fixture", str(tmp_path / "missing")])
        assert code == 1 and "Could not read a fixture" in err


class TestRemove:
    def test_dry_run_removes_nothing(self):
        code, out, _ = run(["remove", "--demo", "messy", "--dry-run"])
        assert code == 0 and "Dry run: nothing was removed." in out
        assert "Remove which?" not in out  # never even asks

    def test_nothing_to_remove_on_a_clean_phone(self):
        code, out, _ = run(["remove", "--demo", "clean"])
        assert code == 0 and "Nothing to remove" in out

    def test_choose_and_confirm(self):
        code, out, _ = run(["remove", "--demo", "messy"], answers=["1", "remove"])
        assert code == 0
        assert "removed  com.fastphone.supercleaner.pro" in out
        assert "Rescanned: 3 apps still at 'high' or higher." in out

    def test_wrong_confirmation_cancels(self):
        code, out, _ = run(["remove", "--demo", "messy"], answers=["all", "yes"])
        assert code == 0 and "Cancelled. Nothing was removed." in out and "removed  " not in out

    def test_blank_answer_cancels(self):
        code, out, _ = run(["remove", "--demo", "messy"], answers=[""])
        assert code == 0 and "Cancelled" in out

    def test_end_of_input_cancels(self):
        code, out, _ = run(["remove", "--demo", "messy"], answers=[])
        assert code == 0 and "Cancelled" in out

    def test_end_of_input_at_confirmation_cancels(self):
        code, out, _ = run(["remove", "--demo", "messy"], answers=["1"])
        assert code == 0 and "Cancelled" in out and "removed  " not in out

    def test_device_admin_failure_sets_exit_code_and_shows_hint(self):
        code, out, _ = run(["remove", "--demo", "messy"], answers=["all", "remove"])
        assert code == 1
        assert "FAILED   com.virusshield.antivirus.free" in out
        assert "device administrator rights" in out
        assert "removed  com.fastphone.supercleaner.pro" in out  # the others still went through

    def test_min_level_medium_offers_more(self):
        _code, out, _ = run(["remove", "--demo", "messy", "--min-level", "medium", "--dry-run"])
        assert " 6. com.freegames.puzzle.colorblast" in out

    def test_bad_selection_is_a_clean_error_and_removes_nothing(self):
        code, out, err = run(["remove", "--demo", "messy"], answers=["9", "remove"])
        assert code == 1 and "no app numbered 9" in err.lower() and "removed  " not in out

    def test_typed_confirmation_is_case_insensitive(self):
        _code, out, _ = run(["remove", "--demo", "messy"], answers=["1", "REMOVE"])
        assert "removed  com.fastphone.supercleaner.pro" in out


class TestParseSelection:
    @pytest.mark.parametrize(
        "text,count,expected",
        [
            ("1", 5, [0]),
            ("1,3", 5, [0, 2]),
            ("1, 3", 5, [0, 2]),
            ("2-4", 5, [1, 2, 3]),
            ("1,1,2", 5, [0, 1]),
            ("ALL", 3, [0, 1, 2]),
            ("3,1", 5, [2, 0]),
            ("1,,", 5, [0]),  # a stray trailing comma is harmless
        ],
    )
    def test_valid(self, text, count, expected):
        assert parse_selection(text, count) == expected

    @pytest.mark.parametrize("text", ["0", "6", "x", "1-9", "-", "1;2", ","])
    def test_invalid(self, text):
        with pytest.raises(CliError):
            parse_selection(text, 5)


class TestCapture:
    def test_capture_then_replay_gives_the_same_report(self, tmp_path, demo_dir):
        target = tmp_path / "cap"
        code, out, _ = run(["capture", "--fixture", str(demo_dir / "messy"), "--out", str(target)])
        assert code == 0 and "Do not publish captures" in out
        _, original, _ = run(["scan", "--demo", "messy", "--format", "json"])
        _, replayed, _ = run(["scan", "--fixture", str(target), "--format", "json"])
        assert json.loads(original) == json.loads(replayed)

    def test_refuses_a_non_empty_folder(self, tmp_path, demo_dir):
        (tmp_path / "x.txt").write_text("hi")
        code, _, err = run(["capture", "--fixture", str(demo_dir / "messy"), "--out", str(tmp_path)])
        assert code == 1 and "not empty" in err


class TestDevices:
    def test_no_adb_gives_a_helpful_error(self):
        code, _, err = run(["devices", "--adb", "/definitely/not/adb"])
        assert code == 1 and "platform-tools" in err

    def test_scan_without_adb_gives_a_helpful_error(self):
        code, _, err = run(["scan", "--adb", "/definitely/not/adb"])
        assert code == 1 and "platform-tools" in err


class TestParserBasics:
    def test_a_command_is_required(self):
        with pytest.raises(SystemExit) as exc:
            main([], stderr=io.StringIO())
        assert exc.value.code == 2

    def test_demo_and_serial_conflict(self):
        with pytest.raises(SystemExit) as exc:
            main(["scan", "--demo", "messy", "--serial", "abc"], stderr=io.StringIO())
        assert exc.value.code == 2

    def test_version(self, capsys):
        with pytest.raises(SystemExit) as exc:
            main(["--version"])
        assert exc.value.code == 0
        assert "phonecheck" in capsys.readouterr().out

    def test_help_lists_every_command(self, capsys):
        with pytest.raises(SystemExit):
            main(["--help"])
        out = capsys.readouterr().out
        for command in ("devices", "scan", "remove", "capture", "serve", "diff", "history"):
            assert command in out

    def test_keyboard_interrupt_is_handled(self, monkeypatch):
        def interrupted(*args, **kwargs):
            raise KeyboardInterrupt

        monkeypatch.setattr(cli, "collect", interrupted)
        code, _, err = run(["scan", "--demo", "clean"])
        assert code == 130 and "cancelled" in err


class TestHistoryCommands:
    @pytest.fixture
    def db(self, tmp_path):
        return str(tmp_path / "h.db")

    def test_scan_is_not_saved_by_default(self, db):
        run(["scan", "--demo", "messy", "--db", db])
        _, out, _ = run(["history", "--db", db])
        assert "No saved scans yet" in out

    def test_save_keeps_json_output_clean(self, db):
        code, out, err = run(["scan", "--demo", "messy", "--format", "json", "--save", "--db", db])
        assert code == 0 and json.loads(out)["scanned_apps"] == 14
        assert "Saved to history as scan #1." in err

    def test_list_stats_and_export(self, db, tmp_path):
        run(["scan", "--demo", "messy", "--save", "--db", db])
        run(["scan", "--demo", "clean", "--save", "--db", db])

        code, out, _ = run(["history", "list", "--db", db])
        assert code == 0 and "DemoCorp Demo A1" in out and "DemoCorp Demo B2" in out

        code, out, _ = run(["history", "stats", "--db", db, "--top", "2"])
        assert code == 0 and "2 saved scans" in out
        assert "com.fastphone.supercleaner.pro" in out and "com.instagram.android" not in out  # --top 2
        assert "boot_start" in out

        target = tmp_path / "out.csv"
        code, out, _ = run(["history", "export", "--db", db, "--out", str(target)])
        assert code == 0 and "Wrote 6 rows" in out
        assert target.read_text(encoding="utf-8").startswith("scan_id,scanned_at,")

    def test_export_to_screen(self, db):
        run(["scan", "--demo", "messy", "--save", "--db", db])
        _, out, _ = run(["history", "export", "--db", db])
        assert len(out.strip().splitlines()) == 7  # header + 6 flagged apps

    def test_stats_since_and_empty(self, db):
        run(["scan", "--demo", "messy", "--save", "--db", db])
        _, out, _ = run(["history", "stats", "--db", db, "--since", "2027-01-01"])
        assert "No flagged apps in the saved scans since 2027-01-01." in out

    def test_bad_since_date(self, db):
        code, _, err = run(["history", "stats", "--db", db, "--since", "last tuesday"])
        assert code == 1 and "YYYY-MM-DD" in err

    def test_remove_can_save_the_scan_it_started_with(self, db):
        run(["remove", "--demo", "messy", "--save", "--db", db, "--dry-run"])
        _, out, _ = run(["history", "--db", db])
        assert "DemoCorp Demo A1" in out

    def test_unusable_database_is_a_clean_error(self, tmp_path):
        bad = tmp_path / "bad.db"
        bad.write_bytes(b"not sqlite" * 200)
        code, _, err = run(["history", "--db", str(bad)])
        assert code == 1 and err.startswith("error:") and "not a phonecheck history database" in err

    def test_environment_variable_picks_the_database(self, tmp_path, monkeypatch):
        monkeypatch.setenv("PHONECHECK_DB", str(tmp_path / "env.db"))
        run(["scan", "--demo", "clean", "--save"])
        assert (tmp_path / "env.db").exists()


class TestDiff:
    def save(self, tmp_path, name, demo):
        path = tmp_path / name
        run(["scan", "--demo", demo, "--format", "json", "--out", str(path)])
        return str(path)

    def test_same_report_twice(self, tmp_path):
        a = self.save(tmp_path, "a.json", "messy")
        code, out, _ = run(["diff", a, a, "--fail-on-new"])
        assert code == 0 and "No change" in out and "Unchanged: 6 flagged apps." in out

    def test_fail_on_new(self, tmp_path):
        clean, messy = self.save(tmp_path, "c.json", "clean"), self.save(tmp_path, "m.json", "messy")
        assert run(["diff", clean, messy])[0] == 0
        code, out, _ = run(["diff", clean, messy, "--fail-on-new"])
        assert code == 1 and "NEW SINCE LAST TIME (6)" in out
        assert run(["diff", messy, clean, "--fail-on-new"])[0] == 0  # only things going away

    def test_not_a_report(self, tmp_path):
        other = tmp_path / "other.json"
        other.write_text('{"hello": "world"}', encoding="utf-8")
        code, _, err = run(["diff", str(other), str(other)])
        assert code == 1 and "not a phonecheck JSON report" in err
