import csv
import io
import sqlite3
from dataclasses import replace
from datetime import datetime

import pytest

from phonecheck import history as history_module
from phonecheck.history import SCHEMA_VERSION, History, HistoryError, default_path
from phonecheck.models import AppInfo, DeviceInfo, Finding, Level, Report, Signal
from phonecheck.rules import analyze, build_context


@pytest.fixture
def store(tmp_path):
    with History(tmp_path / "h.db") as history:
        yield history


@pytest.fixture
def messy_report(messy_snapshot):
    return analyze(messy_snapshot, build_context())


@pytest.fixture
def clean_report(clean_snapshot):
    return analyze(clean_snapshot, build_context())


def finding(package, score, level=Level.HIGH, rules=("overlay",), installer=None):
    signals = tuple(Signal(rule, 1, f"Because of {rule}.") for rule in rules)
    return Finding(app=AppInfo(package=package, installer=installer), score=score, level=level, signals=signals)


def report_on(day, *findings, model="Demo A1"):
    device = DeviceInfo(manufacturer="DemoCorp", model=model, android_release="14", taken_at=datetime(2026, 10, day, 12, 0))
    return Report(device=device, scanned=20, findings=tuple(findings))


class TestSchema:
    def test_new_database_is_at_the_current_version(self, store):
        assert store.schema_version == SCHEMA_VERSION >= 1

    def test_reopening_does_not_reapply_migrations(self, tmp_path, messy_report):
        path = tmp_path / "h.db"
        with History(path) as first:
            first.record(messy_report)
        with History(path) as second:
            assert second.schema_version == SCHEMA_VERSION
            assert second.scan_count() == 1

    def test_creates_missing_folders(self, tmp_path):
        with History(tmp_path / "a" / "b" / "h.db") as history:
            assert history.scan_count() == 0

    def test_refuses_a_database_from_a_newer_version(self, tmp_path):
        path = tmp_path / "future.db"
        with sqlite3.connect(path) as db:
            db.execute(f"PRAGMA user_version = {SCHEMA_VERSION + 1}")
        with pytest.raises(HistoryError, match="newer phonecheck"):
            History(path)

    def test_refuses_a_file_that_is_not_a_database(self, tmp_path):
        path = tmp_path / "notes.db"
        path.write_bytes(b"these are my notes, not a database" * 100)
        with pytest.raises(HistoryError, match="not a phonecheck history database"):
            History(path)

    def test_a_failed_migration_leaves_the_database_untouched(self, tmp_path, monkeypatch):
        path = tmp_path / "h.db"
        broken = (*history_module.MIGRATIONS, "CREATE TABLE extra (x INTEGER); THIS IS NOT SQL;")
        monkeypatch.setattr(history_module, "MIGRATIONS", broken)
        monkeypatch.setattr(history_module, "SCHEMA_VERSION", len(broken))
        with pytest.raises(HistoryError, match="Could not upgrade"):
            History(path)
        with sqlite3.connect(path) as db:
            # migration 1 committed; migration 2 rolled back completely, version bump included
            assert db.execute("PRAGMA user_version").fetchone()[0] == len(broken) - 1
            tables = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
        assert "scans" in tables and "extra" not in tables


class TestDefaultPath:
    def test_environment_variable_wins(self, monkeypatch, tmp_path):
        monkeypatch.setenv("PHONECHECK_DB", str(tmp_path / "x.db"))
        assert default_path() == tmp_path / "x.db"

    def test_per_user_location(self, monkeypatch):
        monkeypatch.delenv("PHONECHECK_DB", raising=False)
        path = default_path()
        assert path.name == "history.db" and path.parent.name == "phonecheck"


class TestRecording:
    def test_records_only_flagged_apps(self, store, messy_report):
        scan_id = store.record(messy_report)
        rows = store._db.execute("SELECT package FROM findings WHERE scan_id = ?", (scan_id,)).fetchall()
        assert {row[0] for row in rows} == {f.app.package for f in messy_report.findings}
        assert len(rows) == 6 < messy_report.scanned  # the full app list is never stored

    def test_stores_nothing_identifying(self, store, messy_report):
        store.record(messy_report)
        columns = {row[1] for table in ("scans", "findings", "signals") for row in store._db.execute(f"PRAGMA table_info({table})")}
        assert not columns & {"serial", "imei", "phone_number", "owner", "account", "customer"}

    def test_clean_phone_is_recorded_with_no_findings(self, store, clean_report):
        store.record(clean_report)
        [scan] = store.recent()
        assert (scan.high, scan.medium, scan.apps_checked) == (0, 0, 8)

    def test_uses_the_phones_clock_when_there_is_one(self, store, messy_report):
        store.record(messy_report, now=datetime(2030, 1, 1))
        assert store.recent()[0].scanned_at == datetime(2026, 10, 6, 14, 5)

    def test_falls_back_to_our_clock(self, store, messy_report):
        no_clock = replace(messy_report, device=replace(messy_report.device, taken_at=None))
        store.record(no_clock, now=datetime(2026, 1, 2, 3, 4, 5))
        assert store.recent()[0].scanned_at == datetime(2026, 1, 2, 3, 4, 5)

    def test_a_failed_write_saves_nothing(self, store):
        duplicate = report_on(1, finding("com.a.b", 7), finding("com.a.b", 8))  # same package twice: primary key clash
        with pytest.raises(sqlite3.IntegrityError):
            store.record(duplicate)
        assert store.scan_count() == 0  # the scan row was rolled back with its findings

    def test_deleting_a_scan_cascades(self, store, messy_report):
        scan_id = store.record(messy_report)
        with store._db:
            store._db.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
        assert store._db.execute("SELECT COUNT(*) FROM signals").fetchone()[0] == 0


class TestQueries:
    @pytest.fixture
    def filled(self, store):
        store.record(report_on(1, finding("com.junk.cleaner", 9, rules=("overlay", "junk_name")), finding("com.other.app", 4, Level.MEDIUM)))
        store.record(report_on(3, finding("com.junk.cleaner", 11, rules=("overlay", "junk_name", "hidden_icon"))))
        store.record(report_on(5, finding("com.junk.cleaner", 4, Level.MEDIUM, rules=("junk_name",)), model="Demo B2"))
        store.record(report_on(7))
        return store

    def test_recent_is_newest_first_and_limited(self, filled):
        scans = filled.recent(limit=3)
        assert [s.scanned_at.day for s in scans] == [7, 5, 3]
        assert scans[1].phone == "DemoCorp Demo B2" and scans[1].medium == 1

    def test_top_packages(self, filled):
        top = filled.top_packages()
        assert [(s.package, s.scans, s.high) for s in top] == [("com.junk.cleaner", 3, 2), ("com.other.app", 1, 0)]
        assert top[0].average_score == 8.0
        assert top[0].last_seen == datetime(2026, 10, 5, 12, 0)

    def test_top_packages_since(self, filled):
        top = filled.top_packages(since=datetime(2026, 10, 2))
        assert [(s.package, s.scans) for s in top] == [("com.junk.cleaner", 2)]

    def test_rule_frequency(self, filled):
        stats = {r.rule: (r.findings, r.share) for r in filled.rule_frequency()}
        assert stats["junk_name"] == (3, 0.75)  # 3 of the 4 flagged apps
        assert stats["hidden_icon"] == (1, 0.25)

    def test_empty_history(self, store):
        assert store.recent() == [] and store.top_packages() == [] and store.rule_frequency() == []

    def test_csv_export(self, filled):
        out = io.StringIO()
        assert filled.export_csv(out) == 4
        rows = list(csv.DictReader(io.StringIO(out.getvalue())))
        assert rows[0]["package"] == "com.junk.cleaner" and rows[0]["rules"] == "junk_name;overlay"
        assert [r["scanned_at"][:10] for r in rows] == ["2026-10-01", "2026-10-01", "2026-10-03", "2026-10-05"]

    def test_csv_export_neutralises_formulas(self, store):
        # A phone reports its own model name: it must open in a spreadsheet as text, not run as a formula.
        store.record(report_on(1, finding("com.a.b", 7, installer="@SUM(1)"), model='=HYPERLINK("http://x","y")'))
        out = io.StringIO()
        store.export_csv(out)
        row = next(csv.DictReader(io.StringIO(out.getvalue())))
        assert row["model"].startswith("'=") and row["installer"] == "'@SUM(1)"
