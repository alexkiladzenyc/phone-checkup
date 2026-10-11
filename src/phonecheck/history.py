"""A local log of past scans, so a shop can see which junk apps keep turning up.

Stored in SQLite (standard library) at a per-user path, or wherever --db or
PHONECHECK_DB points.

Privacy by omission, same as the rest of the tool: a saved scan holds the
phone's make, model and Android version, how many apps were checked, and the
*flagged* apps with their scores and the rules that fired. It never holds the
full app list, a serial number, or anything about the owner.

Schema changes go through MIGRATIONS, applied in order and tracked with
SQLite's `PRAGMA user_version`. A database written by a newer phonecheck is
refused rather than guessed at.
"""

from __future__ import annotations

import csv
import os
import sqlite3
import sys
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import TextIO

from .models import Report

ENV_VAR = "PHONECHECK_DB"

MIGRATIONS: tuple[str, ...] = (
    # 1: scans, the apps each one flagged, and the rules behind each flag.
    """
    CREATE TABLE scans (
        id           INTEGER PRIMARY KEY,
        scanned_at   TEXT NOT NULL,     -- the phone's clock when it reported one, else ours
        recorded_at  TEXT NOT NULL,
        manufacturer TEXT NOT NULL,
        model        TEXT NOT NULL,
        android      TEXT NOT NULL,
        apps_checked INTEGER NOT NULL CHECK (apps_checked >= 0)
    );
    CREATE TABLE findings (
        scan_id   INTEGER NOT NULL REFERENCES scans (id) ON DELETE CASCADE,
        package   TEXT NOT NULL,
        level     TEXT NOT NULL CHECK (level IN ('high', 'medium')),
        score     INTEGER NOT NULL,
        installer TEXT,
        PRIMARY KEY (scan_id, package)
    );
    CREATE TABLE signals (
        scan_id INTEGER NOT NULL,
        package TEXT NOT NULL,
        rule    TEXT NOT NULL,
        points  INTEGER NOT NULL,
        PRIMARY KEY (scan_id, package, rule),
        FOREIGN KEY (scan_id, package) REFERENCES findings (scan_id, package) ON DELETE CASCADE
    );
    CREATE INDEX findings_by_package ON findings (package);
    CREATE INDEX scans_by_time ON scans (scanned_at);
    """,
)
SCHEMA_VERSION = len(MIGRATIONS)


class HistoryError(Exception):
    """The history database can't be used; the message says why and what to do."""


def default_path() -> Path:
    """$PHONECHECK_DB, else the platform's per-user data folder."""
    if os.environ.get(ENV_VAR):
        return Path(os.environ[ENV_VAR])
    if sys.platform == "win32":
        base = Path(os.environ.get("LOCALAPPDATA") or Path.home() / "AppData" / "Local")
    elif sys.platform == "darwin":
        base = Path.home() / "Library" / "Application Support"
    else:
        base = Path(os.environ.get("XDG_DATA_HOME") or Path.home() / ".local" / "share")
    return base / "phonecheck" / "history.db"


# --------------------------------------------------------------------------
# rows handed back to callers
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class ScanSummary:
    id: int
    scanned_at: datetime
    phone: str
    android: str
    apps_checked: int
    high: int
    medium: int


@dataclass(frozen=True)
class PackageStat:
    package: str
    scans: int           # how many saved scans flagged it
    high: int            # ...of which at "likely junk"
    average_score: float
    last_seen: datetime


@dataclass(frozen=True)
class RuleStat:
    rule: str
    findings: int        # how many flagged apps this rule contributed to
    share: float         # ...as a fraction of all flagged apps


# --------------------------------------------------------------------------
# the store
# --------------------------------------------------------------------------


class History:
    """One open history database. Use as a context manager, or call close()."""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self._db = sqlite3.connect(self.path, timeout=10)
        except (OSError, sqlite3.Error) as exc:
            raise HistoryError(f"Could not open the history database at {self.path}: {exc}") from exc
        self._db.row_factory = sqlite3.Row
        self._db.execute("PRAGMA foreign_keys = ON")
        try:
            self._migrate()
        except Exception:
            self._db.close()
            raise

    def __enter__(self) -> History:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def close(self) -> None:
        self._db.close()

    @property
    def schema_version(self) -> int:
        version: int = self._db.execute("PRAGMA user_version").fetchone()[0]
        return version

    def _migrate(self) -> None:
        try:
            current = self.schema_version
        except sqlite3.DatabaseError as exc:
            raise HistoryError(f"{self.path} is not a phonecheck history database ({exc}).") from exc
        if current > SCHEMA_VERSION:
            raise HistoryError(
                f"{self.path} was written by a newer phonecheck (schema {current}, this version knows {SCHEMA_VERSION}). "
                "Upgrade phonecheck, or point --db at another file."
            )
        for version in range(current + 1, SCHEMA_VERSION + 1):
            # executescript() commits first, so wrap each step in an explicit transaction:
            # a migration either applies completely, version bump included, or not at all.
            script = f"BEGIN;\n{MIGRATIONS[version - 1]}\nPRAGMA user_version = {version};\nCOMMIT;"
            try:
                self._db.executescript(script)
            except sqlite3.Error as exc:
                if self._db.in_transaction:
                    self._db.execute("ROLLBACK")
                raise HistoryError(f"Could not upgrade {self.path} to schema {version}: {exc}") from exc

    @contextmanager
    def _transaction(self) -> Iterator[sqlite3.Connection]:
        with self._db:  # commits on success, rolls back on any exception
            yield self._db

    # ---- writing ---------------------------------------------------------

    def record(self, report: Report, *, now: datetime | None = None) -> int:
        """Save one scan; returns its id."""
        recorded = now or datetime.now()
        device = report.device
        with self._transaction() as db:
            cursor = db.execute(
                "INSERT INTO scans (scanned_at, recorded_at, manufacturer, model, android, apps_checked) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (
                    (device.taken_at or recorded).isoformat(timespec="seconds"),
                    recorded.isoformat(timespec="seconds"),
                    device.manufacturer,
                    device.model,
                    device.android_release,
                    report.scanned,
                ),
            )
            scan_id = cursor.lastrowid
            if scan_id is None:  # pragma: no cover - sqlite always sets it after an INSERT
                raise HistoryError("The database did not return an id for the saved scan.")
            db.executemany(
                "INSERT INTO findings (scan_id, package, level, score, installer) VALUES (?, ?, ?, ?, ?)",
                [(scan_id, f.app.package, f.level.value, f.score, f.app.installer) for f in report.findings],
            )
            db.executemany(
                "INSERT INTO signals (scan_id, package, rule, points) VALUES (?, ?, ?, ?)",
                [(scan_id, f.app.package, s.rule, s.points) for f in report.findings for s in f.signals],
            )
        return scan_id

    # ---- reading ---------------------------------------------------------

    def scan_count(self) -> int:
        count: int = self._db.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
        return count

    def recent(self, limit: int = 20) -> list[ScanSummary]:
        rows = self._db.execute(
            """
            SELECT s.id, s.scanned_at, s.manufacturer, s.model, s.android, s.apps_checked,
                   COUNT(f.package) FILTER (WHERE f.level = 'high')   AS high,
                   COUNT(f.package) FILTER (WHERE f.level = 'medium') AS medium
            FROM scans AS s
            LEFT JOIN findings AS f ON f.scan_id = s.id
            GROUP BY s.id
            ORDER BY s.scanned_at DESC, s.id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
        return [
            ScanSummary(
                id=row["id"],
                scanned_at=datetime.fromisoformat(row["scanned_at"]),
                phone=f"{row['manufacturer']} {row['model']}".strip(),
                android=row["android"],
                apps_checked=row["apps_checked"],
                high=row["high"],
                medium=row["medium"],
            )
            for row in rows
        ]

    def top_packages(self, limit: int = 10, since: datetime | None = None) -> list[PackageStat]:
        """The apps flagged in the most saved scans, most frequent first."""
        rows = self._db.execute(
            """
            SELECT f.package,
                   COUNT(*)                                AS scans,
                   COUNT(*) FILTER (WHERE f.level = 'high') AS high,
                   AVG(f.score)                            AS average_score,
                   MAX(s.scanned_at)                       AS last_seen
            FROM findings AS f
            JOIN scans AS s ON s.id = f.scan_id
            WHERE s.scanned_at >= ?
            GROUP BY f.package
            ORDER BY scans DESC, high DESC, average_score DESC, f.package
            LIMIT ?
            """,
            (_since(since), limit),
        ).fetchall()
        return [
            PackageStat(
                package=row["package"],
                scans=row["scans"],
                high=row["high"],
                average_score=round(row["average_score"], 1),
                last_seen=datetime.fromisoformat(row["last_seen"]),
            )
            for row in rows
        ]

    def rule_frequency(self, since: datetime | None = None) -> list[RuleStat]:
        """How often each rule contributed to a flag: shows which signals do the work."""
        rows = self._db.execute(
            """
            WITH flagged AS (
                SELECT f.scan_id, f.package
                FROM findings AS f JOIN scans AS s ON s.id = f.scan_id
                WHERE s.scanned_at >= ?
            )
            SELECT g.rule, COUNT(*) AS findings, (SELECT COUNT(*) FROM flagged) AS total
            FROM signals AS g
            JOIN flagged USING (scan_id, package)
            GROUP BY g.rule
            ORDER BY findings DESC, g.rule
            """,
            (_since(since),),
        ).fetchall()
        return [RuleStat(row["rule"], row["findings"], row["findings"] / row["total"]) for row in rows]

    def export_csv(self, out: TextIO, since: datetime | None = None) -> int:
        """One row per flagged app per scan; returns the number of rows written."""
        rows = self._db.execute(
            """
            SELECT s.id AS scan_id, s.scanned_at, s.manufacturer, s.model, s.android,
                   f.package, f.level, f.score, COALESCE(f.installer, '') AS installer,
                   (SELECT GROUP_CONCAT(rule, ';')
                    FROM (SELECT rule FROM signals AS g
                          WHERE g.scan_id = f.scan_id AND g.package = f.package
                          ORDER BY g.points DESC, g.rule)) AS rules
            FROM findings AS f
            JOIN scans AS s ON s.id = f.scan_id
            WHERE s.scanned_at >= ?
            ORDER BY s.scanned_at, s.id, f.score DESC, f.package
            """,
            (_since(since),),
        ).fetchall()
        columns = ["scan_id", "scanned_at", "manufacturer", "model", "android", "package", "level", "score", "installer", "rules"]
        writer = csv.writer(out, lineterminator="\n")
        writer.writerow(columns)
        for row in rows:
            writer.writerow([_csv_safe(row[column]) for column in columns])
        return len(rows)


def _since(when: datetime | None) -> str:
    # ISO-8601 strings sort chronologically, so a plain string comparison works in SQL.
    return when.isoformat(timespec="seconds") if when else ""


def _csv_safe(value: object) -> object:
    """Stop a spreadsheet treating a cell as a formula (CSV injection).

    Model names and installers are text a phone reported, so a hostile value
    like `=HYPERLINK(...)` must open as text, not run.
    """
    if isinstance(value, str) and value[:1] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + value
    return value


def open_history(path: str | Path | None = None) -> History:
    return History(path or default_path())
