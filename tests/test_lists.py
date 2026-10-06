import pytest

from phonecheck.lists import load_bundled, load_file, parse_package_lines


def test_comments_blank_lines_and_trailing_comments():
    text = "# header\n\ncom.a.one   # first\n  com.b.two\n#com.c.three\n"
    assert parse_package_lines(text) == {"com.a.one", "com.b.two"}


def test_duplicates_collapse():
    assert parse_package_lines("com.a.one\ncom.a.one\n") == {"com.a.one"}


def test_a_bad_line_is_reported_with_its_line_number():
    with pytest.raises(ValueError, match=r"my list, line 2: not a valid package name"):
        parse_package_lines("com.ok.app\nnot a package\n", source="my list")


def test_injection_attempts_are_rejected():
    with pytest.raises(ValueError):
        parse_package_lines("com.ok.app;reboot\n")


def test_load_file(tmp_path):
    path = tmp_path / "junk.txt"
    path.write_text("com.x.y # note\n", encoding="utf-8")
    assert load_file(path) == {"com.x.y"}


def test_load_file_missing(tmp_path):
    with pytest.raises(ValueError, match="Could not read"):
        load_file(tmp_path / "nope.txt")


def test_bundled_lists_are_valid():
    assert len(load_bundled("trusted_apps.txt")) >= 15
    assert load_bundled("known_junk.txt") == frozenset()
