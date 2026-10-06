"""Package-name lists (known junk, trusted apps): bundled defaults plus user files."""

from __future__ import annotations

from importlib import resources
from pathlib import Path

from .parsers import is_valid_package


def parse_package_lines(text: str, source: str = "list") -> frozenset[str]:
    """One package per line; `#` starts a comment. A bad line is an error, not silently ignored."""
    packages: set[str] = set()
    for number, raw in enumerate(text.splitlines(), start=1):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        if not is_valid_package(line):
            raise ValueError(f"{source}, line {number}: not a valid package name: {line!r}")
        packages.add(line)
    return frozenset(packages)


def load_bundled(name: str) -> frozenset[str]:
    text = (resources.files("phonecheck") / "data" / name).read_text(encoding="utf-8")
    return parse_package_lines(text, source=name)


def load_file(path: str | Path) -> frozenset[str]:
    path = Path(path)
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ValueError(f"Could not read {path}: {exc}") from exc
    return parse_package_lines(text, source=str(path))
