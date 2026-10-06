from pathlib import Path

import pytest

import phonecheck
from phonecheck.adb import FixtureDevice
from phonecheck.collector import collect

DEMO_DIR = Path(phonecheck.__file__).parent / "demo_data"


@pytest.fixture
def demo_dir() -> Path:
    return DEMO_DIR


@pytest.fixture
def messy_device() -> FixtureDevice:
    return FixtureDevice(DEMO_DIR / "messy")


@pytest.fixture
def clean_device() -> FixtureDevice:
    return FixtureDevice(DEMO_DIR / "clean")


@pytest.fixture
def messy_snapshot(messy_device):
    return collect(messy_device)


@pytest.fixture
def clean_snapshot(clean_device):
    return collect(clean_device)
