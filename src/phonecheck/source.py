"""Where a Device comes from: a bundled demo phone, a recorded folder, or a real phone over adb."""

from __future__ import annotations

from pathlib import Path

from .adb import AdbDevice, AdbError, Device, FixtureDevice, list_devices

DEMO_NAMES = ("messy", "clean")
DEMO_ROOT = Path(__file__).resolve().parent / "demo_data"


class DeviceSource:
    """Hands out Devices. Demo and fixture phones are opened once so that a simulated
    removal is still visible on the next scan; real phones are opened fresh each time."""

    def __init__(
        self,
        *,
        demo: str | None = None,
        fixture: str | Path | None = None,
        serial: str | None = None,
        adb_path: str = "adb",
    ):
        if demo is not None and demo not in DEMO_NAMES:
            raise ValueError(f"unknown demo phone {demo!r}; choose from {', '.join(DEMO_NAMES)}")
        self.demo, self.fixture, self.serial, self.adb_path = demo, fixture, serial, adb_path
        self._offline: FixtureDevice | None = None

    @classmethod
    def from_args(cls, args) -> "DeviceSource":
        return cls(demo=args.demo, fixture=args.fixture, serial=args.serial, adb_path=args.adb)

    @property
    def is_real(self) -> bool:
        return self.demo is None and self.fixture is None

    @property
    def label(self) -> str:
        if self.demo:
            return f"demo phone ({self.demo})"
        if self.fixture:
            return f"recording {self.fixture}"
        return f"phone {self.serial}" if self.serial else "connected phone"

    def open(self) -> Device:
        if not self.is_real:
            if self._offline is None:
                self._offline = FixtureDevice(DEMO_ROOT / self.demo if self.demo else self.fixture)
            return self._offline
        return AdbDevice(serial=self.serial or self._only_connected_serial(), adb_path=self.adb_path)

    def _only_connected_serial(self) -> str:
        entries = list_devices(self.adb_path)
        ready = [e for e in entries if e.state == "device"]
        if len(ready) == 1:
            return ready[0].serial
        if not entries:
            raise AdbError("No phone found. Plug it in with a data cable and turn on USB debugging.")
        if not ready:
            states = ", ".join(f"{e.serial} is {e.state}" for e in entries)
            raise AdbError(f"No phone is ready ({states}). Unlock it and tap Allow on the USB debugging prompt.")
        names = ", ".join(e.serial for e in ready)
        raise AdbError(f"More than one phone is connected ({names}). Choose one with --serial.")
