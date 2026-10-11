#!/usr/bin/env python3
"""Regenerate docs/screenshot.png: the web page after scanning the demo phone.

Needs Playwright with Chromium (pip install playwright && playwright install chromium).
The screenshot only ever shows the synthetic demo phone.
"""

from __future__ import annotations

import sys
import threading
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from playwright.sync_api import sync_playwright

from phonecheck.rules import build_context
from phonecheck.server import make_server
from phonecheck.source import DeviceSource


def main(out: Path = ROOT / "docs" / "screenshot.png") -> None:
    out.parent.mkdir(parents=True, exist_ok=True)
    httpd, _ = make_server(DeviceSource(demo="messy"), build_context(), port=0)
    threading.Thread(target=lambda: httpd.serve_forever(poll_interval=0.01), daemon=True).start()
    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch()
            page = browser.new_page(viewport={"width": 820, "height": 2400}, color_scheme="light")
            page.goto(f"http://127.0.0.1:{httpd.server_address[1]}/")
            page.click("#scan")
            page.wait_for_selector("#findings .card")
            page.check("input[value='com.fastphone.supercleaner.pro']")
            page.screenshot(path=str(out), full_page=True)
            browser.close()
    finally:
        httpd.shutdown()
        httpd.server_close()
    print(f"wrote {out}")


if __name__ == "__main__":
    main()
