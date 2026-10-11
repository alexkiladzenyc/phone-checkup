"""End-to-end checks in a real headless browser.

Skipped automatically when Playwright or its browser isn't installed
(pip install playwright && playwright install chromium).
"""

import shutil
import threading

import pytest

pytest.importorskip("playwright.sync_api")
from playwright.sync_api import Error as PlaywrightError
from playwright.sync_api import sync_playwright

from phonecheck.rules import build_context
from phonecheck.server import make_server
from phonecheck.source import DeviceSource


@pytest.fixture(scope="module")
def browser():
    with sync_playwright() as playwright:
        try:
            instance = playwright.chromium.launch()
        except PlaywrightError as exc:
            pytest.skip(f"no usable browser: {str(exc).splitlines()[0]}")
        yield instance
        instance.close()


def serve(source):
    httpd, _state = make_server(source, build_context(), port=0)
    thread = threading.Thread(target=lambda: httpd.serve_forever(poll_interval=0.01), daemon=True)
    thread.start()
    return httpd, thread, f"http://127.0.0.1:{httpd.server_address[1]}/"


@pytest.fixture
def messy_page(browser):
    httpd, thread, url = serve(DeviceSource(demo="messy"))
    page = browser.new_page()
    errors = []
    page.on("pageerror", lambda exc: errors.append(str(exc)))
    page.goto(url)
    page.errors = errors
    yield page
    page.close()
    httpd.shutdown()
    httpd.server_close()
    thread.join(timeout=5)


def scan(page):
    page.click("#scan")
    page.wait_for_selector("#findings .card")


def test_page_loads_and_names_the_phone_source(messy_page):
    messy_page.wait_for_function("document.getElementById('source').textContent.includes('demo phone')")
    assert messy_page.is_visible("#simulated")
    assert messy_page.is_disabled("#remove") or not messy_page.is_visible("#removebar")


def test_scan_shows_findings_grouped_by_level(messy_page):
    scan(messy_page)
    assert messy_page.inner_text(".banner") == "4 apps very likely to be junk"
    assert messy_page.locator("#findings .card").count() == 6
    assert messy_page.locator("#findings h2").all_inner_texts() == ["Likely junk", "Worth a look"]
    assert "93% full" in messy_page.inner_text("#notes")
    assert messy_page.errors == []


def test_nothing_is_preselected(messy_page):
    scan(messy_page)
    assert messy_page.locator("#findings input:checked").count() == 0
    assert messy_page.is_disabled("#remove")
    assert messy_page.inner_text("#selected-count") == "Nothing selected"


def test_selecting_enables_removal_and_counts(messy_page):
    scan(messy_page)
    messy_page.check("input[value='com.freegames.puzzle.colorblast']")
    assert messy_page.is_enabled("#remove")
    assert messy_page.inner_text("#selected-count") == "1 app selected"
    messy_page.check("input[value='com.fastphone.supercleaner.pro']")
    assert messy_page.inner_text("#selected-count") == "2 apps selected"


def test_declining_the_confirmation_removes_nothing(messy_page):
    scan(messy_page)
    messy_page.once("dialog", lambda dialog: dialog.dismiss())
    messy_page.check("input[value='com.fastphone.supercleaner.pro']")
    messy_page.click("#remove")
    messy_page.wait_for_timeout(200)
    assert messy_page.locator("#findings .card").count() == 6
    assert messy_page.is_hidden("#results")


def test_confirmed_removal_updates_the_page(messy_page):
    scan(messy_page)
    seen = []

    def accept(dialog):
        seen.append(dialog.message)
        dialog.accept()

    messy_page.once("dialog", accept)
    messy_page.check("input[value='com.fastphone.supercleaner.pro']")
    messy_page.click("#remove")
    messy_page.wait_for_selector("#results li")
    assert "com.fastphone.supercleaner.pro" in seen[0] and "Remove 1 app" in seen[0]
    assert messy_page.inner_text("#results li") == "Removed com.fastphone.supercleaner.pro"
    assert messy_page.inner_text(".banner") == "3 apps very likely to be junk"
    assert messy_page.locator("#findings .card").count() == 5
    assert messy_page.locator("#findings input:checked").count() == 0


def test_device_admin_failure_explains_what_to_do(messy_page):
    scan(messy_page)
    messy_page.once("dialog", lambda dialog: dialog.accept())
    messy_page.check("input[value='com.virusshield.antivirus.free']")
    messy_page.click("#remove")
    messy_page.wait_for_selector("#results li.bad")
    assert "Could not remove com.virusshield.antivirus.free" in messy_page.inner_text("#results li.bad")
    assert "device administrator rights" in messy_page.inner_text("#results li.bad")
    assert messy_page.locator("#findings .card").count() == 6  # still there


def test_clean_phone_says_nothing_found(browser):
    httpd, thread, url = serve(DeviceSource(demo="clean"))
    try:
        page = browser.new_page()
        page.goto(url)
        page.click("#scan")
        page.wait_for_selector(".banner")
        assert page.inner_text(".banner") == "Nothing suspicious found"
        assert "not proof the phone is clean" in page.inner_text("#summary")
        assert page.is_hidden("#removebar")
        page.close()
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=5)


def test_hostile_text_from_a_phone_cannot_run_as_script(browser, tmp_path, demo_dir):
    """An app's version string is whatever its author typed; it must show as text, never execute."""
    evil = "<img src=x onerror=window.__pwned=1>"
    copy = tmp_path / "messy"
    shutil.copytree(demo_dir / "messy", copy)
    dump = copy / "dumpsys_package_com.fastphone.supercleaner.pro.txt"
    dump.write_text(dump.read_text().replace("versionName=4.2.1", f"versionName={evil}"), encoding="utf-8")

    httpd, thread, url = serve(DeviceSource(fixture=copy))
    try:
        page = browser.new_page()
        page.goto(url)
        page.click("#scan")
        page.wait_for_selector("#findings .card")
        page.wait_for_timeout(300)  # give a would-be onerror handler time to fire
        assert page.evaluate("window.__pwned") is None
        assert evil in page.inner_text("#findings")  # visible as plain text
        assert page.locator("#findings img").count() == 0
        page.close()
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=5)
