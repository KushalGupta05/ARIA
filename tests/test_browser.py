"""Exercise the built console against a real, temporary SQLite database."""
import os
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from urllib.error import URLError
from urllib.request import urlopen

from playwright.sync_api import expect, sync_playwright

ROOT = Path(__file__).resolve().parents[1]


class AnalystWorkflowTest(unittest.TestCase):
    def test_review_and_close_case(self):
        folder = self.enterContext(tempfile.TemporaryDirectory())
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        base = f"http://127.0.0.1:{port}"
        process = subprocess.Popen([sys.executable, str(ROOT / "ML_Model" / "demo.py"),
                                    "--state-dir", folder, "--port", str(port)])
        try:
            for _ in range(100):
                if process.poll() is not None:
                    self.fail(f"Demo stopped during startup (exit {process.returncode})")
                try:
                    with urlopen(base + "/api/health", timeout=1):
                        break
                except (URLError, TimeoutError):
                    time.sleep(0.1)
            else:
                self.fail("Demo did not become ready")
            with sync_playwright() as playwright:
                browser = playwright.chromium.launch(executable_path=os.getenv("ARIA_TEST_CHROME") or None)
                page = browser.new_page(viewport={"width": 1440, "height": 900}, color_scheme="dark")
                errors = []
                page.on("pageerror", lambda error: errors.append(str(error)))
                page.goto(base)
                page.get_by_role("button", name="Open analyst console").click()
                expect(page.get_by_role("button", name="Active Alerts (3)")).to_be_visible()
                page.get_by_role("button", name="Alerts", exact=True).click()
                title = "Build worker thread spike during a release job"
                expect(page.get_by_role("heading", name=title)).to_be_visible()
                expect(page).to_have_url(base + "/triage/ARIA-4")
                page.evaluate("document.fonts.ready")
                if screenshot := os.getenv("ARIA_TEST_SCREENSHOT"):
                    page.screenshot(path=screenshot, animations="disabled")
                page.get_by_role("button", name="View Raw Telemetry JSON").click()
                expect(page.locator("pre")).to_contain_text("LAB-BUILD-07")
                page.get_by_role("button", name="Resolve Alert", exact=True).click()
                page.locator(".modal-content select").select_option("Benign")
                page.get_by_placeholder("1-line justification for audit trail").fill("Approved release window")
                page.get_by_role("button", name="Confirm Resolution").click()
                expect(page.get_by_text("Approved release window", exact=False).first).to_be_visible()
                page.reload()
                expect(page.get_by_text("Approved release window", exact=False).first).to_be_visible()
                page.get_by_role("button", name="Analytics", exact=True).click()
                expect(page.get_by_role("heading", name="Security Operations Analytics")).to_be_visible()
                self.assertEqual(errors, [])
                browser.close()
        finally:
            process.terminate()
            process.wait(timeout=10)


if __name__ == "__main__":
    unittest.main()
