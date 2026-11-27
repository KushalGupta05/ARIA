import sqlite3
import sys
import tempfile
import unittest
from contextlib import closing
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "ML_Model"))
import frontend_api
from demo import seed_demo
from frontend_db_setup import init_db


class ConsoleApiTests(unittest.TestCase):
    def setUp(self):
        folder = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.db = folder / "console.db"
        paths = dict(DB_PATH=self.db, QUEUE_DB_PATH=folder / "queue.db",
                     CONFIG_PATH=folder / "settings.json", MITRE_JSON_PATH=ROOT / "examples" / "techniques.json",
                     _CACHED_MITRE_DATA=None, init_db=lambda: init_db(self.db))
        self.enterContext(patch.multiple(frontend_api, **paths))
        self.client = self.enterContext(TestClient(frontend_api.app))

    def test_clean_start_and_repeat_seeding(self):
        self.assertEqual(self.client.get("/api/health").json()["alert_count"], 0)
        self.assertEqual(seed_demo(self.db), 4)
        self.assertEqual(seed_demo(self.db), 0)
        rows = self.client.get("/api/alerts").json()
        self.assertEqual(len(rows), 4)
        self.assertTrue(all(row["rag_analysis"]["demo"] for row in rows))
        self.assertTrue(all(row["feature_snapshot"] for row in rows))

    def test_resolution_survives_restart_and_updates_analytics(self):
        seed_demo(self.db)
        case = self.client.get("/api/alerts").json()[0]["id"]
        payload = {"alert_ids": [case], "closed_by": "Case Reviewer", "disposition": "Benign",
                   "reason": "Release window confirmed"}
        self.assertEqual(self.client.patch("/api/alerts/resolve", json=payload).json()["resolved"], [case])
        init_db(self.db)
        self.assertEqual(seed_demo(self.db), 0)
        alert = self.client.get(f"/api/alerts/{case}").json()
        self.assertEqual((alert["status"], alert["resolve_reason"]), ("RESOLVED", payload["reason"]))
        self.assertEqual(alert["closed_by"], payload["closed_by"])
        self.assertTrue(alert["closed_at"])
        counts = self.client.get("/api/analytics").json()
        self.assertEqual((counts["total_alerts"], counts["closed_by_analyst"], counts["open_alerts"]), (4, 2, 2))

    def test_technique_lookup_and_missing_case(self):
        seed_demo(self.db)
        result = self.client.get("/api/threat-intel", params={"q": "T1057"}).json()
        self.assertEqual(result["total"], 1)
        self.assertEqual(result["techniques"][0]["name"], "Process Discovery")
        self.assertEqual(result["techniques"][0]["observed_count"], 2)
        self.assertEqual(self.client.get("/api/alerts/9999").status_code, 404)

    def test_partial_settings_update_preserves_saved_fields(self):
        self.client.post("/api/settings", json={"analyst_name": "Reviewer"})
        self.client.post("/api/settings", json={"cooldown_seconds": 90})
        saved = self.client.get("/api/settings").json()
        self.assertEqual((saved["analyst_name"], saved["cooldown_seconds"]), ("Reviewer", 90))

    def test_console_id_takes_precedence_over_another_rows_queue_id(self):
        seed_demo(self.db)
        with closing(sqlite3.connect(self.db)) as conn, conn:
            conn.execute("UPDATE soc_alerts SET alert_id=4 WHERE id=1")
        result = self.client.put("/api/alerts/4/opened", json={"by": "Case Reviewer"})
        self.assertEqual(result.status_code, 200)
        self.assertEqual(self.client.get("/api/alerts/4").json()["opened_by"], "Case Reviewer")
        self.assertIsNone(self.client.get("/api/alerts/1").json()["opened_by"])


if __name__ == "__main__":
    unittest.main()
