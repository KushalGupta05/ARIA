"""Serve the local analyst console with a small, persistent synthetic casebook."""
import argparse
import json
import os
import sqlite3
from contextlib import closing
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def seed_demo(db_path):
    from frontend_db_setup import init_db

    init_db(db_path)
    cases = json.loads((ROOT / "examples" / "cases.json").read_text(encoding="utf-8"))
    now = datetime.now(timezone.utc).replace(microsecond=0)
    with closing(sqlite3.connect(db_path)) as conn, conn:
        conn.execute("BEGIN IMMEDIATE")
        if conn.execute("SELECT 1 FROM soc_alerts LIMIT 1").fetchone():
            return 0
        for case in cases:
            timestamp = now - timedelta(minutes=case["minutes_ago"])
            resolved = "closure" in case
            closure = case.get("closure", {})
            analysis = {
                "demo": True,
                "case_title": case["title"],
                "risk_score": case["risk"],
                "triage_action": case["action"],
                "incident_summary": {"what_happened": case["summary"], "confidence": "Illustrative"},
                "mitre_techniques": case["techniques"],
                "rag_threat_intel_context": case["references"],
                "investigation_priority": [
                    {"priority": n, "action": step} for n, step in enumerate(case["steps"], start=1)
                ],
                "analyst_cautions": ["Synthetic case prepared for the analyst walkthrough."],
            }
            conn.execute("""
                INSERT INTO soc_alerts (
                    alert_id, timestamp, agent_name, agent_ip, prediction_class, ml_reasoning,
                    rag_analysis, validation_warnings, severity, status, host_context,
                    feature_snapshot, disposition, resolve_reason, closed_by, closed_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                case["id"], timestamp.isoformat(), case["host"], case["ip"], case["class"],
                "Illustrative prediction assigned to the demo fixture.", json.dumps(analysis),
                case["severity"], "RESOLVED" if resolved else "NEW", json.dumps(case["context"]),
                json.dumps(case["counters"]), closure.get("disposition"), closure.get("reason"),
                "Analyst" if resolved else None,
                (timestamp + timedelta(minutes=8)).isoformat() if resolved else None,
            ))
    return len(cases)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state-dir", type=Path, default=ROOT / "var" / "demo")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--seed-only", action="store_true")
    args = parser.parse_args()
    os.environ["ARIA_STATE_DIR"] = str(args.state_dir.resolve())
    os.environ["ARIA_MITRE_JSON"] = str(ROOT / "examples" / "techniques.json")
    from frontend_db_setup import DB_PATH

    added = seed_demo(DB_PATH)
    print(f"Added {added} synthetic cases. Local state: {DB_PATH.parent}", flush=True)
    if not args.seed_only:
        import uvicorn
        from frontend_api import app

        print(f"Open http://127.0.0.1:{args.port} in your browser.", flush=True)
        uvicorn.run(app, host="127.0.0.1", port=args.port)


if __name__ == "__main__":
    main()
