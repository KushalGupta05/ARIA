"""Storage shared by the analyst API, queue consumer and local demo."""
import os
import sqlite3
from contextlib import closing
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
STATE_DIR = Path(os.environ.get("ARIA_STATE_DIR", PROJECT_ROOT / "var" / "live")).expanduser().resolve()
DB_PATH = STATE_DIR / "aria_frontend.db"
QUEUE_DB_PATH = STATE_DIR / "aria_alerts_queue.db"
CONFIG_PATH = STATE_DIR / "aria_config.json"

AUDIT_COLUMNS = {
    "disposition": "TEXT", "resolve_reason": "TEXT", "closed_by": "TEXT",
    "closed_at": "TEXT", "owner": "TEXT", "opened_at": "TEXT",
    "opened_by": "TEXT", "steps_state": "TEXT", "host_context": "TEXT DEFAULT '{}'",
    "feature_snapshot": "TEXT DEFAULT '{}'", "occurrence_count": "INTEGER DEFAULT 1",
}


def init_db(path=DB_PATH):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with closing(sqlite3.connect(path)) as conn, conn:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("BEGIN IMMEDIATE")
        conn.execute("""
            CREATE TABLE IF NOT EXISTS soc_alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                alert_id INTEGER,
                timestamp TEXT,
                agent_name TEXT,
                agent_ip TEXT,
                prediction_class INTEGER,
                ml_reasoning TEXT,
                rag_analysis TEXT,
                validation_warnings INTEGER,
                severity TEXT,
                status TEXT DEFAULT 'NEW'
            )
        """)
        columns = {row[1] for row in conn.execute("PRAGMA table_info(soc_alerts)")}
        if "id" not in columns:
            # Older worker-only databases used alert_id as their primary key.
            conn.execute("ALTER TABLE soc_alerts ADD COLUMN id INTEGER")
            conn.execute("UPDATE soc_alerts SET id = alert_id")
            conn.execute("""
                CREATE TRIGGER IF NOT EXISTS soc_alerts_assign_id
                AFTER INSERT ON soc_alerts WHEN NEW.id IS NULL
                BEGIN UPDATE soc_alerts SET id = NEW.alert_id WHERE rowid = NEW.rowid; END
            """)
        for name, declaration in AUDIT_COLUMNS.items():
            if name not in columns:
                conn.execute(f"ALTER TABLE soc_alerts ADD COLUMN {name} {declaration}")
        conn.execute("CREATE INDEX IF NOT EXISTS soc_alerts_queue_id ON soc_alerts(alert_id)")


def get_all_alerts():
    if not DB_PATH.is_file():
        return []
    with closing(sqlite3.connect(DB_PATH)) as conn:
        conn.row_factory = sqlite3.Row
        return [dict(row) for row in conn.execute("SELECT * FROM soc_alerts")]


if __name__ == "__main__":
    init_db()
    print(f"Console database ready at {DB_PATH}")
