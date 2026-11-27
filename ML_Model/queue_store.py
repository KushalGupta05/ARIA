"""SQLite queue schema shared by the classifier and investigation worker."""
import sqlite3
from pathlib import Path

def init_database(db_path: str) -> sqlite3.Connection:
    """
    Connect to the SQLite queue database, enable WAL mode for concurrent
    read/write safety, and create/migrate the raw_alerts_queue table if needed.
    """
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS raw_alerts_queue (
            id                INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp         TEXT,
            source_event_id   TEXT,
            agent_name        TEXT,
            agent_ip          TEXT,
            feature_snapshot  TEXT,
            prediction_class  INTEGER,
            host_context      TEXT DEFAULT '{}',
            occurrence_count  INTEGER DEFAULT 1
        );
    """)
    conn.commit()

    # Safely migrate existing databases if new columns do not exist
    for col_name, col_def in [
        ("host_context", "TEXT DEFAULT '{}'"),
        ("occurrence_count", "INTEGER DEFAULT 1"),
    ]:
        try:
            conn.execute(f"ALTER TABLE raw_alerts_queue ADD COLUMN {col_name} {col_def};")
            conn.commit()
        except sqlite3.OperationalError:
            pass  # column already exists

    print(f"[ARIA] SQLite queue ready at {db_path}  (WAL mode)")
    return conn
