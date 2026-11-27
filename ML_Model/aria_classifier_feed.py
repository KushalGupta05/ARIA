#!/usr/bin/env python3
"""
aria_classifier_feed.py
=======================
ARIA ML Consumer Pipeline — bridges a live Docker log stream to a
Random Forest classifier trained on the TON_IoT dataset.

Flow:
  docker logs -> JSON parse -> feature extraction -> RF .predict() -> SQLite queue
"""

import subprocess
import sys
import json
import os
import time
import sqlite3
import numpy as np
import joblib

from frontend_db_setup import CONFIG_PATH, DB_PATH as FRONTEND_DB_PATH, QUEUE_DB_PATH as DB_PATH, STATE_DIR
from queue_store import init_database
from telemetry_schema import FEATURE_KEYS, NORMAL_CLASS

MODEL_PATH = STATE_DIR / "aria_rf_model.pkl"
SAFE_DEFAULT = 0.0


def extract_features(data_dict: dict) -> np.ndarray:
    """
    Map the *data* dictionary coming from Wazuh's archives.json into
    a (15,) NumPy float64 array whose element order matches FEATURE_KEYS.
    Missing keys are filled with SAFE_DEFAULT.
    """
    vec = np.full(len(FEATURE_KEYS), SAFE_DEFAULT, dtype=np.float64)
    for idx, key in enumerate(FEATURE_KEYS):
        raw = data_dict.get(key)
        if raw is not None:
            try:
                vec[idx] = float(raw)
            except (ValueError, TypeError):
                vec[idx] = SAFE_DEFAULT
    return vec

# ---------------------------------------------------------------------------
# 4.  SQLite Queue — Database Setup
# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# 5.  Main Loop — stream -> parse -> predict -> SQLite queue
# ---------------------------------------------------------------------------
DOCKER_CMD = [
    "docker", "exec", "-i",
    os.environ.get("ARIA_WAZUH_CONTAINER", "single-node-wazuh.manager-1"),
    "tail", "-F", "-n", "0",
    "/var/ossec/logs/archives/archives.json",
]

INSERT_SQL = """
    INSERT INTO raw_alerts_queue
        (timestamp, source_event_id, agent_name, agent_ip,
         feature_snapshot, prediction_class, host_context, occurrence_count)
    VALUES (?, ?, ?, ?, ?, ?, ?, 1);
"""

UPDATE_THROTTLED_SQL = """
    UPDATE raw_alerts_queue
    SET occurrence_count = occurrence_count + 1,
        timestamp = ?,
        feature_snapshot = ?,
        host_context = ?
    WHERE id = ?;
"""


def _load_cooldown() -> int:
    cfg_path = CONFIG_PATH
    try:
        with open(cfg_path, "r") as f:
            return int(json.load(f).get("cooldown_seconds", 120))
    except Exception:
        return 120


def cooldown_active(tracker: dict, key: tuple, now: float, cooldown_sec: float) -> bool:
    """Fixed (non-sliding) window: tracker[key] = (first_queued_ts, row_id), set only on INSERT."""
    return key in tracker and (now - tracker[key][0]) < cooldown_sec


def _top_pid_label(host_context_json: str) -> str:
    try:
        procs = json.loads(host_context_json).get("top_processes") or []
        if procs:
            p = procs[0]
            return f"{p.get('name') or p.get('Name') or '?'} ({p.get('pid', p.get('Id', '?'))})"
    except Exception:
        pass
    return "n/a"


def _open_stream() -> subprocess.Popen:
    # tail -F + -n 0: only new lines, survives log rotation inside the container
    return subprocess.Popen(
        DOCKER_CMD,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        bufsize=1,
    )


def main() -> None:
    if not MODEL_PATH.is_file():
        sys.exit("Train the Windows model first with train_windows_model.py.")
    model = joblib.load(MODEL_PATH)
    if model.n_features_in_ != len(FEATURE_KEYS):
        sys.exit("This model has a different feature schema. Rebuild it with train_windows_model.py.")
    db = init_database(DB_PATH)

    # (agent_name, int(prediction)) -> (last_timestamp_epoch, last_row_id)
    cooldown_tracker: dict[tuple[str, int], tuple[float, int]] = {}

    event_count = 0
    alert_count = 0
    proc = None

    try:
        # Auto-reconnect loop: survives `docker restart` of the Wazuh manager
        while True:
            print(f"[ARIA] Starting log stream: {' '.join(DOCKER_CMD)}", flush=True)
            proc = _open_stream()
            for raw_line in proc.stdout:
                raw_line = raw_line.strip()
                if not raw_line:
                    continue
                try:
                    event = json.loads(raw_line)
                except json.JSONDecodeError:
                    continue

                data = event.get("data")
                if not isinstance(data, dict):
                    continue
                if not any(k in data for k in FEATURE_KEYS):
                    continue

                feature_vec = extract_features(data)
                if np.all(feature_vec == 0.0):
                    continue

                prediction = int(model.predict(feature_vec.reshape(1, -1))[0])
                event_count += 1

                ts = event.get("timestamp", "?")
                agent_info = event.get("agent", {})
                agent_name = agent_info.get("name", "?")
                agent_ip = agent_info.get("ip", "?")

                raw_hc = data.get("host_context")
                if isinstance(raw_hc, dict):
                    host_context_json = json.dumps(raw_hc)
                elif isinstance(raw_hc, str):
                    host_context_json = raw_hc
                else:
                    host_context_json = "{}"
                top_pid = _top_pid_label(host_context_json)

                # In scikit-learn alphabetical LabelEncoder sorting on TON_IoT Windows 10:
                # 0=ddos, 1=dos, 2=injection, 3=mitm, 4=normal, 5=password, 6=scanning, 7=xss.
                # Normal baseline traffic is prediction == 4; any prediction != 4 (y_hat != 4) is queued as an anomaly.
                if prediction == NORMAL_CLASS:
                    print(f"[TELEMETRY] Host: {agent_name} | Pred: Class 4 | Top PID: {top_pid} | Action: Normal(Ignored)", flush=True)
                    continue

                snapshot_json = json.dumps({
                    FEATURE_KEYS[i]: float(feature_vec[i]) for i in range(len(FEATURE_KEYS))
                })
                now = time.time()
                cooldown_key = (agent_name, prediction)
                cooldown_sec = _load_cooldown()

                if cooldown_active(cooldown_tracker, cooldown_key, now, cooldown_sec):
                    _, last_row_id = cooldown_tracker[cooldown_key]
                    db.execute(UPDATE_THROTTLED_SQL, (ts, snapshot_json, host_context_json, last_row_id))
                    db.commit()
                    try:
                        fconn = sqlite3.connect(FRONTEND_DB_PATH)
                        fconn.execute("""
                            UPDATE soc_alerts
                            SET occurrence_count = occurrence_count + 1,
                                timestamp = ?, feature_snapshot = ?, host_context = ?
                            WHERE alert_id = ?
                        """, (ts, snapshot_json, host_context_json, last_row_id))
                        fconn.commit()
                        fconn.close()
                    except Exception:
                        pass
                    # NOTE: tracker is intentionally NOT refreshed here (fixed window anchored at first_queued_ts)
                    print(f"[TELEMETRY] Host: {agent_name} | Pred: Class {prediction} | Top PID: {top_pid} | Action: Cooldown (alert #{last_row_id} +1)", flush=True)
                else:
                    cur = db.execute(INSERT_SQL, (
                        ts, event.get("id", "N/A"), agent_name, agent_ip,
                        snapshot_json, prediction, host_context_json,
                    ))
                    new_id = cur.lastrowid
                    db.commit()
                    cooldown_tracker[cooldown_key] = (now, new_id)
                    alert_count += 1
                    print(f"[TELEMETRY] Host: {agent_name} | Pred: Class {prediction} | Top PID: {top_pid} | Action: Queued (id={new_id})", flush=True)

            # stdout closed -> docker exec died (e.g. manager restarted)
            try:
                proc.terminate()
            except Exception:
                pass
            print("[WARN] Log stream closed (Wazuh manager restart?). Reconnecting in 5s...", flush=True)
            time.sleep(5)

    except KeyboardInterrupt:
        print("\n[ARIA] Interrupted -- shutting down gracefully.")
    finally:
        if proc is not None:
            try:
                proc.terminate()
            except Exception:
                pass
        db.close()
        print(f"[ARIA] DB closed.  Session totals -> events={event_count}  alerts={alert_count}")


if __name__ == "__main__":
    main()
