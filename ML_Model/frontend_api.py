import sqlite3
import tempfile
import json
import os
import re
from typing import List, Optional, Dict, Any
from datetime import datetime, timezone
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from contextlib import asynccontextmanager
from pathlib import Path

from frontend_db_setup import CONFIG_PATH, DB_PATH, QUEUE_DB_PATH, PROJECT_ROOT, init_db
from pydantic import BaseModel
import uvicorn

@asynccontextmanager
async def lifespan(app):
    init_db()
    yield


app = FastAPI(title="ARIA analyst API", lifespan=lifespan)

# Add CORS middleware
ALLOWED_ORIGINS = [
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    "http://localhost:4173",
    "http://127.0.0.1:4173",
    "http://localhost:8000",
    "http://127.0.0.1:8000",
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

MITRE_JSON_PATH = Path(os.environ.get(
    "ARIA_MITRE_JSON", Path(__file__).resolve().parent / "RAG_Pipeline" / "data" / "raw" / "parsed_mitre_data.json"
))

DEFAULT_CONFIG = {
    "escalate_threshold": 80,
    "monitor_threshold": 55,
    "cooldown_seconds": 120,
    "analyst_name": "Analyst"
}

# Cache for MITRE data in memory
_CACHED_MITRE_DATA = None

def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def get_queue_db_connection():
    if os.path.exists(QUEUE_DB_PATH):
        conn = sqlite3.connect(QUEUE_DB_PATH)
        conn.row_factory = sqlite3.Row
        return conn
    return None

class AlertStatusUpdate(BaseModel):
    status: str
    disposition: Optional[str] = None
    reason: Optional[str] = None
    closed_by: Optional[str] = None
    owner: Optional[str] = None

class BulkStatusUpdate(AlertStatusUpdate):
    ids: List[int]

class ResolveAlertsPayload(BaseModel):
    alert_ids: Optional[List[int]] = None
    alert_id: Optional[int] = None
    closed_by: Optional[str] = "Analyst"
    disposition: Optional[str] = "True Positive"
    reason: Optional[str] = ""

class StepsUpdate(BaseModel):
    steps: Dict[str, Any]

class OpenedUpdate(BaseModel):
    by: str = "Analyst"

class SettingsPayload(BaseModel):
    escalate_threshold: Optional[int] = 80
    monitor_threshold: Optional[int] = 55
    cooldown_seconds: Optional[int] = 120
    analyst_name: Optional[str] = "Analyst"

def _load_settings() -> dict:
    if os.path.exists(CONFIG_PATH):
        try:
            with open(CONFIG_PATH, "r", encoding="utf-8") as f:
                data = json.load(f)
                res = dict(DEFAULT_CONFIG)
                res.update(data)
                return res
        except Exception as e:
            print(f"[frontend_api] Error reading config: {e}")
    return dict(DEFAULT_CONFIG)

def _save_settings(settings: dict) -> dict:
    merged = _load_settings()
    merged.update(settings)
    with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=CONFIG_PATH.parent, delete=False) as f:
        json.dump(merged, f, indent=2)
    os.replace(f.name, CONFIG_PATH)
    return merged

def _load_mitre_data():
    global _CACHED_MITRE_DATA
    if _CACHED_MITRE_DATA is not None:
        return _CACHED_MITRE_DATA
    if not os.path.exists(MITRE_JSON_PATH):
        return []
    try:
        with open(MITRE_JSON_PATH, "r", encoding="utf-8") as f:
            raw = json.load(f)
            formatted = []
            for item in raw:
                meta = item.get("metadata", {})
                tid = meta.get("mitre_id", "")
                name = meta.get("name", "")
                content = item.get("text_content", "")

                tactics = []
                m_tactics = re.search(r"Tactics:\s*([^\n]+)", content)
                if m_tactics:
                    tactics = [t.strip() for t in m_tactics.group(1).split(",") if t.strip()]

                platforms = []
                m_plat = re.search(r"Platforms:\s*([^\n]+)", content)
                if m_plat:
                    platforms = [p.strip() for p in m_plat.group(1).split(",") if p.strip()]

                desc = ""
                m_desc = re.search(r"Description:\s*([^\n]+(?:\n[^\n]+)?)", content)
                if m_desc:
                    desc = m_desc.group(1).strip()
                else:
                    desc = content[:250].strip()

                formatted.append({
                    "id": tid,
                    "name": name,
                    "tactics": tactics,
                    "platforms": platforms,
                    "description": desc,
                })
            _CACHED_MITRE_DATA = formatted
            return _CACHED_MITRE_DATA
    except Exception as e:
        print(f"[frontend_api] Error loading MITRE data: {e}")
        return []

def parse_rag_analysis(row):
    """Parses rag_analysis and extracts self-contained host_context and feature_snapshot."""
    d = dict(row)
    if 'rag_analysis' in d and d['rag_analysis']:
        try:
            d['rag_analysis'] = json.loads(d['rag_analysis'])
        except (json.JSONDecodeError, TypeError):
            pass

    # 1. Parse direct host_context column on soc_alerts first (self-contained)
    if 'host_context' in d and d['host_context']:
        if isinstance(d['host_context'], str):
            try:
                d['host_context'] = json.loads(d['host_context'])
            except (json.JSONDecodeError, TypeError):
                d['host_context'] = {}
    else:
        d['host_context'] = {}

    # 2. Parse direct feature_snapshot column on soc_alerts first (self-contained)
    if 'feature_snapshot' in d and d['feature_snapshot']:
        if isinstance(d['feature_snapshot'], str):
            try:
                d['feature_snapshot'] = json.loads(d['feature_snapshot'])
            except (json.JSONDecodeError, TypeError):
                d['feature_snapshot'] = {}
    else:
        d['feature_snapshot'] = {}

    # 3. Fallback to extracting from inside rag_analysis if empty
    if isinstance(d.get('rag_analysis'), dict):
        if not d['host_context'] and 'host_context' in d['rag_analysis']:
            d['host_context'] = d['rag_analysis']['host_context']
        if not d['feature_snapshot'] and 'feature_snapshot' in d['rag_analysis']:
            d['feature_snapshot'] = d['rag_analysis']['feature_snapshot']

    d['occurrence_count'] = int(d.get('occurrence_count') or 1)
    return d

def _enrich_alerts_with_queue(alerts_list: List[dict]):
    """Batch-fetches missing host_context or feature_snapshots from raw_alerts_queue."""
    qconn = get_queue_db_connection()
    if not qconn:
        return alerts_list

    try:
        needed_aids = [
            a.get('alert_id') for a in alerts_list
            if a.get('alert_id') and (not a.get('host_context') or not a.get('feature_snapshot'))
        ]
        if not needed_aids:
            qconn.close()
            return alerts_list

        placeholders = ",".join("?" for _ in needed_aids)
        qcur = qconn.cursor()
        qcur.execute(f"SELECT id, feature_snapshot, host_context FROM raw_alerts_queue WHERE id IN ({placeholders})", needed_aids)
        qdata = {}
        for qrow in qcur.fetchall():
            aid = qrow['id']
            try:
                feats = json.loads(qrow['feature_snapshot']) if qrow['feature_snapshot'] else {}
            except Exception:
                feats = {}
            try:
                hctx = json.loads(qrow['host_context']) if qrow['host_context'] else {}
            except Exception:
                hctx = {}
            qdata[aid] = (feats, hctx)
        qconn.close()

        for a in alerts_list:
            aid = a.get('alert_id')
            if aid in qdata:
                feats, hctx = qdata[aid]
                if not a.get('feature_snapshot'):
                    a['feature_snapshot'] = feats
                if not a.get('host_context') or a.get('host_context') == {}:
                    a['host_context'] = hctx
                # also ensure inside rag_analysis if object
                if isinstance(a.get('rag_analysis'), dict):
                    if 'feature_snapshot' not in a['rag_analysis']:
                        a['rag_analysis']['feature_snapshot'] = feats
                    if 'host_context' not in a['rag_analysis'] or a['rag_analysis']['host_context'] == {}:
                        a['rag_analysis']['host_context'] = hctx
    except Exception as e:
        print(f"[frontend_api] Error enriching from queue DB: {e}")
        try:
            qconn.close()
        except:
            pass

    return alerts_list

@app.get("/api/health")
def health():
    """Liveness probe reporting database status."""
    try:
        conn = get_db_connection()
        count = conn.execute("SELECT COUNT(*) FROM soc_alerts").fetchone()[0]
        latest = conn.execute("SELECT id, alert_id, timestamp FROM soc_alerts ORDER BY id DESC LIMIT 1").fetchone()
        conn.close()
        return {
            "status": "ok",
            "database": "sqlite",
            "alert_count": count,
            "latest": dict(latest) if latest else None,
        }
    except sqlite3.Error as e:
        raise HTTPException(status_code=503, detail=f"Database error: {str(e)}")

@app.get("/api/alerts")
def get_alerts(aggregate: bool = Query(False, description="Group identical alerts together")):
    """Returns all alerts from soc_alerts table, enriched with telemetry."""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM soc_alerts ORDER BY timestamp DESC")
        raw_alerts = [parse_rag_analysis(row) for row in cursor.fetchall()]
        conn.close()

        raw_alerts = _enrich_alerts_with_queue(raw_alerts)

        if not aggregate:
            return raw_alerts

        aggregated = {}
        for alert in raw_alerts:
            rag = alert.get("rag_analysis", {}) or {}
            risk = rag.get("risk_score", "UNKNOWN")
            sig = f"{alert['agent_ip']}_{alert['ml_reasoning']}_{risk}_{alert['status']}"

            if sig not in aggregated:
                alert['occurrence_count'] = 1
                alert['related_ids'] = [alert['id']]
                aggregated[sig] = alert
            else:
                aggregated[sig]['occurrence_count'] += 1
                aggregated[sig]['related_ids'].append(alert['id'])

        return list(aggregated.values())

    except sqlite3.Error as e:
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")

# UI links use the console row ID. Old API clients can supply a queue ID.
CASE_LOOKUP = """
    SELECT id FROM soc_alerts WHERE id = :case_id OR alert_id = :case_id
    ORDER BY (id = :case_id) DESC, id LIMIT 1
"""

@app.get("/api/alerts/{alert_id}")
def get_alert(alert_id: int):
    """Returns a single alert by its integer ID or alert_id."""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(f"SELECT * FROM soc_alerts WHERE id = ({CASE_LOOKUP})", {"case_id": alert_id})
        row = cursor.fetchone()
        conn.close()

        if row is None:
            raise HTTPException(status_code=404, detail="Alert not found")

        alert_dict = parse_rag_analysis(row)
        return _enrich_alerts_with_queue([alert_dict])[0]
    except sqlite3.Error as e:
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")

def _apply_status(cursor, alert_id: int, u) -> bool:
    cursor.execute(CASE_LOOKUP, {"case_id": alert_id})
    row = cursor.fetchone()
    if row is None:
        return False
    real_id = row[0]
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    if u.status.upper() == "RESOLVED":
        cursor.execute(
            "UPDATE soc_alerts SET status=?, disposition=?, resolve_reason=?, closed_by=?, closed_at=? WHERE id=?",
            (u.status.upper(), u.disposition, u.reason, u.closed_by or "Analyst", now, real_id))
    else:
        cursor.execute("UPDATE soc_alerts SET status=?, owner=COALESCE(?, owner) WHERE id=?",
                       (u.status.upper(), u.owner, real_id))
    return True

@app.patch("/api/alerts/resolve")
@app.post("/api/alerts/resolve")
def resolve_alerts(payload: ResolveAlertsPayload):
    """Resolves one or more alerts with disposition, analyst name, and reason."""
    ids = payload.alert_ids or ([payload.alert_id] if payload.alert_id is not None else [])
    if not ids:
        raise HTTPException(status_code=400, detail="Missing alert_ids or alert_id")

    disposition = payload.disposition or "True Positive"
    reason = payload.reason or ""
    closed_by = payload.closed_by or "Analyst"
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        resolved = []
        for i in ids:
            cursor.execute(CASE_LOOKUP, {"case_id": i})
            row = cursor.fetchone()
            if row:
                real_id = row[0]
                cursor.execute(
                    "UPDATE soc_alerts SET status='RESOLVED', disposition=?, resolve_reason=?, closed_by=?, closed_at=? WHERE id=?",
                    (disposition, reason, closed_by, now, real_id)
                )
                resolved.append(real_id)
        conn.commit()
        conn.close()
        return {
            "status": "ok",
            "resolved": resolved,
            "count": len(resolved),
            "disposition": disposition,
            "closed_by": closed_by,
            "closed_at": now
        }
    except sqlite3.Error as e:
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")

@app.put("/api/alerts/{alert_id}/status")
def update_alert_status(alert_id: int, status_update: AlertStatusUpdate):
    """Accepts {'status','disposition','reason','closed_by','owner'} and updates the DB."""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        if not _apply_status(cursor, alert_id, status_update):
            conn.close()
            raise HTTPException(status_code=404, detail="Alert not found")
        conn.commit()
        conn.close()
        return {"message": "Alert status updated successfully", "id": alert_id, "status": status_update.status}
    except sqlite3.Error as e:
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")

@app.post("/api/alerts/bulk-status")
def bulk_update_status(payload: BulkStatusUpdate):
    """Applies one status/disposition to many alerts in a single transaction."""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        updated = [i for i in payload.ids if _apply_status(cursor, i, payload)]
        conn.commit()
        conn.close()
        return {"updated": updated, "count": len(updated)}
    except sqlite3.Error as e:
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")

@app.put("/api/alerts/{alert_id}/steps")
def update_steps(alert_id: int, payload: StepsUpdate):
    """Stores the investigation checklist state ({index: {by, at}}) as JSON."""
    try:
        conn = get_db_connection()
        result = conn.execute(f"UPDATE soc_alerts SET steps_state=:steps WHERE id=({CASE_LOOKUP})",
                              {"steps": json.dumps(payload.steps), "case_id": alert_id})
        conn.commit()
        conn.close()
        if result.rowcount == 0:
            raise HTTPException(status_code=404, detail="Alert not found")
        return {"id": alert_id, "steps": payload.steps}
    except sqlite3.Error as e:
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")

@app.put("/api/alerts/{alert_id}/opened")
def mark_opened(alert_id: int, payload: OpenedUpdate):
    """Records first analyst view (audit trail)."""
    try:
        conn = get_db_connection()
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        result = conn.execute(f"""UPDATE soc_alerts SET opened_at=COALESCE(opened_at, :now),
                                opened_by=COALESCE(opened_by, :who) WHERE id=({CASE_LOOKUP})""",
                              {"now": now, "who": payload.by, "case_id": alert_id})
        conn.commit()
        conn.close()
        if result.rowcount == 0:
            raise HTTPException(status_code=404, detail="Alert not found")
        return {"id": alert_id}
    except sqlite3.Error as e:
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")

@app.get("/api/analytics")
def get_analytics():
    """Computes real-time SOC metrics and aggregations from soc_alerts."""
    try:
        conn = get_db_connection()
        cur = conn.cursor()

        total = cur.execute("SELECT COUNT(*) FROM soc_alerts").fetchone()[0]
        open_count = cur.execute("SELECT COUNT(*) FROM soc_alerts WHERE status != 'RESOLVED'").fetchone()[0]
        resolved_count = cur.execute("SELECT COUNT(*) FROM soc_alerts WHERE status == 'RESOLVED'").fetchone()[0]
        closed_by_analyst = cur.execute("SELECT COUNT(*) FROM soc_alerts WHERE status == 'RESOLVED' AND closed_by IS NOT NULL AND UPPER(closed_by) NOT IN ('ARIA', 'RULE')").fetchone()[0]
        closed_by_aria = cur.execute("SELECT COUNT(*) FROM soc_alerts WHERE status == 'RESOLVED' AND UPPER(closed_by) IN ('ARIA', 'RULE')").fetchone()[0]

        # Severity breakdown
        sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for sev, c in cur.execute("SELECT severity, COUNT(*) FROM soc_alerts GROUP BY severity").fetchall():
            s_up = (sev or "UNKNOWN").upper()
            sev_counts[s_up] = c

        # Disposition breakdown
        disp_counts = {"True Positive": 0, "False Positive": 0, "Benign": 0, "Duplicate": 0, "Unresolved": 0}
        for d, c in cur.execute("SELECT COALESCE(disposition, 'Unresolved'), COUNT(*) FROM soc_alerts GROUP BY disposition").fetchall():
            disp_counts[d] = c

        # Top affected hosts
        top_hosts = []
        for host, c in cur.execute("SELECT agent_name, COUNT(*) FROM soc_alerts GROUP BY agent_name ORDER BY COUNT(*) DESC LIMIT 5").fetchall():
            top_hosts.append({"host": host or "Unknown", "count": c})

        # Top triggered prediction classes (matching TON_IoT alphabetical LabelEncoder indices 0..7)
        class_names = {
            0: "DDoS",
            1: "DoS / Resource Exhaustion",
            2: "Code Injection",
            3: "MITM",
            4: "Normal Baseline",
            5: "Password / Brute Force",
            6: "Network Scanning",
            7: "XSS / Web Attack"
        }
        top_classes = []
        for pclass, reason, c in cur.execute("SELECT prediction_class, ml_reasoning, COUNT(*) FROM soc_alerts GROUP BY prediction_class ORDER BY COUNT(*) DESC LIMIT 5").fetchall():
            top_classes.append({
                "class": pclass,
                "name": class_names.get(pclass, f"Class {pclass}"),
                "reason": reason or "",
                "count": c
            })

        # Timeline: last 24 hourly UTC buckets, chronological, zero-filled
        from datetime import timedelta
        def _parse_ts(s):
            try:
                d = datetime.fromisoformat(str(s).replace("Z", "+00:00").replace(" UTC", "+00:00"))
                return d if d.tzinfo else d.replace(tzinfo=timezone.utc)
            except Exception:
                return None
        now_h = datetime.now(timezone.utc).replace(minute=0, second=0, microsecond=0)
        buckets = {now_h - timedelta(hours=i): 0 for i in range(23, -1, -1)}
        for (ts,) in cur.execute("SELECT timestamp FROM soc_alerts WHERE timestamp IS NOT NULL").fetchall():
            d = _parse_ts(ts)
            if d is None:
                continue
            key = d.astimezone(timezone.utc).replace(minute=0, second=0, microsecond=0)
            if key in buckets:
                buckets[key] += 1
        timeline = [{"time": k.strftime("%Y-%m-%d %H:00"), "label": k.strftime("%H:00"), "count": v}
                    for k, v in sorted(buckets.items())]
        # Mean Time To Triage (MTTT)
        time_diffs = []
        for t_str, c_str in cur.execute("SELECT timestamp, closed_at FROM soc_alerts WHERE status = 'RESOLVED' AND closed_at IS NOT NULL").fetchall():
            try:
                t = datetime.fromisoformat(t_str.replace("Z", "+00:00").replace(" UTC", "+00:00"))
                c = datetime.fromisoformat(c_str.replace("Z", "+00:00").replace(" UTC", "+00:00"))
                diff = (c - t).total_seconds()
                if 0 <= diff <= 86400 * 30:
                    time_diffs.append(diff)
            except Exception:
                pass

        avg_mttt_sec = round(sum(time_diffs) / len(time_diffs), 1) if time_diffs else 0
        conn.close()

        # False positive rate calculation
        fp_count = disp_counts.get("False Positive", 0)
        fp_rate = round((fp_count / resolved_count * 100), 1) if resolved_count > 0 else 0.0

        return {
            "total_alerts": total,
            "open_alerts": open_count,
            "resolved_alerts": resolved_count,
            "closed_by_analyst": closed_by_analyst,
            "closed_by_aria": closed_by_aria,
            "mean_time_to_triage_sec": avg_mttt_sec,
            "false_positive_rate": fp_rate,
            "severity_breakdown": sev_counts,
            "disposition_breakdown": disp_counts,
            "top_hosts": top_hosts,
            "top_classes": top_classes,
            "volume_timeline": timeline
        }
    except sqlite3.Error as e:
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")

@app.get("/api/threat-intel")
def get_threat_intel(q: Optional[str] = Query(None, description="Search query for technique ID, name, or description")):
    """Searches MITRE ATT&CK techniques and correlates with local alert frequencies."""
    try:
        mitre_list = _load_mitre_data()

        # Count occurrences in local DB
        conn = get_db_connection()
        cur = conn.cursor()
        rows = cur.execute("SELECT rag_analysis FROM soc_alerts").fetchall()
        conn.close()

        tech_counts = {}
        for r in rows:
            if not r[0]:
                continue
            try:
                data = json.loads(r[0])
                observed = set()
                for technique in data.get("mitre_techniques", []) or []:
                    observed.update(re.findall(r"\bT\d{4}(?:\.\d{3})?\b", str(technique)))
                for reference in data.get("rag_threat_intel_context", []) or []:
                    details = f"{reference.get('description', '')} {reference.get('source', '')}"
                    observed.update(re.findall(r"\bT\d{4}(?:\.\d{3})?\b", details))
                for tid in observed:
                    tech_counts[tid] = tech_counts.get(tid, 0) + 1
            except Exception:
                pass

        q_lower = q.lower().strip() if q else ""
        results = []
        for t in mitre_list:
            tid = t["id"]
            name = t["name"]
            desc = t["description"]
            tactics = t.get("tactics", [])
            platforms = t.get("platforms", [])
            obs = tech_counts.get(tid, 0)

            if not q_lower or (
                q_lower in tid.lower() or
                q_lower in name.lower() or
                q_lower in desc.lower() or
                any(q_lower in tac.lower() for tac in tactics)
            ):
                results.append({
                    "id": tid,
                    "name": name,
                    "tactics": tactics,
                    "platforms": platforms,
                    "description": desc,
                    "observed_count": obs
                })

        results.sort(key=lambda x: (-x["observed_count"], x["id"]))
        return {
            "total": len(results),
            "query": q or "",
            "techniques": results[:100]
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Threat intel search error: {str(e)}")

@app.get("/api/settings")
def get_settings():
    """Reads current system configuration from aria_config.json."""
    return _load_settings()

@app.post("/api/settings")
def update_settings(payload: SettingsPayload):
    """Updates and persists system configuration to aria_config.json."""
    try:
        saved = _save_settings(payload.model_dump(exclude_unset=True))
        return {"status": "ok", "settings": saved}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to save settings: {str(e)}")

DIST = PROJECT_ROOT / "ARIA-Frontend" / "dist"
if (DIST / "index.html").is_file():
    app.mount("/assets", StaticFiles(directory=DIST / "assets"), name="assets")

    @app.get("/", include_in_schema=False)
    @app.get("/login", include_in_schema=False)
    @app.get("/dashboard", include_in_schema=False)
    @app.get("/triage", include_in_schema=False)
    @app.get("/triage/{case_id}", include_in_schema=False)
    @app.get("/threat-intel", include_in_schema=False)
    @app.get("/analytics", include_in_schema=False)
    @app.get("/settings", include_in_schema=False)
    def serve_console():
        return FileResponse(DIST / "index.html")
else:
    @app.get("/", response_class=HTMLResponse, include_in_schema=False)
    def console_setup():
        return '<h1>ARIA analyst API</h1><p>Build the React console using the repository quickstart.</p><a href="/docs">API documentation</a>'


if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8000)
