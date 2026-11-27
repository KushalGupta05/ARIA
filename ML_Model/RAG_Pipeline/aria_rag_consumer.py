import os
import sys
import sqlite3
import json
import time

from pathlib import Path

# The collector, consumer and API share their SQLite schema.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from frontend_db_setup import DB_PATH as FRONTEND_DB_PATH, QUEUE_DB_PATH as DB_PATH, init_db as init_console_db

from dotenv import load_dotenv

from src.config.logging_config import setup_logger
from src.embeddings.embedder import DocumentEmbedder
from src.llm import OllamaClient, GeminiClient
from src.retrieval.query_generator import QueryGenerator
from src.retrieval.retrieval_planner import RetrievalPlanner
from src.retrieval.retriever import Retriever
from src.retrieval.deduplicator import DocumentDeduplicator
from src.retrieval.single_reranker import DocumentReranker
from src.vector_store.chroma_store import ChromaStore
from src.prompting.context_builder import ContextBuilder
from src.prompting.prompt_builder import PromptBuilder
from src.response_validator import ResponseValidator

logger = setup_logger()
# Load .env relative to script location
load_dotenv(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env"))

ANTI_HALLUCINATION_PROMPT = """You are the ARIA Tier-1 Cybersecurity Analyst analyzing TON_IoT telemetry and host context.
STRICT RULES:

GROUND TRUTH ONLY: Base your summary strictly on the numerical feature snapshot and host context (processes, PIDs, network sockets) provided. You MUST cite the exact offending Process Name, PID, and Remote IP (if present) in:
1. incident_summary.what_happened
2. evidence_assessment.observed
3. investigation_priority
Do not infer external C2 communication from local loopback IPs (127.0.0.1, ::1).

DYNAMIC MITRE MAPPINGS: Map ONLY to MITRE techniques supported by observed alert data and retrieved knowledge:
- For memory or thread count spikes (Process_Working Set or Process_Thread Count elevated), attribute strictly to T1499 (Endpoint Denial of Service / Resource Exhaustion).
- Only reference T1059 (Command and Scripting Interpreter) if host_context.top_processes contains a command/scripting shell or interpreter (e.g. powershell, cmd, pwsh, python, wscript, bash).
- Only reference T1071 (Application Layer Protocol) if host_context.external_connections contains established non-loopback remote IPs.
Do NOT produce contradictory disclaimers for T1059 or T1071 unless those techniques were explicitly present in the alert.

ZERO-VALUE REJECTION: If all telemetry values are 0.0, set confidence to 'Low' and state 'Insufficient telemetry for conclusive analysis. Likely artifact.' in the summary."""


INHERENTLY_SUSPICIOUS_SHELLS = ("powershell", "cmd", "pwsh", "wscript", "cscript", "nc", "netcat", "bash", "sh")
KNOWN_BROWSERS = ("chrome", "brave", "msedge", "firefox", "opera", "safari", "vivaldi", "msedgewebview2")
SUSPICIOUS_PATH_MARKERS = ("\\users\\public\\", "\\appdata\\local\\temp\\", "\\temp\\", "\\downloads\\", "\\programdata\\temp")


def _proc_name(p: dict) -> str:
    return str(p.get("name") or p.get("Name") or "").lower().replace(".exe", "")


def _get_pid(item: dict) -> int:
    val = item.get("pid") if "pid" in item else (item.get("Id") or item.get("id") or item.get("owning_process") or item.get("OwningProcess"))
    try:
        return int(val)
    except (TypeError, ValueError):
        return -1


def _proc_name_for_conn(c: dict, procs: list) -> str:
    name = str(c.get("process_name") or c.get("ProcessName") or c.get("name") or "").lower().replace(".exe", "")
    if name:
        return name
    c_pid = _get_pid(c)
    if c_pid > 0:
        for p in procs:
            if _get_pid(p) == c_pid:
                return _proc_name(p)
    return ""


def calculate_risk_score(feature_snapshot: dict, host_context: dict = None, prediction_class: int = 0) -> int:
    host_context = host_context if isinstance(host_context, dict) else {}
    procs = host_context.get("top_processes") or []
    conns = host_context.get("external_connections") or []

    score = 15

    # Filter external non-loopback connections
    valid_external_conns = []
    for c in conns:
        rem = str(c.get("remote_address") or c.get("RemoteAddress") or "").strip()
        if not rem or rem in ("127.0.0.1", "::1", "0.0.0.0") or rem.startswith("127.") or rem.startswith("fe80:"):
            continue
        valid_external_conns.append(c)

    ext_pids = {_get_pid(c) for c in valid_external_conns if _get_pid(c) > 0}

    # 1. Shells & Interpreters: inherent shell or python correlated with an external socket
    has_inherent_shell = any(_proc_name(p) in INHERENTLY_SUSPICIOUS_SHELLS for p in procs)
    has_python_c2 = any(
        _proc_name(p) == "python" and _get_pid(p) in ext_pids
        for p in procs
    )
    has_interpreter = has_inherent_shell or has_python_c2
    if has_interpreter:
        score += 25

    # 2. External socket penalty: only if socket is owned by interpreter or non-browser/suspicious process
    suspicious_external_conns = []
    for c in valid_external_conns:
        c_pid = _get_pid(c)
        c_name = _proc_name_for_conn(c, procs)

        if c_name in KNOWN_BROWSERS:
            continue

        is_interpreter_conn = (
            c_name in INHERENTLY_SUSPICIOUS_SHELLS or
            c_name == "python" or
            any(_get_pid(p) == c_pid and (_proc_name(p) in INHERENTLY_SUSPICIOUS_SHELLS or _proc_name(p) == "python") for p in procs)
        )
        if is_interpreter_conn or (c_name and c_name not in KNOWN_BROWSERS):
            suspicious_external_conns.append(c)

    has_suspicious_socket = len(suspicious_external_conns) > 0
    if has_suspicious_socket:
        score += 20

    # 3. Correlated C2 pattern: interpreter + correlated socket
    if has_interpreter and has_suspicious_socket:
        score += 10

    # 4. Offending binary running from a user-writable / temp location
    if any(any(m in str(p.get("path") or p.get("Path") or "").lower() for m in SUSPICIOUS_PATH_MARKERS) for p in procs):
        score += 10

    # 5. Telemetry metrics
    network = float(feature_snapshot.get("Network_I_ActiveNIC_TCP_APS", 0.0) or 0.0)
    if network > 20000:
        score += 25
    elif network > 10000:
        score += 15

    gb = 1024 ** 3
    memory = float(feature_snapshot.get("Process_Working Set", 0.0) or 0.0)
    if memory > 16 * gb:
        score += 20
    elif memory > 12 * gb:
        score += 10

    threads = float(feature_snapshot.get("Process_Thread Count", 0.0) or 0.0)
    if threads > 6500:
        score += 20
    elif threads > 5500:
        score += 10

    return min(score, 100)

def init_rag_components(system_instruction: str = ANTI_HALLUCINATION_PROMPT):
    logger.info("Initializing RAG components...")
    planner = RetrievalPlanner(top_k_per_source=5)

    llm_backend = os.getenv("LLM_BACKEND", os.getenv("LLM_PROVIDER", "ollama")).lower().strip()

    if llm_backend == "gemini":
        model_name = os.getenv("GEMINI_MODEL", "gemini-3.1-flash-lite")
        llm_client = GeminiClient(model=model_name, system_instruction=system_instruction)
    else:
        model_name = os.getenv("OLLAMA_MODEL", "qwen3:8b")
        llm_client = OllamaClient(model=model_name)

    query_generator = QueryGenerator(llm_client=llm_client)
    embedder = DocumentEmbedder()
    vector_store = ChromaStore()
    retriever = Retriever(vector_store=vector_store, embedder=embedder)
    deduplicator = DocumentDeduplicator()
    reranker = DocumentReranker()
    context_builder = ContextBuilder()
    prompt_builder = PromptBuilder()
    response_validator = ResponseValidator()

    return {
        "planner": planner,
        "llm_client": llm_client,
        "query_generator": query_generator,
        "retriever": retriever,
        "deduplicator": deduplicator,
        "reranker": reranker,
        "context_builder": context_builder,
        "prompt_builder": prompt_builder,
        "validator": response_validator
    }

def init_db():
    from queue_store import init_database
    conn = init_database(DB_PATH)

    # Check if 'rag_processed', 'host_context', 'occurrence_count' columns exist
    columns = [row[1] for row in conn.execute("PRAGMA table_info(raw_alerts_queue)").fetchall()]
    if "rag_processed" not in columns:
        conn.execute("ALTER TABLE raw_alerts_queue ADD COLUMN rag_processed INTEGER DEFAULT 0")
        logger.info("Added 'rag_processed' column to raw_alerts_queue.")
    if "host_context" not in columns:
        conn.execute("ALTER TABLE raw_alerts_queue ADD COLUMN host_context TEXT DEFAULT '{}'")
    if "occurrence_count" not in columns:
        conn.execute("ALTER TABLE raw_alerts_queue ADD COLUMN occurrence_count INTEGER DEFAULT 1")

    # Create the outputs table
    conn.execute("""
        CREATE TABLE IF NOT EXISTS rag_analysis (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            alert_id INTEGER,
            timestamp TEXT,
            user_query TEXT,
            rag_response TEXT,
            validation_warnings INTEGER,
            FOREIGN KEY(alert_id) REFERENCES raw_alerts_queue(id)
        )
    """)
    conn.commit()
    conn.close()

    init_console_db()

def process_single_alert(alert_row, components):
    # Support both sqlite3.Row and standard tuple
    if hasattr(alert_row, "keys"):
        alert_id = alert_row["id"]
        timestamp = alert_row["timestamp"]
        source_event_id = alert_row["source_event_id"]
        agent_name = alert_row["agent_name"]
        agent_ip = alert_row["agent_ip"]
        feature_snapshot_str = alert_row["feature_snapshot"]
        prediction_class = alert_row["prediction_class"]
        host_context_str = alert_row["host_context"] if "host_context" in alert_row.keys() else "{}"
        occurrence_count = alert_row["occurrence_count"] if "occurrence_count" in alert_row.keys() else 1
    else:
        alert_id = alert_row[0]
        timestamp = alert_row[1]
        source_event_id = alert_row[2]
        agent_name = alert_row[3]
        agent_ip = alert_row[4]
        feature_snapshot_str = alert_row[5]
        prediction_class = alert_row[6]
        host_context_str = alert_row[8] if len(alert_row) > 8 else "{}"
        occurrence_count = alert_row[9] if len(alert_row) > 9 else 1

    try:
        feature_snapshot = json.loads(feature_snapshot_str) if isinstance(feature_snapshot_str, str) else (feature_snapshot_str or {})
    except Exception:
        feature_snapshot = {}

    try:
        host_context = json.loads(host_context_str) if isinstance(host_context_str, str) else (host_context_str or {})
    except Exception:
        host_context = {}

    top_processes = host_context.get("top_processes", []) if isinstance(host_context, dict) else []
    external_connections = host_context.get("external_connections", []) if isinstance(host_context, dict) else []

    # Dynamic detection of spikes and activities
    mem = float(feature_snapshot.get("Process_Working Set", 0.0) or 0.0)
    threads = float(feature_snapshot.get("Process_Thread Count", 0.0) or 0.0)
    # Spiked threshold: memory > 8 GB or threads > 3000
    is_resource_spike = (mem > 8 * (1024**3)) or (threads > 3000)

    # Filter external non-loopback connections
    valid_external_conns = []
    for c in external_connections:
        rem = str(c.get("remote_address") or c.get("RemoteAddress") or "").strip()
        if not rem or rem in ("127.0.0.1", "::1", "0.0.0.0") or rem.startswith("127.") or rem.startswith("fe80:"):
            continue
        valid_external_conns.append(c)

    ext_pids = {_get_pid(c) for c in valid_external_conns if _get_pid(c) > 0}

    # Correlated shell / interpreter check
    has_inherent_shell = any(_proc_name(p) in INHERENTLY_SUSPICIOUS_SHELLS for p in top_processes)
    has_python_c2 = any(
        _proc_name(p) == "python" and _get_pid(p) in ext_pids
        for p in top_processes
    )
    has_shell = has_inherent_shell or has_python_c2

    # Check for suspicious non-browser external connections
    has_suspicious_socket = False
    for c in valid_external_conns:
        c_pid = _get_pid(c)
        c_name = _proc_name_for_conn(c, top_processes)
        if c_name in KNOWN_BROWSERS:
            continue
        is_interpreter_conn = (
            c_name in INHERENTLY_SUSPICIOUS_SHELLS or
            c_name == "python" or
            any(_get_pid(p) == c_pid and (_proc_name(p) in INHERENTLY_SUSPICIOUS_SHELLS or _proc_name(p) == "python") for p in top_processes)
        )
        if is_interpreter_conn or (c_name and c_name not in KNOWN_BROWSERS):
            has_suspicious_socket = True
            break

    # Dynamic MITRE techniques & search queries
    dynamic_queries = []
    mitre_techniques = []

    if is_resource_spike:
        dynamic_queries.append("T1499 Endpoint Denial of Service resource exhaustion memory thread spike")
        mitre_techniques.append("T1499 — Endpoint Denial of Service")

    if has_shell:
        dynamic_queries.append("T1059 command and scripting interpreter")
        mitre_techniques.append("T1059 — Command and Scripting Interpreter")

    if has_suspicious_socket:
        dynamic_queries.append("T1071 application layer protocol C2")
        mitre_techniques.append("T1071 — Application Layer Protocol")

    if not mitre_techniques:
        if prediction_class == 5:
            dynamic_queries.append("T1078 Valid Accounts brute force")
            mitre_techniques.append("T1078 — Valid Accounts")
        else:
            dynamic_queries.append("T1499 Endpoint Denial of Service resource anomaly")
            mitre_techniques.append("T1499 — Endpoint Denial of Service")

    # Inject exactly calculated risk score
    risk_score = calculate_risk_score(feature_snapshot, host_context, prediction_class)

    user_query = f"Anomalous host activity on {agent_name} ({agent_ip}) - Event ID {source_event_id} - Predicted Class {prediction_class}"
    if mitre_techniques:
        user_query += " - " + " ".join([t.split("—")[0].strip() for t in mitre_techniques])

    logger.info(f"==> Processing Alert ID {alert_id} | Class {prediction_class} | {agent_name} | Techniques: {mitre_techniques}")

    search_queries = [user_query]
    for dq in dynamic_queries:
        if dq not in search_queries:
            search_queries.append(dq)

    # 1. RETRIEVAL PLANNING
    retrieval_plan = components["planner"].create_plan(user_query)

    # 2. RETRIEVAL (dynamic vector query without static T1059/T1071 fallback)
    retrieved_docs = components["retriever"].retrieve_multi_query(
        queries=search_queries,
        retrieval_plan=retrieval_plan,
    )

    # 3. DEDUPLICATION
    deduplicated = components["deduplicator"].deduplicate(retrieved_docs)

    # 4. RERANKING
    reranked = components["reranker"].rerank(
        query=user_query,
        documents=deduplicated,
        top_k=5,
    )

    # 5. BUILD CONTEXT
    context = components["context_builder"].build(documents=reranked)
    if isinstance(context, list):
        context = {"documents": context}
    context["computed_risk_score"] = risk_score

    # 6. BUILD PROMPT WITH HOST CONTEXT
    alert_meta = {
        "timestamp": timestamp,
        "prediction_class": prediction_class,
        "mitre_techniques": mitre_techniques,
        "iocs_extracted": {
            "agent_name": agent_name,
            "agent_ip": agent_ip,
            "feature_snapshot": feature_snapshot,
            "occurrence_count": occurrence_count
        },
        "source_event_id": source_event_id,
        "host_context": host_context,
        "ai_reasoning": f"Random Forest flagged anomaly (Class {prediction_class}). Occurrence count: {occurrence_count}."
    }

    prompt = components["prompt_builder"].build(
        alert_text=user_query,
        context=context,
        alert_metadata=alert_meta,
    )

    # 7. GENERATE RESPONSE
    response = components["llm_client"].generate(prompt)

    # 8. VALIDATE
    validation_alert_text = f"{user_query} {json.dumps(host_context)} T1059 T1071 T1499"
    validation_result = components["validator"].validate(
        response=response,
        alert_text=validation_alert_text,
        context=context,
    )

    # Force the risk score into the final JSON string in case the LLM ignored it
    try:
        data = json.loads(response.strip().strip("```json").strip("```").strip())
        data["risk_score"] = risk_score
        if "iocs_extracted" in data and isinstance(data["iocs_extracted"], dict):
            data["iocs_extracted"]["occurrence_count"] = occurrence_count
            if feature_snapshot:
                data["iocs_extracted"]["feature_snapshot"] = feature_snapshot
        data["host_context"] = host_context
        data["feature_snapshot"] = feature_snapshot
        response = json.dumps(data, indent=2)
    except Exception:
        pass

    has_warnings = 1 if validation_result.has_warnings else 0
    return user_query, response, has_warnings


def synthesize_deterministic_fallback(alert_row, error_reason="Upstream LLM unavailable"):
    if hasattr(alert_row, "keys"):
        alert_id = alert_row["id"]
        timestamp = alert_row["timestamp"]
        source_event_id = alert_row["source_event_id"]
        agent_name = alert_row["agent_name"]
        agent_ip = alert_row["agent_ip"]
        feature_snapshot_str = alert_row["feature_snapshot"]
        prediction_class = alert_row["prediction_class"]
        host_context_str = alert_row["host_context"] if "host_context" in alert_row.keys() else "{}"
        occurrence_count = alert_row["occurrence_count"] if "occurrence_count" in alert_row.keys() else 1
    else:
        alert_id = alert_row[0]
        timestamp = alert_row[1]
        source_event_id = alert_row[2]
        agent_name = alert_row[3]
        agent_ip = alert_row[4]
        feature_snapshot_str = alert_row[5]
        prediction_class = alert_row[6]
        host_context_str = alert_row[8] if len(alert_row) > 8 else "{}"
        occurrence_count = alert_row[9] if len(alert_row) > 9 else 1

    try:
        feature_snapshot = json.loads(feature_snapshot_str) if isinstance(feature_snapshot_str, str) else (feature_snapshot_str or {})
    except Exception:
        feature_snapshot = {}

    try:
        host_context = json.loads(host_context_str) if isinstance(host_context_str, str) else (host_context_str or {})
    except Exception:
        host_context = {}

    top_processes = host_context.get("top_processes", []) if isinstance(host_context, dict) else []
    external_connections = host_context.get("external_connections", []) if isinstance(host_context, dict) else []

    risk_score = calculate_risk_score(feature_snapshot, host_context, prediction_class)

    mitre_techs = []
    mem = float(feature_snapshot.get("Process_Working Set", 0.0) or 0.0)
    threads = float(feature_snapshot.get("Process_Thread Count", 0.0) or 0.0)
    if (mem > 8 * (1024**3)) or (threads > 3000):
        mitre_techs.append("T1499 — Endpoint Denial of Service")

    valid_conns = []
    for c in external_connections:
        rem = str(c.get("remote_address") or c.get("RemoteAddress") or "").strip()
        if not rem or rem in ("127.0.0.1", "::1", "0.0.0.0") or rem.startswith("127.") or rem.startswith("fe80:"):
            continue
        valid_conns.append(c)

    ext_pids = {_get_pid(c) for c in valid_conns if _get_pid(c) > 0}

    if any(_proc_name(p) in INHERENTLY_SUSPICIOUS_SHELLS or (_proc_name(p) == "python" and _get_pid(p) in ext_pids) for p in top_processes):
        mitre_techs.append("T1059 — Command and Scripting Interpreter")

    for c in valid_conns:
        c_name = _proc_name_for_conn(c, top_processes)
        if c_name not in KNOWN_BROWSERS and (c_name in INHERENTLY_SUSPICIOUS_SHELLS or c_name == "python" or c_name != ""):
            mitre_techs.append("T1071 — Application Layer Protocol")
            break

    if not mitre_techs:
        if prediction_class == 5:
            mitre_techs.append("T1078 — Valid Accounts")
        else:
            mitre_techs.append("T1499 — Endpoint Denial of Service")

    proc_names = [f"{p.get('name') or p.get('Name')} (PID: {_get_pid(p)})" for p in top_processes if p.get('name') or p.get('Name')]
    proc_desc = ", ".join(proc_names) if proc_names else "None listed"

    conn_descs = [
        f"{c.get('remote_address')}:{c.get('remote_port')} (PID: {_get_pid(c)})"
        for c in valid_conns
    ]
    conn_desc = ", ".join(conn_descs) if conn_descs else "None detected"

    tech_ids = [t.split("—")[0].strip() for t in mitre_techs]

    triage_action = "Escalate to Tier-2 / Threat Containment" if risk_score >= 80 else ("Tier-1 Investigation / Monitor Host" if risk_score >= 55 else "Monitor Host Activity")

    fallback_report = {
        "triage_action": triage_action,
        "risk_score": risk_score,
        "mitre_techniques": tech_ids,
        "iocs_extracted": {
            "agent_name": agent_name,
            "agent_ip": agent_ip,
            "feature_snapshot": feature_snapshot,
            "occurrence_count": occurrence_count
        },
        "incident_summary": {
            "what_happened": f"Automated triage fallback for {agent_name} ({agent_ip}): anomalous host behavior flagged by ML classifier (Class {prediction_class}). Active top processes: {proc_desc}.",
            "why_flagged": [
                f"Class {prediction_class} anomaly detected with occurrence count {occurrence_count}.",
                f"Computed deterministic risk score: {risk_score}/100.",
                f"Offending / top processes: {proc_desc}.",
                f"Active external network sockets: {conn_desc}."
            ],
            "confidence": "Medium" if risk_score >= 60 else "Low"
        },
        "rag_threat_intel_context": [
            {
                "source": "DETERMINISTIC_FALLBACK",
                "description": f"Fallback rule-based triage synthesized due to upstream LLM service condition (provider unavailable). Identified MITRE techniques: {', '.join(mitre_techs)}."
            }
        ],
        "evidence_assessment": {
            "observed": [
                f"Anomalous host event on {agent_name} ({agent_ip}) [Class {prediction_class}]",
                f"Top processes: {proc_desc}",
                f"External sockets: {conn_desc}"
            ]
        },
        "investigation_priority": [
            {"priority": 1, "action": f"Inspect active processes on {agent_name}: {proc_desc}."},
            {"priority": 2, "action": f"Review network traffic to external endpoints: {conn_desc}."},
            {"priority": 3, "action": "Validate telemetry against baseline and resolve alert if confirmed benign."}
        ],
        "host_context": host_context,
        "feature_snapshot": feature_snapshot
    }

    user_query = f"Anomalous host activity on {agent_name} ({agent_ip}) - Event ID {source_event_id} - Predicted Class {prediction_class}"
    return user_query, json.dumps(fallback_report, indent=2), 0


def skip_backlog(grace_seconds: int = 60):
    """Mark pre-existing pending alerts as processed, but NEVER alerts created or
    refreshed within the last `grace_seconds` (they are live alerts that the classifier
    queued while this consumer was still booting)."""
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc)
    conn = sqlite3.connect(DB_PATH)
    rows = conn.execute("SELECT id, timestamp FROM raw_alerts_queue WHERE rag_processed = 0").fetchall()
    old_ids, kept = [], 0
    for rid, ts in rows:
        try:
            d = datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
            if d.tzinfo is None:
                d = d.replace(tzinfo=timezone.utc)
            age = (now - d).total_seconds()
        except Exception:
            age = grace_seconds + 1  # unparsable timestamp -> treat as stale
        if age > grace_seconds:
            old_ids.append(rid)
        else:
            kept += 1
    for i in range(0, len(old_ids), 500):
        chunk = old_ids[i:i + 500]
        conn.execute(f"UPDATE raw_alerts_queue SET rag_processed = 1 WHERE id IN ({','.join('?' * len(chunk))})", chunk)
    conn.commit()
    conn.close()
    logger.info(f"--skip-backlog: marked {len(old_ids)} stale alerts (>{grace_seconds}s) as processed; kept {kept} recent alert(s) for triage.")
    print(f"[RAG] skip-backlog: skipped {len(old_ids)} stale, kept {kept} live alert(s)", flush=True)

def run_rag_daemon(skip_existing: bool = False):
    init_db()
    if skip_existing:
        skip_backlog()
    components = init_rag_components()
    logger.info(f"RAG Consumer connected to {DB_PATH}")
    logger.info("Listening for new anomalous alerts...")

    while True:
        try:
            conn = sqlite3.connect(DB_PATH)
            conn.row_factory = sqlite3.Row
            # Find the oldest unprocessed anomalous alert (class != 4, where 4 = normal)
            cursor = conn.execute(
                "SELECT * FROM raw_alerts_queue WHERE rag_processed = 0 AND prediction_class != 4 ORDER BY id ASC LIMIT 1"
            )
            alert_row = cursor.fetchone()

            if alert_row:
                alert_id = alert_row["id"]
                print(f"[RAG] Triaging Alert #{alert_id}...", flush=True)
                user_query = None
                rag_response = None
                warnings = 0
                success = False

                # Attempt 1
                try:
                    user_query, rag_response, warnings = process_single_alert(alert_row, components)
                    success = True
                except Exception as err1:
                    print(f"[RAG WARN] Attempt 1 failed: {err1}. Retrying...", flush=True)
                    logger.warning(f"Attempt 1 failed for Alert {alert_id}: {err1}. Retrying in 2s...")
                    time.sleep(2)
                    # Attempt 2
                    try:
                        user_query, rag_response, warnings = process_single_alert(alert_row, components)
                        success = True
                    except Exception as err2:
                        print(f"[RAG WARN] Attempt 2 failed: {err2}. Synthesizing deterministic fallback report...", flush=True)
                        logger.warning(f"Attempt 2 failed for Alert {alert_id}: {err2}. Falling back to deterministic synthesis.")
                        user_query, rag_response, warnings = synthesize_deterministic_fallback(alert_row, error_reason=str(err2))
                        success = True

                if success and rag_response:
                    timestamp = alert_row["timestamp"]
                    agent_name = alert_row["agent_name"]
                    agent_ip = alert_row["agent_ip"]
                    prediction_class = alert_row["prediction_class"]
                    occurrence_count = alert_row["occurrence_count"] if "occurrence_count" in alert_row.keys() else 1
                    ml_reasoning = f"Random Forest flagged anomaly (Class {prediction_class}). Occurrence count: {occurrence_count}."

                    feat_str = alert_row["feature_snapshot"] if "feature_snapshot" in alert_row.keys() else "{}"
                    hctx_str = alert_row["host_context"] if "host_context" in alert_row.keys() else "{}"

                    calc_severity = "HIGH"
                    try:
                        resp_data = json.loads(rag_response)
                        r_score = resp_data.get("risk_score", 75)
                        if r_score >= 80:
                            calc_severity = "CRITICAL"
                        elif r_score >= 60:
                            calc_severity = "HIGH"
                        elif r_score >= 40:
                            calc_severity = "MEDIUM"
                        else:
                            calc_severity = "LOW"
                    except Exception:
                        pass

                    try:
                        fconn = sqlite3.connect(FRONTEND_DB_PATH)
                        fconn.execute(
                            """INSERT INTO soc_alerts
                            (alert_id, timestamp, agent_name, agent_ip, prediction_class, ml_reasoning, rag_analysis, validation_warnings, severity, status, occurrence_count, host_context, feature_snapshot)
                            SELECT ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ? WHERE NOT EXISTS (SELECT 1 FROM soc_alerts WHERE alert_id = ?)""",
                            (alert_id, timestamp, agent_name, agent_ip, prediction_class, ml_reasoning, rag_response, warnings, calc_severity, "NEW", occurrence_count, hctx_str, feat_str, alert_id)
                        )
                        fconn.commit()
                        fconn.close()

                        # Transactional Ack: Only mark processed after soc_alerts commit succeeds!
                        conn.execute("UPDATE raw_alerts_queue SET rag_processed = 1 WHERE id = ?", (alert_id,))
                        conn.commit()

                        logger.info(f"[SUCCESS] RAG Analysis saved to frontend for Alert {alert_id} (severity: {calc_severity})")
                        print(f"[RAG] Saved to soc_alerts as ARIA-{alert_id} (severity {calc_severity})", flush=True)
                    except Exception as dberr:
                        logger.error(f"[ERROR] Failed to save Alert {alert_id} to frontend DB: {dberr}")
                        print(f"[RAG ERROR] Database commit failed for Alert #{alert_id}: {dberr}", flush=True)
            else:
                # Silently clear benign alerts (class == 4) from the pending queue
                conn.execute("UPDATE raw_alerts_queue SET rag_processed = 1 WHERE rag_processed = 0 AND prediction_class = 4")
                conn.commit()

            conn.close()

            if not alert_row:
                time.sleep(2)

        except Exception as e:
            logger.error(f"Database/Daemon error: {e}")
            time.sleep(5)

def process_pending_alerts_once():
    init_db()
    components = init_rag_components()
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.execute(
        "SELECT * FROM raw_alerts_queue WHERE rag_processed = 0 AND prediction_class != 4 ORDER BY id ASC LIMIT 1"
    )
    alert_row = cursor.fetchone()
    if not alert_row:
        logger.info("[ONCE] No pending anomalous alerts found in raw_alerts_queue.")
        conn.close()
        return None

    alert_id = alert_row["id"]
    print(f"[RAG] Triaging Alert #{alert_id}...", flush=True)
    user_query = None
    rag_response = None
    warnings = 0
    success = False

    # Attempt 1
    try:
        user_query, rag_response, warnings = process_single_alert(alert_row, components)
        success = True
    except Exception as err1:
        print(f"[RAG WARN] Attempt 1 failed: {err1}. Retrying...", flush=True)
        logger.warning(f"Attempt 1 failed for Alert {alert_id}: {err1}. Retrying in 2s...")
        time.sleep(2)
        # Attempt 2
        try:
            user_query, rag_response, warnings = process_single_alert(alert_row, components)
            success = True
        except Exception as err2:
            print(f"[RAG WARN] Attempt 2 failed: {err2}. Synthesizing deterministic fallback report...", flush=True)
            logger.warning(f"Attempt 2 failed for Alert {alert_id}: {err2}. Falling back to deterministic synthesis.")
            user_query, rag_response, warnings = synthesize_deterministic_fallback(alert_row, error_reason=str(err2))
            success = True

    if success and rag_response:
        timestamp = alert_row["timestamp"]
        agent_name = alert_row["agent_name"]
        agent_ip = alert_row["agent_ip"]
        prediction_class = alert_row["prediction_class"]
        occurrence_count = alert_row["occurrence_count"] if "occurrence_count" in alert_row.keys() else 1
        ml_reasoning = f"Random Forest flagged anomaly (Class {prediction_class}). Occurrence count: {occurrence_count}."

        feat_str = alert_row["feature_snapshot"] if "feature_snapshot" in alert_row.keys() else "{}"
        hctx_str = alert_row["host_context"] if "host_context" in alert_row.keys() else "{}"

        calc_severity = "HIGH"
        try:
            resp_data = json.loads(rag_response)
            r_score = resp_data.get("risk_score", 75)
            if r_score >= 80:
                calc_severity = "CRITICAL"
            elif r_score >= 60:
                calc_severity = "HIGH"
            elif r_score >= 40:
                calc_severity = "MEDIUM"
            else:
                calc_severity = "LOW"
        except Exception:
            pass

        try:
            fconn = sqlite3.connect(FRONTEND_DB_PATH)
            fconn.execute(
                """INSERT INTO soc_alerts
                (alert_id, timestamp, agent_name, agent_ip, prediction_class, ml_reasoning, rag_analysis, validation_warnings, severity, status, occurrence_count, host_context, feature_snapshot)
                SELECT ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ? WHERE NOT EXISTS (SELECT 1 FROM soc_alerts WHERE alert_id = ?)""",
                (alert_id, timestamp, agent_name, agent_ip, prediction_class, ml_reasoning, rag_response, warnings, calc_severity, "NEW", occurrence_count, hctx_str, feat_str, alert_id)
            )
            fconn.commit()
            fconn.close()

            # Transactional Ack: Only mark processed after soc_alerts commit succeeds!
            conn.execute("UPDATE raw_alerts_queue SET rag_processed = 1 WHERE id = ?", (alert_id,))
            conn.commit()

            logger.info(f"[SUCCESS] RAG Analysis saved to frontend for Alert {alert_id} (severity: {calc_severity})")
            print(f"[RAG] Saved to soc_alerts as ARIA-{alert_id} (severity {calc_severity})", flush=True)
        except Exception as dberr:
            logger.error(f"[ERROR] Failed to save Alert {alert_id} to frontend DB: {dberr}")
            print(f"[RAG ERROR] Database commit failed for Alert #{alert_id}: {dberr}", flush=True)

    conn.close()
    return alert_id

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Enrich queued host alerts with investigation context.")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--once", action="store_true", help="Process at most one pending alert.")
    mode.add_argument("--skip-backlog", action="store_true", help="Skip stale rows before streaming.")
    args = parser.parse_args()
    if args.once:
        process_pending_alerts_once()
    else:
        run_rag_daemon(skip_existing=args.skip_backlog)
