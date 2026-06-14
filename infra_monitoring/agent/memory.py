# ─────────────────────────────────────────────────────────────────────────────
#  agent/memory.py
#
#  Long-term memory for the Infrastructure Monitoring Agent using ChromaDB.
#  This gives the agent the ability to remember past incidents, spot patterns,
#  and compare current metrics against historical baselines.
#
#  LOCAL DEV  : ChromaDB runs as a local file-based vector database.
#               All data is stored in the /data/memory folder on your laptop.
#               No server needed, no API key, completely free.
#
#  PRODUCTION : ChromaDB can be swapped for Azure AI Search by changing
#               the client initialisation only. All function signatures
#               stay identical so graph.py needs zero changes.
#
#  What gets stored in memory:
#    - Every health check report (full text + structured metadata)
#    - Every escalation event
#    - Metric snapshots for trend analysis
#
#  What memory enables:
#    - "Has this resource breached threshold before?"
#    - "How many times has CPU escalated this week?"
#    - "What was the disk usage 3 checks ago?"
#    - Pattern detection across multiple checks
# ─────────────────────────────────────────────────────────────────────────────

import os
import json
import datetime
import logging
import uuid

import chromadb
from chromadb.config import Settings

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
#  DATABASE INITIALISATION
#
#  ChromaDB is initialised as a persistent local database.
#  All vectors and metadata are saved to /data/memory so they survive
#  between runs. The agent's memory grows with every check it performs.
# ─────────────────────────────────────────────────────────────────────────────

DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "memory")
os.makedirs(DATA_DIR, exist_ok=True)

# Initialise the ChromaDB persistent client
chroma_client = chromadb.PersistentClient(
    path=DATA_DIR,
    settings=Settings(
        anonymized_telemetry=False      # Disable ChromaDB telemetry
    )
)

# ── Collections ───────────────────────────────────────────────────────────────
# A collection in ChromaDB is like a table in a SQL database.
# We use three separate collections for different types of memory.

# Stores every full health check report
health_reports_collection = chroma_client.get_or_create_collection(
    name="health_reports",
    metadata={"description": "Full infrastructure health check reports"}
)

# Stores every escalation event separately for quick lookup
escalations_collection = chroma_client.get_or_create_collection(
    name="escalations",
    metadata={"description": "Escalation events from the infra monitoring agent"}
)

# Stores raw metric snapshots for trend analysis
metrics_collection = chroma_client.get_or_create_collection(
    name="metric_snapshots",
    metadata={"description": "Raw metric snapshots for trend and baseline analysis"}
)

logger.info(f"ChromaDB memory initialised at: {DATA_DIR}")


# ─────────────────────────────────────────────────────────────────────────────
#  FUNCTION 1 — save_health_report
#
#  Called after every agent run to save the full report to memory.
#  The report text is stored as a vector embedding so it can be
#  searched semantically later ("find reports where disk was critical").
# ─────────────────────────────────────────────────────────────────────────────

def save_health_report(
    report: str,
    severity: str,
    overall_status: str,
    escalated: bool,
    check_timestamp: str
) -> str:
    """
    Save a completed health check report to long-term memory.

    Args:
        report:           Full text of the health report from the agent
        severity:         Highest severity found (LOW/MEDIUM/HIGH/CRITICAL)
        overall_status:   Overall system status (HEALTHY/WARNING/CRITICAL)
        escalated:        Whether this check triggered an escalation
        check_timestamp:  ISO format timestamp of when the check ran

    Returns:
        report_id: Unique ID of the saved report (for cross-referencing)
    """
    report_id = str(uuid.uuid4())

    try:
        health_reports_collection.add(
            ids=[report_id],
            documents=[report],         # Full report text — stored as vector
            metadatas=[{
                "report_id": report_id,
                "severity": severity,
                "overall_status": overall_status,
                "escalated": str(escalated),    # ChromaDB metadata must be string/int/float
                "check_timestamp": check_timestamp,
                "saved_at": datetime.datetime.now().isoformat()
            }]
        )
        logger.info(f"Health report saved to memory — ID: {report_id} | Severity: {severity}")

    except Exception as e:
        logger.error(f"Failed to save health report to memory: {str(e)}")

    return report_id


# ─────────────────────────────────────────────────────────────────────────────
#  FUNCTION 2 — save_escalation_event
#
#  Called whenever the agent sets escalate=True.
#  Stored separately so escalations can be queried quickly
#  without scanning all health reports.
# ─────────────────────────────────────────────────────────────────────────────

def save_escalation_event(
    report_id: str,
    severity: str,
    reason: str,
    affected_resource: str,
    check_timestamp: str
) -> str:
    """
    Save an escalation event to memory.

    Args:
        report_id:         ID of the health report that triggered this escalation
        severity:          Severity level that caused escalation
        reason:            The reason the agent decided to escalate
        affected_resource: Which resource breached threshold (CPU/Memory/Disk/Network)
        check_timestamp:   ISO format timestamp of when the check ran

    Returns:
        escalation_id: Unique ID of the saved escalation event
    """
    escalation_id = str(uuid.uuid4())

    escalation_text = (
        f"Escalation at {check_timestamp}. "
        f"Severity: {severity}. "
        f"Affected: {affected_resource}. "
        f"Reason: {reason}."
    )

    try:
        escalations_collection.add(
            ids=[escalation_id],
            documents=[escalation_text],
            metadatas=[{
                "escalation_id": escalation_id,
                "report_id": report_id,
                "severity": severity,
                "affected_resource": affected_resource,
                "reason": reason,
                "check_timestamp": check_timestamp,
                "saved_at": datetime.datetime.now().isoformat()
            }]
        )
        logger.info(
            f"Escalation event saved — ID: {escalation_id} | "
            f"Resource: {affected_resource} | Severity: {severity}"
        )

    except Exception as e:
        logger.error(f"Failed to save escalation event to memory: {str(e)}")

    return escalation_id


# ─────────────────────────────────────────────────────────────────────────────
#  FUNCTION 3 — save_metric_snapshot
#
#  Saves a raw snapshot of the key metric values from each check.
#  This builds a time-series history that enables trend detection.
#  Example: "CPU has been above 70% for the last 5 checks"
# ─────────────────────────────────────────────────────────────────────────────

def save_metric_snapshot(
    cpu_percent: float,
    memory_percent: float,
    disk_percent_max: float,
    network_errors: int,
    check_timestamp: str
) -> str:
    """
    Save a lightweight metric snapshot for trend analysis.

    Args:
        cpu_percent:       Overall CPU usage percentage
        memory_percent:    Overall RAM usage percentage
        disk_percent_max:  Highest disk usage % across all partitions
        network_errors:    Total network errors in + out
        check_timestamp:   ISO format timestamp of when the check ran

    Returns:
        snapshot_id: Unique ID of the saved snapshot
    """
    snapshot_id = str(uuid.uuid4())

    snapshot_text = (
        f"Metric snapshot at {check_timestamp}: "
        f"CPU={cpu_percent}%, "
        f"Memory={memory_percent}%, "
        f"Disk(max)={disk_percent_max}%, "
        f"NetworkErrors={network_errors}"
    )

    try:
        metrics_collection.add(
            ids=[snapshot_id],
            documents=[snapshot_text],
            metadatas=[{
                "snapshot_id": snapshot_id,
                "cpu_percent": cpu_percent,
                "memory_percent": memory_percent,
                "disk_percent_max": disk_percent_max,
                "network_errors": network_errors,
                "check_timestamp": check_timestamp,
                "saved_at": datetime.datetime.now().isoformat()
            }]
        )
        logger.info(f"Metric snapshot saved — CPU: {cpu_percent}% | Memory: {memory_percent}%")

    except Exception as e:
        logger.error(f"Failed to save metric snapshot: {str(e)}")

    return snapshot_id


# ─────────────────────────────────────────────────────────────────────────────
#  FUNCTION 4 — get_recent_reports
#
#  Retrieves the N most recent health reports from memory.
#  Used by main.py to show history and by the agent to detect
#  whether a current issue is a new problem or a recurring one.
# ─────────────────────────────────────────────────────────────────────────────

def get_recent_reports(n: int = 5) -> list:
    """
    Retrieve the N most recent health check reports from memory.

    Args:
        n: Number of recent reports to retrieve (default 5)

    Returns:
        List of report dicts with text and metadata, sorted newest first
    """
    try:
        total = health_reports_collection.count()
        if total == 0:
            logger.info("No reports in memory yet")
            return []

        # Retrieve up to n reports — ChromaDB returns in insertion order
        results = health_reports_collection.get(
            limit=min(n, total),
            include=["documents", "metadatas"]
        )

        reports = []
        for i in range(len(results["ids"])):
            reports.append({
                "report_id": results["ids"][i],
                "report_text": results["documents"][i],
                "metadata": results["metadatas"][i]
            })

        # Sort by timestamp descending (newest first)
        reports.sort(
            key=lambda x: x["metadata"].get("check_timestamp", ""),
            reverse=True
        )

        logger.info(f"Retrieved {len(reports)} recent reports from memory")
        return reports

    except Exception as e:
        logger.error(f"Failed to retrieve recent reports: {str(e)}")
        return []


# ─────────────────────────────────────────────────────────────────────────────
#  FUNCTION 5 — get_escalation_count
#
#  Returns how many escalations have occurred in the last N hours.
#  Used by main.py to show escalation frequency and alert if
#  escalations are happening too often (storm detection).
# ─────────────────────────────────────────────────────────────────────────────

def get_escalation_count(hours: int = 24) -> dict:
    """
    Count escalation events that occurred in the last N hours.

    Args:
        hours: How many hours back to look (default 24)

    Returns:
        Dict with total count and list of escalation summaries
    """
    try:
        total = escalations_collection.count()
        if total == 0:
            return {"count": 0, "hours_checked": hours, "escalations": []}

        results = escalations_collection.get(
            limit=total,
            include=["documents", "metadatas"]
        )

        # Filter to the time window
        cutoff = datetime.datetime.now() - datetime.timedelta(hours=hours)
        recent_escalations = []

        for i in range(len(results["ids"])):
            metadata = results["metadatas"][i]
            try:
                event_time = datetime.datetime.fromisoformat(
                    metadata.get("check_timestamp", "")
                )
                if event_time >= cutoff:
                    recent_escalations.append({
                        "escalation_id": results["ids"][i],
                        "severity": metadata.get("severity"),
                        "affected_resource": metadata.get("affected_resource"),
                        "reason": metadata.get("reason"),
                        "timestamp": metadata.get("check_timestamp")
                    })
            except (ValueError, TypeError):
                continue

        logger.info(
            f"Escalation count in last {hours}h: {len(recent_escalations)}"
        )

        return {
            "count": len(recent_escalations),
            "hours_checked": hours,
            "escalations": sorted(
                recent_escalations,
                key=lambda x: x["timestamp"],
                reverse=True
            )
        }

    except Exception as e:
        logger.error(f"Failed to get escalation count: {str(e)}")
        return {"count": 0, "hours_checked": hours, "escalations": [], "error": str(e)}


# ─────────────────────────────────────────────────────────────────────────────
#  FUNCTION 6 — get_metric_trend
#
#  Returns the last N metric snapshots so the agent or main.py
#  can see whether metrics are improving, stable, or worsening.
# ─────────────────────────────────────────────────────────────────────────────

def get_metric_trend(n: int = 10) -> dict:
    """
    Retrieve the last N metric snapshots to analyse trends.

    Args:
        n: Number of snapshots to retrieve (default 10)

    Returns:
        Dict with snapshots list and simple trend indicators
    """
    try:
        total = metrics_collection.count()
        if total == 0:
            return {"snapshots": [], "trend": "no data yet"}

        results = metrics_collection.get(
            limit=min(n, total),
            include=["documents", "metadatas"]
        )

        snapshots = []
        for i in range(len(results["ids"])):
            snapshots.append(results["metadatas"][i])

        # Sort oldest first for trend calculation
        snapshots.sort(key=lambda x: x.get("check_timestamp", ""))

        # Simple trend: compare first half average vs second half average
        trend = "stable"
        if len(snapshots) >= 4:
            mid = len(snapshots) // 2
            first_half_cpu = sum(s.get("cpu_percent", 0) for s in snapshots[:mid]) / mid
            second_half_cpu = sum(s.get("cpu_percent", 0) for s in snapshots[mid:]) / (len(snapshots) - mid)

            if second_half_cpu > first_half_cpu + 10:
                trend = "CPU increasing"
            elif second_half_cpu < first_half_cpu - 10:
                trend = "CPU decreasing"
            else:
                trend = "stable"

        return {
            "snapshots": snapshots,
            "total_snapshots_in_memory": total,
            "trend": trend
        }

    except Exception as e:
        logger.error(f"Failed to get metric trend: {str(e)}")
        return {"snapshots": [], "trend": "error", "error": str(e)}


# ─────────────────────────────────────────────────────────────────────────────
#  FUNCTION 7 — get_memory_summary
#
#  Returns a high-level summary of everything in memory.
#  Used by main.py to display memory stats on startup.
# ─────────────────────────────────────────────────────────────────────────────

def get_memory_summary() -> dict:
    """
    Return a summary of what is currently stored in agent memory.

    Returns:
        Dict with counts for reports, escalations, and metric snapshots
    """
    try:
        return {
            "total_health_reports": health_reports_collection.count(),
            "total_escalations": escalations_collection.count(),
            "total_metric_snapshots": metrics_collection.count(),
            "memory_location": DATA_DIR,
            "status": "operational"
        }
    except Exception as e:
        logger.error(f"Failed to get memory summary: {str(e)}")
        return {"status": "error", "error": str(e)}