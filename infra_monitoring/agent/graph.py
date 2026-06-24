# ─────────────────────────────────────────────────────────────────────────────
#  agent/graph.py
#  Graph flow:
#  [START] → [collect_metrics_node] → [check_patch_status_node] →
#  [analyse_metrics_node] → [parse_output_node] → [END]
# ─────────────────────────────────────────────────────────────────────────────

import sys
import os
import json
import datetime
import logging
from typing import TypedDict, Annotated, Sequence
import operator

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from langchain_core.messages import BaseMessage, HumanMessage, SystemMessage, AIMessage
from langchain_ollama import ChatOllama
from langgraph.graph import StateGraph, END

from infra_monitoring.agent.tools import (
    get_cpu_metrics,
    get_memory_metrics,
    get_disk_metrics,
    get_network_metrics,
    get_top_processes,
    check_os_patch_status     # ⭐ NEW
)
from infra_monitoring.agent.prompts import INFRA_MONITORING_SYSTEM_PROMPT
from shared.event_schema import AIOpsEvent, MetricsSnapshot


# ─────────────────────────────────────────────────────────────────────────────
#  LOGGING SETUP
# ─────────────────────────────────────────────────────────────────────────────

os.makedirs("logs", exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler("logs/infra_agent.log")
    ]
)
logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
#  AGENT STATE
# ─────────────────────────────────────────────────────────────────────────────

class AgentState(TypedDict):
    messages: Annotated[Sequence[BaseMessage], operator.add]
    raw_metrics: dict
    patch_status: dict          # ⭐ NEW — result of check_os_patch_status
    escalate: bool
    severity: str
    overall_status: str
    report: str
    check_timestamp: str
    error: str


# ─────────────────────────────────────────────────────────────────────────────
#  LLM CONFIGURATION
# ─────────────────────────────────────────────────────────────────────────────

llm = ChatOllama(
    model="llama3.2",
    temperature=0,
    num_ctx=4096,
)

# ── PRODUCTION (uncomment when on company laptop) ────────────────────────────
# from langchain_openai import AzureChatOpenAI
# llm = AzureChatOpenAI(
#     azure_deployment=os.getenv("AZURE_OPENAI_DEPLOYMENT_NAME"),
#     azure_endpoint=os.getenv("AZURE_OPENAI_ENDPOINT"),
#     api_key=os.getenv("AZURE_OPENAI_API_KEY"),
#     api_version=os.getenv("AZURE_OPENAI_API_VERSION", "2024-02-01"),
#     temperature=0,
# )


# ─────────────────────────────────────────────────────────────────────────────
#  NODE 1 — collect_metrics_node
# ─────────────────────────────────────────────────────────────────────────────

def collect_metrics_node(state: AgentState) -> dict:
    logger.info("Collecting real system metrics from all tools...")

    raw_metrics = {}

    tools_to_run = [
        ("cpu",       get_cpu_metrics),
        ("memory",    get_memory_metrics),
        ("disk",      get_disk_metrics),
        ("network",   get_network_metrics),
        ("processes", get_top_processes),
    ]

    for name, tool_fn in tools_to_run:
        try:
            result = tool_fn.invoke({})
            raw_metrics[name] = result
            logger.info(f"Tool '{name}' collected successfully")
        except Exception as e:
            error_msg = f"Tool '{name}' failed: {str(e)}"
            logger.error(error_msg)
            raw_metrics[name] = {"error": error_msg}

    logger.info("All tools executed — real metrics collected")
    return {
        "raw_metrics": raw_metrics,
        "check_timestamp": datetime.datetime.now().isoformat()
    }


# ─────────────────────────────────────────────────────────────────────────────
#  NODE 2 — check_patch_status_node  ⭐ NEW
#
#  Checks whether the local OS has any outstanding patches by calling
#  check_os_patch_status. This runs independently of the LLM — it's a
#  pure data-collection step, same pattern as collect_metrics_node.
#  Runs after metrics collection and before the LLM analysis step.
# ─────────────────────────────────────────────────────────────────────────────

def check_patch_status_node(state: AgentState) -> dict:
    logger.info("Checking OS patch status...")

    try:
        result = check_os_patch_status.invoke({})
        logger.info(
            f"Patch check complete — OS: {result.get('mapped_os_label')} | "
            f"Outstanding: {result.get('patches_outstanding', 0)} | "
            f"Highest severity: {result.get('highest_severity')}"
        )
    except Exception as e:
        error_msg = f"Patch status check failed: {str(e)}"
        logger.error(error_msg)
        result = {
            "patches_outstanding": 0,
            "outstanding_patches": [],
            "highest_severity": "none",
            "patch_action_needed": False,
            "load_error": error_msg,
        }

    return {"patch_status": result}


# ─────────────────────────────────────────────────────────────────────────────
#  NODE 3 — analyse_metrics_node
# ─────────────────────────────────────────────────────────────────────────────

def analyse_metrics_node(state: AgentState) -> dict:
    logger.info("Sending real metrics to LLM for analysis...")

    raw_metrics = state.get("raw_metrics", {})

    analysis_prompt = f"""
You have been given the following REAL infrastructure metrics collected right now
from the live system. These are actual values — do not estimate or change them.

═══════════════════════════════════════════════════════════
REAL COLLECTED METRICS
═══════════════════════════════════════════════════════════

CPU METRICS:
{json.dumps(raw_metrics.get("cpu", {}), indent=2)}

MEMORY METRICS:
{json.dumps(raw_metrics.get("memory", {}), indent=2)}

DISK METRICS:
{json.dumps(raw_metrics.get("disk", {}), indent=2)}

NETWORK METRICS:
{json.dumps(raw_metrics.get("network", {}), indent=2)}

TOP PROCESSES:
{json.dumps(raw_metrics.get("processes", {}), indent=2)}

═══════════════════════════════════════════════════════════

Using ONLY the real values above, produce the full structured
Infrastructure Health Report exactly as specified in your instructions.
Use the actual numbers from the metrics above — do not use placeholder
or example values under any circumstances.
"""

    messages = [
        SystemMessage(content=INFRA_MONITORING_SYSTEM_PROMPT),
        HumanMessage(content=analysis_prompt)
    ]

    try:
        response = llm.invoke(messages)
        logger.info("LLM analysis complete")
        return {"messages": [response]}

    except Exception as e:
        error_msg = f"LLM analysis failed: {str(e)}"
        logger.error(error_msg)
        return {
            "messages": [AIMessage(content=f"ERROR: {error_msg}")],
            "error": error_msg
        }


# ─────────────────────────────────────────────────────────────────────────────
#  NODE 4 — parse_output_node
# ─────────────────────────────────────────────────────────────────────────────

def parse_output_node(state: AgentState) -> dict:
    logger.info("Parsing agent output for escalation decision")

    final_report = ""
    for message in reversed(state["messages"]):
        if isinstance(message, AIMessage) and message.content:
            final_report = message.content
            break

    if not final_report:
        logger.warning("No final report found in messages")
        return {
            "escalate": False,
            "severity": "UNKNOWN",
            "overall_status": "UNKNOWN",
            "report": "No report generated",
            "check_timestamp": datetime.datetime.now().isoformat(),
            "error": "Agent produced no output"
        }

    report_upper = final_report.upper()

    escalate = "ESCALATE: YES" in report_upper

    if "CRITICAL" in report_upper:
        severity = "CRITICAL"
    elif "HIGH" in report_upper:
        severity = "HIGH"
    elif "MEDIUM" in report_upper:
        severity = "MEDIUM"
    else:
        severity = "LOW"

    if "OVERALL STATUS:** CRITICAL" in report_upper or escalate:
        overall_status = "CRITICAL"
    elif "OVERALL STATUS:** WARNING" in report_upper or severity in ["HIGH", "MEDIUM"]:
        overall_status = "WARNING"
    else:
        overall_status = "HEALTHY"

    logger.info(
        f"Parsed — Severity: {severity} | "
        f"Overall: {overall_status} | "
        f"Escalate: {escalate}"
    )

    # ── Feature 1: Wire memory — save every run to long-term storage ─────────
    try:
        from infra_monitoring.agent.memory import (
            save_health_report, save_escalation_event, save_metric_snapshot
        )

        raw = state.get("raw_metrics", {})
        cpu_val = raw.get("cpu", {}).get("cpu_percent_overall", 0.0) or 0.0
        mem_val = raw.get("memory", {}).get("ram", {}).get("percent_used", 0.0) or 0.0
        disk_parts = raw.get("disk", {}).get("partitions", [])
        disk_max = max((p.get("percent_used", 0) for p in disk_parts), default=0.0)
        net = raw.get("network", {}).get("overall", {})
        net_errors = (net.get("errors_in", 0) or 0) + (net.get("errors_out", 0) or 0)

        report_id = save_health_report(
            report=final_report,
            severity=severity,
            overall_status=overall_status,
            escalated=escalate,
            check_timestamp=datetime.datetime.now().isoformat(),
        )

        save_metric_snapshot(
            cpu_percent=cpu_val,
            memory_percent=mem_val,
            disk_percent_max=disk_max,
            network_errors=net_errors,
            check_timestamp=datetime.datetime.now().isoformat(),
        )

        if escalate:
            save_escalation_event(
                report_id=report_id,
                severity=severity,
                reason=f"Severity {severity} detected — escalation triggered",
                affected_resource=severity,
                check_timestamp=datetime.datetime.now().isoformat(),
            )

        logger.info(f"Memory saved — report_id: {report_id}")

    except Exception as mem_err:
        logger.warning(f"Memory save failed (non-critical): {mem_err}")

    return {
        "escalate": escalate,
        "severity": severity,
        "overall_status": overall_status,
        "report": final_report,
        "check_timestamp": datetime.datetime.now().isoformat(),
        "error": state.get("error", "")
    }


# ─────────────────────────────────────────────────────────────────────────────
#  BUILD THE GRAPH
# ─────────────────────────────────────────────────────────────────────────────

def build_infra_agent_graph():
    builder = StateGraph(AgentState)

    builder.add_node("collect_metrics",     collect_metrics_node)
    builder.add_node("check_patch_status",  check_patch_status_node)   # ⭐ NEW
    builder.add_node("analyse_metrics",     analyse_metrics_node)
    builder.add_node("parse",               parse_output_node)

    builder.set_entry_point("collect_metrics")
    builder.add_edge("collect_metrics", "check_patch_status")          # ⭐ NEW
    builder.add_edge("check_patch_status", "analyse_metrics")          # ⭐ NEW
    builder.add_edge("analyse_metrics", "parse")
    builder.add_edge("parse", END)

    logger.info("Infra agent graph compiled successfully (with patch status check)")
    return builder.compile()


# ─────────────────────────────────────────────────────────────────────────────
#  COMPILED AGENT
# ─────────────────────────────────────────────────────────────────────────────

infra_agent = build_infra_agent_graph()


# ─────────────────────────────────────────────────────────────────────────────
#  RUN AND ESCALATE — called by main.py
# ─────────────────────────────────────────────────────────────────────────────

def run_and_escalate(result: dict = None):
    """
    Runs the escalation pipeline (incident escalation + patch escalation).

    Args:
        result: Optional — a pre-computed agent result (e.g. from
                infra_agent.invoke() already run by main.py's
                run_single_check()). If not provided, invokes the agent
                fresh. This avoids running the LLM twice when main.py
                already has a result it can pass in.
    """
    from oura_router import oura_receive as route_event    # ⭐ CHANGED — now routes through OURA

    if result is None:
        logger.info("Running Infra Monitoring Agent...")
        result = infra_agent.invoke({"messages": []})
    else:
        logger.info("Reusing already-computed agent result — skipping duplicate LLM call")

    # ── NEW: Patch escalation — independent of the health-metric escalation ──
    # This runs BEFORE the "system healthy, no incident" early return below,
    # because a missing patch on an otherwise healthy server is still worth
    # flagging on its own, separate from CPU/memory/disk health.
    try:
        patch_status = result.get("patch_status", {})
        outstanding = patch_status.get("outstanding_patches", [])

        # Only escalate for critical or important severity patches — moderate/low
        # patches follow the normal scheduled maintenance cycle and don't need
        # an urgent agent-to-agent handoff.
        urgent_patches = [
            p for p in outstanding
            if p.get("severity") in ("critical", "important")
        ]

        if urgent_patches:
            top_patch = urgent_patches[0]  # already sorted critical-first
            patch_severity_map = {"critical": "P1", "important": "P2"}
            patch_p_level = patch_severity_map.get(top_patch["severity"], "P3")

            patch_event = AIOpsEvent(
                event_type="patch_needed",
                source_agent="infra_monitoring",
                severity=patch_p_level,
                target_host=os.getenv("HOSTNAME", "local-host"),
                target_service="os-patching",
                alert_title=(
                    f"{len(urgent_patches)} outstanding patch(es) detected on "
                    f"{patch_status.get('mapped_os_label', 'unknown OS')} "
                    f"(highest: {top_patch['patch_id']}, {top_patch['severity']})"
                ),
                alert_description=(
                    f"OS detected: {patch_status.get('mapped_os_label')}\n"
                    f"Outstanding patches: {len(outstanding)}\n"
                    f"Most urgent: {top_patch['patch_id']} — {top_patch['title']}\n"
                    f"Severity: {top_patch['severity']} | CVE score: {top_patch['cve_score']}\n"
                    f"CVE IDs: {', '.join(top_patch.get('cve_ids', []))}"
                ),
                metrics=MetricsSnapshot(extra={"patches_outstanding": len(outstanding)}),
                environment="production",
            )

            logger.info(
                f"Patch escalation — {len(urgent_patches)} urgent patch(es) found. "
                f"Routing patch_needed event."
            )

            patch_resolved_event = route_event(patch_event)
            logger.info(
                f"Patch event resolution status: {patch_resolved_event.resolution_status}"
            )

    except Exception as patch_escalation_error:
        logger.warning(
            f"Patch escalation failed (non-critical): {patch_escalation_error}"
        )

    # ── Feature 3: Recurring incident detection ───────────────────────────────
    try:
        from infra_monitoring.agent.memory import get_escalation_count
        recent = get_escalation_count(hours=2)
        recurring = recent.get("count", 0) >= 3
        if recurring:
            logger.warning(
                f"RECURRING INCIDENT — {recent['count']} escalations in last 2 hours"
            )
    except Exception:
        recurring = False
        recent = {"count": 0}

    if not result.get("escalate", False):
        logger.info(f"System healthy — Status: {result.get('overall_status')}")
        print(f"\n[Infra Monitoring] System is HEALTHY. No incidents to resolve.")
        return None

    severity_map = {
        "CRITICAL": "P1",
        "HIGH":     "P2",
        "MEDIUM":   "P3",
        "LOW":      "P4",
    }
    p_level = severity_map.get(result.get("severity", "LOW"), "P3")

    raw     = result.get("raw_metrics", {})
    cpu     = raw.get("cpu", {})
    memory  = raw.get("memory", {})
    disk    = raw.get("disk", {})
    network = raw.get("network", {})

    metrics = MetricsSnapshot(
        cpu_percent=cpu.get("cpu_percent_overall"),
        memory_percent=memory.get("ram", {}).get("percent_used"),
        disk_percent=max(
            (p.get("percent_used", 0) for p in disk.get("partitions", [])),
            default=None
        ),
        network_latency_ms=None,
    )

    # ── Feature 2: Extract specific breaching metric for better context ───────
    report_text = result.get("report", "")
    report_upper = report_text.upper()

    if "CPU" in report_upper and ("CRITICAL" in report_upper or "HIGH" in report_upper):
        breaching_metric = "CPU"
        target_service = "system-cpu"
    elif "MEMORY" in report_upper and ("CRITICAL" in report_upper or "HIGH" in report_upper):
        breaching_metric = "Memory"
        target_service = "system-memory"
    elif "DISK" in report_upper and "CRITICAL" in report_upper:
        breaching_metric = "Disk"
        target_service = "system-disk"
    elif "NETWORK" in report_upper and ("CRITICAL" in report_upper or "HIGH" in report_upper):
        breaching_metric = "Network"
        target_service = "system-network"
    else:
        breaching_metric = "System"
        target_service = "system"

    cpu_val = cpu.get("cpu_percent_overall", "unknown")
    mem_val = memory.get("ram", {}).get("percent_used", "unknown")
    disk_parts = disk.get("partitions", [])
    disk_max = max((p.get("percent_used", 0) for p in disk_parts), default=0)

    structured_description = (
        f"BREACHING METRIC: {breaching_metric}\n"
        f"CPU: {cpu_val}% | Memory: {mem_val}% | Disk(max): {disk_max}%\n"
        f"Severity: {result.get('severity')} | Status: {result.get('overall_status')}\n\n"
        f"FULL REPORT EXCERPT:\n{report_text[:1000]}"
    )

    alert_title = f"{breaching_metric} {result.get('severity')} on {os.getenv('HOSTNAME', 'local-host')}"

    # Feature 3 cont — flag recurring in title and force P1
    if recurring:
        alert_title = f"[RECURRING x{recent['count']}] {alert_title}"
        p_level = "P1"

    event = AIOpsEvent(
        event_type="incident",
        source_agent="infra_monitoring",
        severity=p_level,
        target_host=os.getenv("HOSTNAME", "local-host"),
        target_service=target_service,
        alert_title=alert_title,
        alert_description=structured_description,
        metrics=metrics,
        environment="production",
    )

    logger.info(f"Escalating to APP Orchestrator — Severity: {p_level}")
    resolved_event = route_event(event)

    logger.info(f"Incident resolved — Status: {resolved_event.resolution_status}")
    return resolved_event