# ─────────────────────────────────────────────────────────────────────────────
#  agent/graph.py
#
#  Infrastructure Monitoring Agent — LangGraph core.
#
#  Graph flow:
#  [START] → [collect_metrics_node] → [analyse_metrics_node] → [parse_output_node] → [END]
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
    get_top_processes
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
#  NODE 2 — analyse_metrics_node
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
#  NODE 3 — parse_output_node
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

    builder.add_node("collect_metrics", collect_metrics_node)
    builder.add_node("analyse_metrics", analyse_metrics_node)
    builder.add_node("parse",           parse_output_node)

    builder.set_entry_point("collect_metrics")
    builder.add_edge("collect_metrics", "analyse_metrics")
    builder.add_edge("analyse_metrics", "parse")
    builder.add_edge("parse", END)

    logger.info("Infra agent graph compiled successfully")
    return builder.compile()


# ─────────────────────────────────────────────────────────────────────────────
#  COMPILED AGENT
# ─────────────────────────────────────────────────────────────────────────────

infra_agent = build_infra_agent_graph()


# ─────────────────────────────────────────────────────────────────────────────
#  RUN AND ESCALATE — called by main.py
# ─────────────────────────────────────────────────────────────────────────────

def run_and_escalate():
    from app_orchestrator import route_event

    logger.info("Running Infra Monitoring Agent...")
    result = infra_agent.invoke({"messages": []})

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
        cpu_percent=cpu.get("cpu_percent"),
        memory_percent=memory.get("percent"),
        disk_percent=disk.get("percent"),
        network_latency_ms=network.get("latency_ms"),
    )

    event = AIOpsEvent(
        event_type="incident",
        source_agent="infra_monitoring",
        severity=p_level,
        target_host=os.getenv("HOSTNAME", "local-host"),
        target_service="system",
        alert_title=f"{result.get('overall_status')} detected by Infra Monitoring Agent",
        alert_description=result.get("report", "")[:2500],
        metrics=metrics,
        environment="production",
    )

    logger.info(f"Escalating to APP Orchestrator — Severity: {p_level}")
    resolved_event = route_event(event)

    logger.info(f"Incident resolved — Status: {resolved_event.resolution_status}")
    return resolved_event