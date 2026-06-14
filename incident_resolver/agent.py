from langchain_ollama import ChatOllama
from langchain_core.messages import SystemMessage, HumanMessage
from langgraph.graph import StateGraph, END
from typing import TypedDict, List, Annotated
import operator

from incident_resolver.prompts import INCIDENT_RESOLVER_SYSTEM_PROMPT
from incident_resolver.tools import search_runbooks, execute_remediation_action, escalate_to_human
from incident_resolver.knowledge_base import seed_knowledge_base
from shared.event_schema import AIOpsEvent


class IncidentResolverState(TypedDict):
    event: AIOpsEvent
    messages: Annotated[List, operator.add]
    runbooks_searched: bool
    action_taken: str
    resolution_status: str
    incident_summary: str


def get_llm():
    return ChatOllama(
        model="llama3.2",
        temperature=0.1,
        num_ctx=8192,
    )


def search_knowledge_node(state: IncidentResolverState) -> dict:
    event = state["event"]
    search_query = f"{event.alert_title} {event.alert_description} {event.target_service or ''}"
    print(f"\n[Incident Resolver] Searching knowledge base for: '{event.alert_title}'")

    runbook_results = search_runbooks(search_query)
    search_message = HumanMessage(
        content=f"Knowledge base search results for this incident:\n\n{runbook_results}"
    )

    return {
        "messages": [search_message],
        "runbooks_searched": True,
    }


def reason_and_plan_node(state: IncidentResolverState) -> dict:
    event = state["event"]
    llm = get_llm()

    system = SystemMessage(content=INCIDENT_RESOLVER_SYSTEM_PROMPT)

    incident_brief = HumanMessage(content=f"""
New incident assigned to you:

Event ID    : {event.event_id}
Severity    : {event.severity}
Host        : {event.target_host}
Service     : {event.target_service or 'Unknown'}
Environment : {event.environment}
Alert Title : {event.alert_title}
Description : {event.alert_description}
Metrics     : {event.metrics.model_dump() if event.metrics else 'No metrics provided'}
Routing Hops: {event.routing_hops}

Review the knowledge base results already retrieved, then decide on your resolution action.

IMPORTANT — You must end your response with exactly this format:
COMMAND: <the exact shell command to run on the target host>

If no command is needed, write:
COMMAND: echo "no_action_needed"

If human escalation is required, write:
ESCALATE_TO_HUMAN
and do NOT include a COMMAND line.

Example valid endings:
IMPORTANT — This agent is running on Windows. Use Windows-compatible commands only.
Windows command examples:
COMMAND: tasklist | findstr nginx
COMMAND: taskkill /F /IM nginx.exe
COMMAND: wmic cpu get loadpercentage
COMMAND: dir C:\\logs
COMMAND: powershell Get-Process | Sort-Object CPU -Descending | Select-Object -First 10a
""")

    all_messages = [system, incident_brief] + state.get("messages", [])

    print(f"[Incident Resolver] LLM reasoning about incident...")
    response = llm.invoke(all_messages)

    return {
        "messages": [response],
    }


def execute_action_node(state: IncidentResolverState) -> dict:
    event = state["event"]
    last_message = state["messages"][-1]
    llm_response = last_message.content if hasattr(last_message, "content") else str(last_message)

    print(f"[Incident Resolver] Executing resolution action...")

    # --- Check for escalation first ---
    if "ESCALATE_TO_HUMAN" in llm_response.upper():
        reason = "Agent determined human intervention is required."
        result = escalate_to_human(event, reason)
        return {
            "action_taken": "Escalated to human operator",
            "resolution_status": "escalated_to_human",
            "messages": [HumanMessage(content=f"Tool result: {result}")],
        }

    if event.routing_hops >= 3:
        reason = f"Maximum routing hops reached ({event.routing_hops}). Forcing human escalation."
        result = escalate_to_human(event, reason)
        return {
            "action_taken": "Forced escalation — max hops exceeded",
            "resolution_status": "escalated_to_human",
            "messages": [HumanMessage(content=f"Tool result: {result}")],
        }

    # --- Execute the real command ---
    action_result = execute_remediation_action(
        action=llm_response,
        host=event.target_host,
        service=event.target_service,
    )

    # --- Determine resolution status based on executor result ---
    if "SUCCESS" in action_result:
        resolution_status = "resolved"
    elif "WARNING" in action_result:
        resolution_status = "resolved_no_action"
    else:
        resolution_status = "execution_failed"

    return {
        "action_taken": action_result,
        "resolution_status": resolution_status,
        "messages": [HumanMessage(content=f"Tool result: {action_result}")],
    }


def summarise_node(state: IncidentResolverState) -> dict:
    llm = get_llm()

    summary_prompt = HumanMessage(content=f"""
The remediation action has been executed.
Result: {state.get('action_taken', 'N/A')}
Status: {state.get('resolution_status', 'unknown')}

Now write the final incident summary using the required format:
---INCIDENT SUMMARY---
Host: ...
Service: ...
Severity: ...
Root Cause: ...
Action Taken: ...
Status: RESOLVED or ESCALATED_TO_HUMAN
---END SUMMARY---
""")

    all_messages = (
        [SystemMessage(content=INCIDENT_RESOLVER_SYSTEM_PROMPT)]
        + state.get("messages", [])
        + [summary_prompt]
    )

    response = llm.invoke(all_messages)
    summary_text = response.content

    print(f"\n[Incident Resolver] ── INCIDENT COMPLETE ──")
    print(summary_text)

    return {
        "incident_summary": summary_text,
        "messages": [response],
    }


def build_incident_resolver_graph():
    graph = StateGraph(IncidentResolverState)

    graph.add_node("search_knowledge", search_knowledge_node)
    graph.add_node("reason_and_plan", reason_and_plan_node)
    graph.add_node("execute_action", execute_action_node)
    graph.add_node("summarise", summarise_node)

    graph.set_entry_point("search_knowledge")
    graph.add_edge("search_knowledge", "reason_and_plan")
    graph.add_edge("reason_and_plan", "execute_action")
    graph.add_edge("execute_action", "summarise")
    graph.add_edge("summarise", END)

    return graph.compile()


def run_incident_resolver(event: AIOpsEvent) -> AIOpsEvent:
    seed_knowledge_base()

    graph = build_incident_resolver_graph()

    initial_state: IncidentResolverState = {
        "event": event,
        "messages": [],
        "runbooks_searched": False,
        "action_taken": "",
        "resolution_status": "in_progress",
        "incident_summary": "",
    }

    final_state = graph.invoke(initial_state)

    event.resolution_status = final_state["resolution_status"]
    event.resolution_summary = final_state["incident_summary"]

    return event