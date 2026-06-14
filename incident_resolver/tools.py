from incident_resolver.knowledge_base import query_knowledge_base
from shared.event_schema import AIOpsEvent
from datetime import datetime
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from executor.executor_factory import get_executor


def search_runbooks(query: str) -> str:
    results = query_knowledge_base(query, n_results=3)

    if not results:
        return "No relevant runbooks found in the knowledge base for this query."

    output = f"Found {len(results)} relevant runbook(s):\n\n"
    for r in results:
        output += f"── {r['title']} (relevance: {r['score']}) ──\n"
        output += f"{r['content']}\n\n"

    return output


def execute_remediation_action(action: str, host: str, service: str = None) -> str:
    """
    Extracts the shell command from the LLM's response and runs it
    via the executor (local subprocess or SSH depending on config).
    """
    timestamp = datetime.utcnow().isoformat()

    # --- Extract the COMMAND line from LLM output ---
    command = None
    for line in action.splitlines():
        if line.strip().upper().startswith("COMMAND:"):
            command = line.strip()[len("COMMAND:"):].strip()
            break

    # If LLM didn't follow the format, log it and skip execution
    if not command:
        print(f"  [EXECUTOR] [{timestamp}] No COMMAND line found in LLM output. Skipping execution.")
        print(f"  [EXECUTOR] Raw LLM output was:\n{action[:300]}")
        return "WARNING: No executable command was extracted from the LLM response. No action taken."

    print(f"  [EXECUTOR] [{timestamp}] Running command on {host}: {command}")

    # --- Run the command via executor ---
    executor = get_executor()
    result = executor.execute(command)

    # --- Format the result for the agent ---
    if result["success"]:
        output = f"SUCCESS: Command executed on {host}.\n"
        output += f"Command : {result['command']}\n"
        output += f"Output  : {result['stdout'] or '(no output)'}\n"
    else:
        output = f"FAILED: Command execution failed on {host}.\n"
        output += f"Command : {result['command']}\n"
        output += f"Error   : {result['stderr'] or '(no error message)'}\n"
        output += f"Code    : {result['return_code']}\n"

    return output


def escalate_to_human(event: AIOpsEvent, reason: str) -> str:
    """
    RIGHT NOW: Prints a formatted escalation notice.
    LATER: POST to PagerDuty, ServiceNow, or Slack.
    """
    notice = f"""
╔══════════════════════════════════════════════════════╗
║           ESCALATION TO HUMAN OPERATOR               ║
╠══════════════════════════════════════════════════════╣
║ Event ID : {event.event_id[:8]}...
║ Host     : {event.target_host}
║ Severity : {event.severity}
║ Alert    : {event.alert_title}
║ Reason   : {reason}
║ Time     : {datetime.utcnow().isoformat()}
╚══════════════════════════════════════════════════════╝
    """
    print(notice)
    return f"Escalation triggered. Human operator notified. Reason: {reason}"