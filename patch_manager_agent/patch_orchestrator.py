"""
patch_orchestrator.py
=====================
The routing layer that sits between the APP Orchestrator (or OURA)
and the Patch Manager Agent.

In the full AIOps system, events flow like this:
  OURA → APP Orchestrator → [this file] → Patch Manager Agent

This module:
  1. Receives structured event payloads (from OURA / APP Orchestrator)
  2. Classifies the event to determine which patch task type to run
  3. Extracts parameters from the event
  4. Calls the Patch Manager Agent with the right task
  5. Returns structured results back up the chain

You can also call this module directly from the CLI or from test scripts.
"""

import json
from datetime import datetime
from typing import Optional

from patch_agent import run_patch_agent


# ─────────────────────────────────────────────
#  EVENT SCHEMA
#  Defines what an incoming patch event looks like.
#  OURA / APP Orchestrator will send events in this format.
# ─────────────────────────────────────────────

def create_patch_event(
    event_type: str,
    source: str = "manual",
    priority: str = "standard",
    hostname: Optional[str] = None,
    patch_id: Optional[str] = None,
    description: str = "",
    metadata: Optional[dict] = None,
) -> dict:
    """
    Creates a standardised patch event payload.

    Args:
        event_type: Type of patch event. One of:
                    'patch_scan_requested'
                    'patch_all_servers'
                    'patch_specific_server'
                    'patch_compliance_check'
                    'patch_history_request'
                    'emergency_patch_required'
                    'critical_vulnerability_detected'
        source: Where this event came from ('oura', 'app_orchestrator', 'infra_monitoring', 'manual', 'scheduler')
        priority: 'standard', 'high', 'critical', 'emergency'
        hostname: Optional — target server for server-specific events
        patch_id: Optional — specific patch ID for targeted patching
        description: Human-readable description of why this event was triggered
        metadata: Any additional data to pass to the agent

    Returns:
        A standardised event dict
    """
    return {
        "event_id": f"PATCH-{datetime.now().strftime('%Y%m%d%H%M%S%f')[:18]}",
        "event_type": event_type,
        "source": source,
        "priority": priority,
        "hostname": hostname,
        "patch_id": patch_id,
        "description": description,
        "metadata": metadata or {},
        "timestamp": datetime.now().isoformat(),
        "agent_target": "patch_manager",
    }


# ─────────────────────────────────────────────
#  EVENT CLASSIFIER
#  Maps incoming event types to agent task types.
# ─────────────────────────────────────────────

# Maps event_type → (task_type, requires_approval_in_description)
EVENT_TO_TASK_MAP = {
    "patch_scan_requested":          ("scan",              False),
    "patch_all_servers":             ("patch_all",         True),
    "patch_specific_server":         ("patch_server",      True),
    "patch_compliance_check":        ("compliance_report", False),
    "patch_history_request":         ("patch_history",     False),
    "emergency_patch_required":      ("emergency_patch",   False),  # Emergency bypasses normal approval
    "critical_vulnerability_detected": ("emergency_patch", False),
    "scheduled_patch_cycle":         ("patch_all",         True),
    "vulnerability_scan_complete":   ("scan",              False),
}


def classify_event(event: dict) -> dict:
    """
    Takes an incoming event and returns the task type and parameters
    that the Patch Manager Agent needs to run.

    Returns:
        dict with:
          - task_type: str
          - task_input: dict
          - test_mode: bool
          - force_approved: bool
          - classification_notes: str
    """
    event_type = event.get("event_type", "patch_scan_requested")
    priority = event.get("priority", "standard")
    hostname = event.get("hostname")
    metadata = event.get("metadata", {})

    # Get base task mapping
    task_type, _ = EVENT_TO_TASK_MAP.get(
        event_type, ("scan", False)
    )

    # Build task input from event data
    task_input = {}
    if hostname:
        task_input["hostname"] = hostname.upper()
    if event.get("patch_id"):
        task_input["patch_id"] = event["patch_id"]
    if metadata.get("filter_severity"):
        task_input["filter_severity"] = metadata["filter_severity"]

    # Determine approval and test mode from priority and metadata
    is_test_mode = metadata.get("test_mode", False)
    is_force_approved = metadata.get("force_approved", False)

    # Emergency events get fast-tracked
    if priority in ("emergency", "critical") or event_type in (
        "emergency_patch_required", "critical_vulnerability_detected"
    ):
        task_type = "emergency_patch"
        is_force_approved = True  # Emergency patches bypass standard approval

    notes = (
        f"Event '{event_type}' classified as task '{task_type}'. "
        f"Priority: {priority}. "
        f"Test mode: {is_test_mode}. "
        f"Force approved: {is_force_approved}."
    )

    return {
        "task_type": task_type,
        "task_input": task_input,
        "test_mode": is_test_mode,
        "force_approved": is_force_approved,
        "classification_notes": notes,
    }


# ─────────────────────────────────────────────
#  MAIN ROUTING FUNCTION
#  This is what OURA / APP Orchestrator calls.
# ─────────────────────────────────────────────

def route_to_patch_agent(event: dict) -> dict:
    """
    Main entry point for the routing layer.
    Receives an event, classifies it, and dispatches to the patch agent.

    Args:
        event: A standardised patch event dict (from create_patch_event)

    Returns:
        dict with:
          - event_id: original event ID
          - task_type: what was run
          - agent_status: 'complete', 'awaiting_approval', 'error'
          - patches_applied: int
          - patches_failed: int
          - final_report: str (the agent's final report)
          - routing_metadata: classification info and timing
    """
    start_time = datetime.now()
    event_id = event.get("event_id", "UNKNOWN")

    print(f"\n{'='*70}")
    print(f"PATCH ORCHESTRATOR — Routing event: {event_id}")
    print(f"Event type: {event.get('event_type')}")
    print(f"Source: {event.get('source')}")
    print(f"Priority: {event.get('priority')}")
    print(f"{'='*70}")

    # Step 1: Classify the event
    classification = classify_event(event)
    print(f"\nClassification: {classification['classification_notes']}")

    # Step 2: Run the patch agent
    try:
        agent_result = run_patch_agent(
            task_type=classification["task_type"],
            task_input=classification["task_input"],
            test_mode=classification["test_mode"],
            force_approved=classification["force_approved"],
        )

        # Step 3: Build the routing response
        end_time = datetime.now()
        duration_seconds = (end_time - start_time).total_seconds()

        response = {
            "event_id": event_id,
            "event_type": event.get("event_type"),
            "task_type": classification["task_type"],
            "agent_status": agent_result.get("agent_status", "unknown"),
            "patches_applied": agent_result.get("patches_applied", 0),
            "patches_failed": agent_result.get("patches_failed", 0),
            "patches_rolled_back": agent_result.get("patches_rolled_back", 0),
            "final_report": agent_result.get("final_report", "No report generated"),
            "error_message": agent_result.get("error_message"),
            "routing_metadata": {
                "source": event.get("source"),
                "priority": event.get("priority"),
                "classification": classification["classification_notes"],
                "duration_seconds": round(duration_seconds, 2),
                "completed_at": end_time.isoformat(),
            },
        }

        print(f"\n{'='*70}")
        print(f"ROUTING COMPLETE — Event {event_id}")
        print(f"Status: {response['agent_status']}")
        print(f"Duration: {duration_seconds:.1f} seconds")
        print(f"{'='*70}\n")

        return response

    except Exception as e:
        print(f"[ORCHESTRATOR ERROR] {e}")
        return {
            "event_id": event_id,
            "task_type": classification.get("task_type", "unknown"),
            "agent_status": "error",
            "error_message": str(e),
            "patches_applied": 0,
            "patches_failed": 0,
            "patches_rolled_back": 0,
            "final_report": f"Agent execution failed: {str(e)}",
        }


# ─────────────────────────────────────────────
#  CONVENIENCE FUNCTIONS
#  Short-cut callers for the most common events.
#  These are what you'd call from scripts or
#  from other agents that need to trigger patching.
# ─────────────────────────────────────────────

def trigger_patch_scan(test_mode: bool = True) -> dict:
    """Triggers a full patch inventory scan across all servers."""
    event = create_patch_event(
        event_type="patch_scan_requested",
        source="manual",
        priority="standard",
        description="Manual patch scan requested",
        metadata={"test_mode": test_mode},
    )
    return route_to_patch_agent(event)


def trigger_patch_all(test_mode: bool = True, force_approved: bool = False) -> dict:
    """Triggers a full patching run across all servers."""
    event = create_patch_event(
        event_type="patch_all_servers",
        source="scheduler",
        priority="standard",
        description="Scheduled monthly patch cycle",
        metadata={"test_mode": test_mode, "force_approved": force_approved},
    )
    return route_to_patch_agent(event)


def trigger_patch_server(
    hostname: str,
    test_mode: bool = True,
    force_approved: bool = False,
) -> dict:
    """Triggers patching of a specific server."""
    event = create_patch_event(
        event_type="patch_specific_server",
        source="manual",
        priority="standard",
        hostname=hostname,
        description=f"Targeted patch request for {hostname}",
        metadata={"test_mode": test_mode, "force_approved": force_approved},
    )
    return route_to_patch_agent(event)


def trigger_compliance_check(test_mode: bool = True) -> dict:
    """Triggers a compliance report across the fleet."""
    event = create_patch_event(
        event_type="patch_compliance_check",
        source="manual",
        priority="standard",
        description="Monthly compliance check",
        metadata={"test_mode": test_mode},
    )
    return route_to_patch_agent(event)


def trigger_emergency_patch(
    description: str = "Critical zero-day vulnerability detected",
    hostname: Optional[str] = None,
) -> dict:
    """Triggers an emergency patch run — bypasses standard approval."""
    event = create_patch_event(
        event_type="emergency_patch_required",
        source="vulnerability_scanner",
        priority="emergency",
        hostname=hostname,
        description=description,
        metadata={"test_mode": False, "force_approved": True},  # Emergency = live + approved
    )
    return route_to_patch_agent(event)


def trigger_patch_history(hostname: str, test_mode: bool = True) -> dict:
    """Retrieves the patch history for a specific server."""
    event = create_patch_event(
        event_type="patch_history_request",
        source="manual",
        priority="standard",
        hostname=hostname,
        description=f"Patch history requested for {hostname}",
        metadata={"test_mode": test_mode},
    )
    return route_to_patch_agent(event)


# ─────────────────────────────────────────────
#  DIRECT INVOCATION
# ─────────────────────────────────────────────

if __name__ == "__main__":
    print("Patch Orchestrator — Direct invocation")
    print("Running a patch scan in test mode...\n")
    result = trigger_patch_scan(test_mode=True)
    print(f"\nFinal status: {result['agent_status']}")