from shared.event_schema import AIOpsEvent
from incident_resolver.agent import run_incident_resolver


def route_event(event: AIOpsEvent) -> AIOpsEvent:
    print(f"\n[APP Orchestrator] Received: {event.alert_title} ({event.severity})")
    print(f"[APP Orchestrator] Source: {event.source_agent} → Hops: {event.routing_hops}")

    event.routing_hops += 1

    if event.routing_hops > 3:
        print("[APP Orchestrator] WARNING: Max hops exceeded. Dropping to human queue.")
        event.resolution_status = "escalated_to_human"
        event.resolution_summary = "Max routing hops exceeded. Needs human review."
        return event

    if event.event_type == "incident":
        print(f"[APP Orchestrator] Routing to → Incident Resolver")
        return run_incident_resolver(event)

    elif event.event_type == "cost_alert":
        print("[APP Orchestrator] Cost Optimizer not built yet — queuing for human.")
        event.resolution_status = "escalated_to_human"
        return event

    elif event.event_type == "patch_needed":
        print("[APP Orchestrator] Routing to → Patch Manager Agent")     # ⭐ CHANGED
        return run_patch_manager_for_event(event)                        # ⭐ CHANGED

    else:
        print(f"[APP Orchestrator] Unknown event type: {event.event_type}")
        event.resolution_status = "escalated_to_human"
        return event


# ─────────────────────────────────────────────────────────────────────────────
#  NEW FUNCTION — run_patch_manager_for_event  ⭐ NEW
#
#  Bridges an incoming AIOpsEvent (patch_needed) to the Patch Manager
#  Agent's existing orchestrator (patch_orchestrator.py), then translates
#  the Patch Manager's result back into the AIOpsEvent shape so the rest
#  of the system (logging, hop counting, resolution_status) works exactly
#  the same as it does for incidents.
#
#  This function does NOT change anything inside patch_manager_agent —
#  it only adapts between the two event formats.
# ─────────────────────────────────────────────────────────────────────────────

def run_patch_manager_for_event(event: AIOpsEvent) -> AIOpsEvent:
    """
    Takes a patch_needed AIOpsEvent (raised by Infra Monitoring when it
    detects outstanding OS patches) and routes it to the Patch Manager
    Agent's orchestrator, then maps the result back onto the event.
    """
    import sys
    import os

    # Patch Manager Agent lives at the project root as a sibling folder.
    # We add BOTH the project root (so "patch_manager_agent.patch_orchestrator"
    # resolves) AND the patch_manager_agent folder itself (so that file's own
    # internal imports like "from patch_agent import ..." keep working
    # exactly as they did when run directly from inside that folder).
    project_root = os.path.dirname(__file__)
    patch_manager_dir = os.path.join(project_root, "patch_manager_agent")

    if project_root not in sys.path:
        sys.path.insert(0, project_root)
    if patch_manager_dir not in sys.path:
        sys.path.insert(0, patch_manager_dir)

    from patch_orchestrator import trigger_patch_server
    from patch_inventory import SERVER_REGISTRY

    print(f"[APP Orchestrator] Patch target host: {event.target_host}")
    print(f"[APP Orchestrator] Severity: {event.severity}")

    # Map P1/P2 severity to whether this should be force-approved.
    # P1 (critical, CVSS-driven emergency) proceeds immediately.
    # P2 (important) still goes through the normal approval gate.
    force_approved = event.severity == "P1"

    # The target_host on the AIOpsEvent is the local machine's hostname,
    # which won't match a server name in patch_manager_agent's simulated
    # SERVER_REGISTRY (e.g. "WEB-PROD-01"). For the local demo we map any
    # unrecognised host to a representative server so the existing Patch
    # Manager logic runs end-to-end. In production this mapping comes
    # from Azure Resource Graph (real hostname → real Azure resource ID).
    if event.target_host.upper() in SERVER_REGISTRY:
        target_server = event.target_host.upper()
    else:
        target_server = next(
            (h for h, s in SERVER_REGISTRY.items()
             if s["os_family"] == "windows" and s["environment"] == "production"),
            list(SERVER_REGISTRY.keys())[0],
        )
        print(
            f"[APP Orchestrator] Host '{event.target_host}' not in server registry — "
            f"using representative target '{target_server}' for this demo run."
        )

    try:
        patch_result = trigger_patch_server(
            hostname=target_server,
            test_mode=False,
            force_approved=force_approved,
        )

        agent_status = patch_result.get("agent_status", "unknown")

        if agent_status == "complete" and patch_result.get("patches_failed", 0) == 0:
            event.resolution_status = "resolved"
        elif agent_status == "awaiting_approval":
            event.resolution_status = "escalated_to_human"
        else:
            event.resolution_status = "failed"

        event.resolution_summary = (
            f"Patch Manager Agent ran task '{patch_result.get('task_type')}' "
            f"on {target_server}. Status: {agent_status}. "
            f"Patches applied: {patch_result.get('patches_applied', 0)}, "
            f"failed: {patch_result.get('patches_failed', 0)}, "
            f"rolled back: {patch_result.get('patches_rolled_back', 0)}."
        )

        print(f"[APP Orchestrator] Patch Manager result: {event.resolution_status}")
        print(f"[APP Orchestrator] {event.resolution_summary}")

    except Exception as e:
        print(f"[APP Orchestrator] Patch Manager invocation failed: {e}")
        event.resolution_status = "failed"
        event.resolution_summary = f"Patch Manager invocation error: {str(e)}"

    return event