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
        print("[APP Orchestrator] Routing to → Patch Manager Agent")
        return run_patch_manager_for_event(event)

    else:
        print(f"[APP Orchestrator] Unknown event type: {event.event_type}")
        event.resolution_status = "escalated_to_human"
        return event


# ─────────────────────────────────────────────────────────────────────────────
#  NEW FUNCTION — run_patch_manager_for_event
#
#  Bridges an incoming AIOpsEvent (patch_needed) to the Patch Manager
#  Agent's existing orchestrator (patch_orchestrator.py), then translates
#  the Patch Manager's result back into the AIOpsEvent shape so the rest
#  of the system (logging, hop counting, resolution_status) works exactly
#  the same as it does for incidents.
#
#  This function does NOT change anything inside patch_manager_agent —
#  it only adapts between the two event formats.
#
#  ⭐ UPDATED: Now also runs the same explicit knowledge-base check that
#  the manual patch_receiver.py path does — "has this patch been seen
#  before, what happened last time" — before dispatching to the agent.
#  This closes the gap where the automated path skipped straight to
#  analysis without first checking institutional memory, unlike the
#  manual path which always shows this to the operator.
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
    from patch_inventory import SERVER_REGISTRY, AVAILABLE_PATCHES

    print(f"[APP Orchestrator] Patch target host: {event.target_host}")
    print(f"[APP Orchestrator] Severity: {event.severity}")

    # ── ⭐ NEW: Explicit knowledge-base check, same as the manual path ──────
    # We try to identify which specific patch triggered this event so we
    # can look it up. Infra Monitoring's alert_title includes the patch
    # ID (e.g. "...highest: KB5034441, critical)"), so we extract it from
    # there. If we can't identify a specific patch ID, we skip this step
    # gracefully — the rest of the flow is unaffected either way.
    kb_summary_note = ""
    try:
        from patch_receiver import check_kb_for_patch

        # Try to find a known patch_id mentioned in the alert title
        matched_patch = None
        for candidate in AVAILABLE_PATCHES:
            if candidate["patch_id"] in event.alert_title:
                matched_patch = candidate
                break

        if matched_patch:
            print(f"[APP Orchestrator] Checking knowledge base for {matched_patch['patch_id']}...")
            kb_check = check_kb_for_patch(matched_patch)

            if kb_check["found"] or kb_check["past_deployment_count"] > 0:
                print(f"[APP Orchestrator] ✅ Patch found in knowledge base!")
                print(f"[APP Orchestrator] Recommendation: {kb_check['recommendation']}")
                print(f"[APP Orchestrator] Past deployments: {kb_check['past_deployment_count']}")
            else:
                print(f"[APP Orchestrator] 🆕 Patch not previously seen in knowledge base.")

            kb_summary_note = (
                f"KB check: {kb_check['recommendation']} "
                f"(past deployments: {kb_check['past_deployment_count']})"
            )
        else:
            print(f"[APP Orchestrator] Could not identify a specific known patch ID from alert title — "
                  f"skipping explicit KB lookup, proceeding to full analysis.")
            kb_summary_note = "No specific patch ID matched for KB lookup; proceeded directly to analysis."

    except Exception as kb_err:
        print(f"[APP Orchestrator] KB check skipped (non-critical): {kb_err}")
        kb_summary_note = "KB check skipped due to error."

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
            f"rolled back: {patch_result.get('patches_rolled_back', 0)}. "
            f"{kb_summary_note}"
        )

        print(f"[APP Orchestrator] Patch Manager result: {event.resolution_status}")
        print(f"[APP Orchestrator] {event.resolution_summary}")

    except Exception as e:
        print(f"[APP Orchestrator] Patch Manager invocation failed: {e}")
        event.resolution_status = "failed"
        event.resolution_summary = f"Patch Manager invocation error: {str(e)}"

    return event