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
        print("[APP Orchestrator] Patch Manager not built yet — queuing for human.")
        event.resolution_status = "escalated_to_human"
        return event

    else:
        print(f"[APP Orchestrator] Unknown event type: {event.event_type}")
        event.resolution_status = "escalated_to_human"
        return event