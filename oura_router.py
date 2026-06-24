# ─────────────────────────────────────────────────────────────────────────────
#  oura_router.py
#
#  OURA — the master orchestrator for the AI-Powered Operation Lifecycle.
#
#  WHAT THIS IS RIGHT NOW (honest status):
#    A thin entry point that sits above app_orchestrator.py. Today, with
#    only Infra Monitoring, Incident Resolver, and Patch Manager built,
#    OURA's job is simple: receive an event from any agent, log it as the
#    system's single entry point, and hand it to app_orchestrator.py for
#    actual routing.
#
#    As more agents come online (Cost Optimizer, DevOps Deployer, ITSM
#    agents, etc.), OURA is where cross-cutting decisions move TO —
#    things like: which orchestrator should even see this event (APP
#    Orchestrator vs a future Common Orchestrator), global rate limiting,
#    cross-agent deduplication, and system-wide audit logging.
#
#    Right now there is only one orchestrator (APP Orchestrator), so OURA
#    routes everything there. This file exists so that distinction is
#    already in place architecturally — adding the Common Orchestrator
#    later means adding ONE branch here, not rewriting how agents call in.
#
#  WHY THIS MATTERS FOR THE DEMO:
#    Every agent-to-agent event in the system can now be shown as flowing
#    through ONE named entry point — OURA — exactly as described in the
#    system design. It is not a placeholder with no logic; it does real
#    logging, real event-history tracking, and real routing today.
# ─────────────────────────────────────────────────────────────────────────────

import json
import os
import datetime
from pathlib import Path

from shared.event_schema import AIOpsEvent
from app_orchestrator import route_event as route_to_app_orchestrator


# ─────────────────────────────────────────────────────────────────────────────
#  EVENT LOG
#  OURA keeps a running log of every event that has ever passed through
#  it, regardless of which agent raised it or which orchestrator handled
#  it. This is the system-wide audit trail your manager would expect from
#  a real master orchestrator.
# ─────────────────────────────────────────────────────────────────────────────

OURA_LOG_FILE = Path("oura_event_log.json")


def _load_log() -> list:
    if OURA_LOG_FILE.exists():
        with open(OURA_LOG_FILE, "r") as f:
            return json.load(f)
    return []


def _append_log(entry: dict):
    log = _load_log()
    log.append(entry)
    with open(OURA_LOG_FILE, "w") as f:
        json.dump(log, f, indent=2)


# ─────────────────────────────────────────────────────────────────────────────
#  MAIN ENTRY POINT — oura_receive
#
#  Every agent in the system should call THIS function (not
#  app_orchestrator.route_event directly) when it needs to hand off work.
#  This is the single front door of the AI-Powered Operation Lifecycle.
# ─────────────────────────────────────────────────────────────────────────────

def oura_receive(event: AIOpsEvent) -> AIOpsEvent:
    """
    The single entry point for all inter-agent events in the system.

    Currently routes every event to the APP Orchestrator, since that is
    the only orchestrator built so far. Logs every event — incoming and
    resolved — to oura_event_log.json for full audit visibility.
    """
    received_at = datetime.datetime.now().isoformat()

    print(f"\n{'='*70}")
    print(f"OURA — Master Orchestrator")
    print(f"Event received from: {event.source_agent}")
    print(f"Event type: {event.event_type} | Severity: {event.severity}")
    print(f"Title: {event.alert_title}")
    print(f"{'='*70}")

    # ── Routing decision ─────────────────────────────────────────────────
    # Today there is only one downstream orchestrator. This if/elif
    # structure is intentionally left in place (rather than a single
    # unconditional call) so that adding a Common Orchestrator later for
    # ITSM-side agents is a one-line addition here, not a redesign.
    if event.event_type in ("incident", "cost_alert", "patch_needed", "deploy_request"):
        print(f"[OURA] Routing decision: APP Orchestrator")
        resolved_event = route_to_app_orchestrator(event)
    else:
        print(f"[OURA] No orchestrator configured yet for event_type='{event.event_type}'. "
              f"Escalating to human queue.")
        event.resolution_status = "escalated_to_human"
        event.resolution_summary = f"No orchestrator available for event_type={event.event_type}"
        resolved_event = event

    # ── Log the full lifecycle of this event ────────────────────────────
    _append_log({
        "event_id": resolved_event.event_id,
        "received_at": received_at,
        "resolved_at": datetime.datetime.now().isoformat(),
        "source_agent": resolved_event.source_agent,
        "event_type": resolved_event.event_type,
        "severity": resolved_event.severity,
        "target_host": resolved_event.target_host,
        "alert_title": resolved_event.alert_title,
        "routing_hops": resolved_event.routing_hops,
        "resolution_status": resolved_event.resolution_status,
        "resolution_summary": resolved_event.resolution_summary,
    })

    print(f"\n[OURA] Event {resolved_event.event_id[:8]}... resolved: "
          f"{resolved_event.resolution_status}")
    print(f"[OURA] Logged to {OURA_LOG_FILE}")
    print(f"{'='*70}\n")

    return resolved_event


# ─────────────────────────────────────────────────────────────────────────────
#  CONVENIENCE — show_oura_log
#  Prints the full event history. Good for demoing to your manager —
#  shows every event that has ever flowed through the system end to end.
# ─────────────────────────────────────────────────────────────────────────────

def show_oura_log(last_n: int = 20):
    log = _load_log()

    if not log:
        print("\n[OURA] No events logged yet.")
        return

    print(f"\n{'='*90}")
    print(f"  OURA EVENT LOG — {len(log)} total events (showing last {min(last_n, len(log))})")
    print(f"{'='*90}")
    print(f"  {'TIME':<20} {'SOURCE':<18} {'TYPE':<14} {'SEV':<5} {'STATUS':<20} {'TITLE'}")
    print(f"  {'-'*20} {'-'*18} {'-'*14} {'-'*5} {'-'*20} {'-'*30}")

    for entry in log[-last_n:]:
        time_str = entry["received_at"][:19].replace("T", " ")
        title_short = entry["alert_title"][:40]
        print(
            f"  {time_str:<20} {entry['source_agent']:<18} {entry['event_type']:<14} "
            f"{entry['severity']:<5} {str(entry['resolution_status']):<20} {title_short}"
        )

    print(f"{'='*90}\n")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="OURA Master Orchestrator")
    parser.add_argument("--log", action="store_true", help="Show the OURA event log")
    args = parser.parse_args()

    if args.log:
        show_oura_log()
    else:
        print("OURA router is a library module — import oura_receive() from your agents.")
        print("Run with --log to view the event history.")
