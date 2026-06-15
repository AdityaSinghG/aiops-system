"""
patch_tools.py
==============
All tools available to the Patch Manager Agent.

These are the agent's "hands" — the actual actions it can take.
Each function is one tool. The agent decides which tools to call
and in what order based on the task it receives.

IMPORTANT — THE TWO-PHASE RULE:
Following the same pattern as Infra Monitoring Agent:
  Phase 1 (collect_data_node): Python calls these tools directly to gather real data
  Phase 2 (analyse_node): LLM receives the collected data and reasons over it

The LLM never calls these functions directly.
The graph nodes call them and pass results to the LLM as context.

AZURE SWAP:
  Each tool marked "AZURE SWAP" shows what to replace the local
  implementation with. The function signatures never change.
"""

import json
from datetime import datetime, timedelta
from typing import Optional

from patch_inventory import (
    get_server_inventory,
    get_available_patches,
    get_patch_history,
    get_unpatched_servers,
    get_server_details,
    simulate_patch_apply,
    simulate_health_check,
    simulate_rollback,
)
from patch_knowledge_base import (
    query_knowledge_base,
    store_patch_outcome,
    initialise_knowledge_base,
)


# ─────────────────────────────────────────────
#  TOOL 1: SCAN ALL SERVERS FOR PENDING PATCHES
# ─────────────────────────────────────────────

def tool_scan_patch_inventory(filter_severity: Optional[str] = None) -> dict:
    """
    Scans the entire server fleet and returns a full inventory of
    pending patches, sorted by priority (production + critical CVE first).

    Args:
        filter_severity: Optional filter — 'critical', 'important', 'moderate', 'low'
                         If None, returns all severities.

    Returns:
        dict with:
          - total_servers_with_patches: int
          - total_pending_patches: int
          - critical_patch_count: int
          - servers: list of servers with their pending patches
          - summary: human-readable summary string

    AZURE SWAP:
        Replace get_unpatched_servers() with:
        az rest --method get --url "https://management.azure.com/subscriptions/{sub}/
        providers/Microsoft.Maintenance/updates?api-version=2023-04-01"
    """
    print("[TOOL] Scanning all servers for pending patches...")

    unpatched = get_unpatched_servers()

    # Apply severity filter if requested
    if filter_severity:
        filtered = []
        for item in unpatched:
            filtered_patches = [
                p for p in item["pending_patches"]
                if p["severity"] == filter_severity
            ]
            if filtered_patches:
                filtered.append({**item, "pending_patches": filtered_patches})
        unpatched = filtered

    # Aggregate counts
    total_critical = sum(item["critical_count"] for item in unpatched)
    total_important = sum(item["important_count"] for item in unpatched)
    total_patches = sum(len(item["pending_patches"]) for item in unpatched)

    # Build clean output structure
    servers_output = []
    for item in unpatched:
        server = item["server"]
        servers_output.append({
            "hostname": server["hostname"],
            "role": server["role"],
            "os": server["os"],
            "environment": server["environment"],
            "criticality": server["criticality"],
            "last_patched": server["last_patched"],
            "days_since_patched": (
                datetime.now() - datetime.strptime(server["last_patched"], "%Y-%m-%d")
            ).days,
            "patch_group": server["patch_group"],
            "maintenance_window": server["maintenance_window"],
            "pending_patch_count": len(item["pending_patches"]),
            "critical_patches": item["critical_count"],
            "important_patches": item["important_count"],
            "highest_cve_score": item["highest_cve_score"],
            "pending_patches": [
                {
                    "patch_id": p["patch_id"],
                    "title": p["title"],
                    "severity": p["severity"],
                    "cve_score": p["cve_score"],
                    "cve_ids": p["cve_ids"],
                    "reboot_required": p["reboot_required"],
                    "estimated_duration_minutes": p["estimated_duration_minutes"],
                    "release_date": p["release_date"],
                }
                for p in item["pending_patches"]
            ],
        })

    # Build summary
    if total_critical > 0:
        urgency = "🔴 CRITICAL — Immediate action required"
    elif total_important > 0:
        urgency = "🟡 IMPORTANT — Action required within 14 days"
    else:
        urgency = "🟢 MODERATE/LOW — Schedule for next maintenance window"

    summary = (
        f"Found {len(servers_output)} servers with {total_patches} pending patches. "
        f"Critical: {total_critical}, Important: {total_important}. "
        f"Status: {urgency}"
    )

    result = {
        "scan_timestamp": datetime.now().isoformat(),
        "total_servers_with_patches": len(servers_output),
        "total_pending_patches": total_patches,
        "critical_patch_count": total_critical,
        "important_patch_count": total_important,
        "urgency_level": urgency,
        "servers": servers_output,
        "summary": summary,
    }

    print(f"[TOOL] Scan complete: {summary}")
    return result


# ─────────────────────────────────────────────
#  TOOL 2: BUILD PATCH SCHEDULE / DEPLOYMENT PLAN
# ─────────────────────────────────────────────

def tool_build_patch_schedule(scan_results: dict) -> dict:
    """
    Takes the output of tool_scan_patch_inventory and builds a
    detailed deployment schedule respecting batch ordering,
    maintenance windows, and priority rules.

    Args:
        scan_results: The dict returned by tool_scan_patch_inventory

    Returns:
        dict with:
          - deployment_plan: ordered list of batches
          - estimated_total_duration_hours: float
          - schedule_notes: list of important scheduling notes

    This function purely uses Python logic — no LLM needed.
    The LLM then reviews this plan and can modify it.
    """
    print("[TOOL] Building patch deployment schedule...")

    servers = scan_results.get("servers", [])

    # Group servers by batch
    batches = {"staging": [], "batch_a": [], "batch_b": [], "batch_c": []}
    for server in servers:
        group = server.get("patch_group", "batch_b")
        # Staging servers always go first regardless of their patch_group
        if server["environment"] == "staging":
            batches["staging"].append(server)
        elif group in batches:
            batches[group].append(server)
        else:
            batches["batch_b"].append(server)

    deployment_plan = []
    schedule_notes = []
    total_duration_hours = 0

    # Build each batch entry
    batch_order = [
        ("staging", "Staging Environment", "Anytime", "24 hours soak period required after staging"),
        ("batch_a", "Production Batch A (Lower-criticality)", "Sunday 02:00-06:00 UTC", "2 hour verification before Batch B"),
        ("batch_b", "Production Batch B (Secondary)", "Sunday 02:00-06:00 UTC", "2 hour verification before Batch C"),
        ("batch_c", "Production Batch C (Database Tier)", "Saturday 01:00-05:00 UTC", "Requires DBA sign-off before start"),
    ]

    for batch_key, batch_name, window, note in batch_order:
        batch_servers = batches.get(batch_key, [])
        if not batch_servers:
            continue

        # Calculate estimated duration for this batch
        # (longest single server determines batch duration since they can run in parallel)
        max_server_duration = 0
        for server in batch_servers:
            server_total_mins = sum(
                p["estimated_duration_minutes"] for p in server["pending_patches"]
            )
            if server["os_family"] == "windows" if "os_family" in server else True:
                server_total_mins += 20  # Windows reboot overhead
            else:
                server_total_mins += 10  # Linux reboot overhead
            max_server_duration = max(max_server_duration, server_total_mins)

        batch_duration_hours = max_server_duration / 60
        total_duration_hours += batch_duration_hours + 2  # +2 for post-batch verification

        # Find the most severe patch across all servers in this batch
        all_patches = [p for s in batch_servers for p in s["pending_patches"]]
        max_cve = max((p["cve_score"] for p in all_patches), default=0)
        has_critical = any(p["severity"] == "critical" for p in all_patches)
        needs_reboot = any(p["reboot_required"] for p in all_patches)

        deployment_plan.append({
            "batch": batch_key,
            "batch_name": batch_name,
            "maintenance_window": window,
            "server_count": len(batch_servers),
            "servers": [s["hostname"] for s in batch_servers],
            "highest_cve_score": max_cve,
            "has_critical_patches": has_critical,
            "reboot_required": needs_reboot,
            "estimated_duration_hours": round(batch_duration_hours, 1),
            "post_batch_verification_hours": 2,
            "prerequisite_note": note,
            "patches_in_batch": list({
                p["patch_id"] for s in batch_servers for p in s["pending_patches"]
            }),
        })

        if note:
            schedule_notes.append(f"[{batch_name}]: {note}")

    # Add additional notes for critical patches
    if scan_results.get("critical_patch_count", 0) > 0:
        schedule_notes.append(
            "⚠️  CRITICAL patches detected. Standard scheduling applies unless CVSS >= 9.0 "
            "in which case emergency procedure PB-014 may be required."
        )
        schedule_notes.append(
            "📋 Change manager notification required before production patching begins."
        )

    result = {
        "schedule_created_at": datetime.now().isoformat(),
        "deployment_plan": deployment_plan,
        "estimated_total_duration_hours": round(total_duration_hours, 1),
        "batch_count": len(deployment_plan),
        "schedule_notes": schedule_notes,
        "recommendation": (
            "Begin with staging environment patching. "
            f"Total estimated time: {round(total_duration_hours, 1)} hours across "
            f"{len(deployment_plan)} batches."
        ),
    }

    print(f"[TOOL] Schedule built: {len(deployment_plan)} batches, "
          f"~{round(total_duration_hours, 1)} hours total")
    return result


# ─────────────────────────────────────────────
#  TOOL 3: APPLY A PATCH TO A SPECIFIC SERVER
# ─────────────────────────────────────────────

def tool_apply_patch(hostname: str, patch_id: str, approved: bool = True) -> dict:
    """
    Applies a specific patch to a specific server.
    Always checks approval flag before proceeding on production servers.

    Args:
        hostname: The server to patch (e.g. 'WEB-PROD-01')
        patch_id: The patch to apply (e.g. 'KB5034441')
        approved: Whether human/change-manager approval has been confirmed.
                  Staging always proceeds. Production requires approved=True.

    Returns:
        dict with success/failure details and whether reboot is needed.

    AZURE SWAP:
        Replace simulate_patch_apply() with Azure Update Manager REST API:
        POST /subscriptions/{sub}/resourceGroups/{rg}/providers/
        Microsoft.Maintenance/maintenanceConfigurations/{config}/
        start?api-version=2023-04-01
    """
    print(f"[TOOL] Applying patch {patch_id} to {hostname}...")

    server = get_server_details(hostname)
    if not server:
        return {
            "success": False,
            "hostname": hostname,
            "patch_id": patch_id,
            "error": f"Server {hostname} not found in inventory",
        }

    # Enforce approval gate for production servers
    if server["environment"] == "production" and not approved:
        return {
            "success": False,
            "hostname": hostname,
            "patch_id": patch_id,
            "error": "Approval required for production server patching. "
                     "Set approved=True only after change manager confirmation.",
            "action_required": "Obtain change manager approval before proceeding",
        }

    # Check if auto_reboot_allowed constraint needs surfacing
    patches = get_available_patches(hostname)
    target_patch = next((p for p in patches if p["patch_id"] == patch_id), None)

    if target_patch and target_patch["reboot_required"] and not server["auto_reboot_allowed"]:
        return {
            "success": False,
            "hostname": hostname,
            "patch_id": patch_id,
            "error": f"{hostname} does not allow automatic reboots. "
                     "Manual DBA/operator reboot required after patch installation.",
            "action_required": "Notify DBA/operator to perform manual reboot after patch",
        }

    # Execute the patch
    result = simulate_patch_apply(hostname, patch_id)

    # Log outcome to knowledge base for future reference
    if result["success"]:
        store_patch_outcome(
            hostname=hostname,
            patch_id=patch_id,
            outcome="success",
            notes=f"Patch applied successfully. Reboot required: {result.get('reboot_required', False)}",
        )
    else:
        store_patch_outcome(
            hostname=hostname,
            patch_id=patch_id,
            outcome="failed",
            notes=result.get("error", "Unknown error"),
        )

    print(f"[TOOL] Patch {patch_id} on {hostname}: {'SUCCESS' if result['success'] else 'FAILED'}")
    return result


# ─────────────────────────────────────────────
#  TOOL 4: RUN POST-PATCH HEALTH CHECK
# ─────────────────────────────────────────────

def tool_run_health_check(hostname: str) -> dict:
    """
    Runs a comprehensive health check on a server after patching.
    Checks CPU, memory, disk, services, and ping response.

    Args:
        hostname: The server to health-check

    Returns:
        dict with healthy: bool and detailed metrics

    AZURE SWAP:
        Replace simulate_health_check() with Azure Monitor query:
        GET /subscriptions/{sub}/resourceGroups/{rg}/providers/
        Microsoft.Insights/metrics?metricnames=Percentage%20CPU,...
    """
    print(f"[TOOL] Running health check on {hostname}...")
    result = simulate_health_check(hostname)
    print(f"[TOOL] Health check {hostname}: {'HEALTHY' if result['healthy'] else 'UNHEALTHY'}")
    return result


# ─────────────────────────────────────────────
#  TOOL 5: ROLLBACK A PATCH
# ─────────────────────────────────────────────

def tool_rollback_patch(hostname: str, patch_id: str, reason: str) -> dict:
    """
    Rolls back a previously applied patch on a server.
    Should be called when health check fails post-patch.

    Args:
        hostname: The server to rollback
        patch_id: The patch to rollback
        reason: Why the rollback is being performed (for audit trail)

    Returns:
        dict with rollback success/failure

    AZURE SWAP:
        Replace simulate_rollback() with Azure Update Manager rollback API.
    """
    print(f"[TOOL] Rolling back {patch_id} on {hostname}. Reason: {reason}")

    result = simulate_rollback(hostname, patch_id)

    # Always log rollbacks to knowledge base
    store_patch_outcome(
        hostname=hostname,
        patch_id=patch_id,
        outcome="rolled_back",
        notes=f"Rollback reason: {reason}. Rollback success: {result['success']}",
    )

    print(f"[TOOL] Rollback {patch_id} on {hostname}: {'SUCCESS' if result['success'] else 'FAILED'}")
    return result


# ─────────────────────────────────────────────
#  TOOL 6: GET PATCH HISTORY FOR A SERVER
# ─────────────────────────────────────────────

def tool_get_server_patch_history(hostname: str) -> dict:
    """
    Retrieves the full patch history for a specific server.
    Used to check what has already been applied and when.

    Args:
        hostname: Server to get history for

    Returns:
        dict with server details and full patch history

    AZURE SWAP:
        Replace get_patch_history() with Azure Update Manager history endpoint.
    """
    print(f"[TOOL] Fetching patch history for {hostname}...")

    server = get_server_details(hostname)
    if not server:
        return {"error": f"Server {hostname} not found"}

    history = get_patch_history(hostname)

    return {
        "hostname": hostname,
        "role": server["role"],
        "os": server["os"],
        "environment": server["environment"],
        "last_patched": server["last_patched"],
        "days_since_last_patch": (
            datetime.now() - datetime.strptime(server["last_patched"], "%Y-%m-%d")
        ).days,
        "total_patches_applied": len(history),
        "patch_history": history,
    }


# ─────────────────────────────────────────────
#  TOOL 7: QUERY KNOWLEDGE BASE
# ─────────────────────────────────────────────

def tool_query_kb(query: str, n_results: int = 2) -> dict:
    """
    Queries the patch management knowledge base for relevant playbooks.
    Used to retrieve procedures, rules, and lessons learned.

    Args:
        query: Natural language description of what you need
               (e.g. 'rollback procedure for failed Windows patch')
        n_results: How many results to return (default 2)

    Returns:
        dict with list of relevant playbook excerpts
    """
    print(f"[TOOL] Querying knowledge base: '{query}'")

    results = query_knowledge_base(query, n_results=n_results)

    return {
        "query": query,
        "results_found": len(results),
        "playbooks": results,
    }


# ─────────────────────────────────────────────
#  TOOL 8: GENERATE COMPLIANCE REPORT
# ─────────────────────────────────────────────

def tool_generate_compliance_report() -> dict:
    """
    Generates a full patch compliance report across the entire fleet.
    Shows which servers are compliant vs overdue vs unpatched.

    Returns:
        dict with compliance status per server and overall fleet metrics

    This is a pure Python calculation — no LLM required.
    The LLM uses this output to write the narrative summary.
    """
    print("[TOOL] Generating patch compliance report...")

    all_servers = get_server_inventory()
    compliance_data = []

    # Compliance thresholds (days since last patch)
    THRESHOLDS = {
        "compliant": 30,    # Patched within 30 days = green
        "warning": 60,      # 31-60 days = amber
        "overdue": 90,      # 61-90 days = red
        # 90+ days = critical overdue (dark red)
    }

    fleet_compliant = 0
    fleet_warning = 0
    fleet_overdue = 0
    fleet_critical_overdue = 0

    for server in all_servers:
        days_since = (
            datetime.now() - datetime.strptime(server["last_patched"], "%Y-%m-%d")
        ).days

        pending = get_available_patches(server["hostname"])
        history = get_patch_history(server["hostname"])

        # Determine compliance status
        if days_since <= THRESHOLDS["compliant"] and len(pending) == 0:
            status = "compliant"
            status_color = "🟢"
            fleet_compliant += 1
        elif days_since <= THRESHOLDS["warning"]:
            status = "warning"
            status_color = "🟡"
            fleet_warning += 1
        elif days_since <= THRESHOLDS["overdue"]:
            status = "overdue"
            status_color = "🔴"
            fleet_overdue += 1
        else:
            status = "critical_overdue"
            status_color = "⛔"
            fleet_critical_overdue += 1

        compliance_data.append({
            "hostname": server["hostname"],
            "role": server["role"],
            "environment": server["environment"],
            "criticality": server["criticality"],
            "os": server["os"],
            "last_patched": server["last_patched"],
            "days_since_patch": days_since,
            "pending_patches": len(pending),
            "critical_pending": sum(1 for p in pending if p["severity"] == "critical"),
            "patches_applied_total": len(history),
            "compliance_status": status,
            "status_indicator": status_color,
        })

    total_servers = len(all_servers)
    compliance_rate = round((fleet_compliant / total_servers) * 100, 1) if total_servers else 0

    result = {
        "report_generated_at": datetime.now().isoformat(),
        "fleet_summary": {
            "total_servers": total_servers,
            "compliant": fleet_compliant,
            "warning": fleet_warning,
            "overdue": fleet_overdue,
            "critical_overdue": fleet_critical_overdue,
            "overall_compliance_rate": f"{compliance_rate}%",
        },
        "servers": sorted(
            compliance_data,
            key=lambda x: {"compliant": 0, "warning": 1, "overdue": 2, "critical_overdue": 3}[
                x["compliance_status"]
            ],
        ),
        "action_required": fleet_critical_overdue > 0 or fleet_overdue > 0,
    }

    print(f"[TOOL] Compliance report: {compliance_rate}% compliant "
          f"({fleet_critical_overdue} critical overdue)")
    return result


# ─────────────────────────────────────────────
#  TOOL 9: CHECK IF IN MAINTENANCE WINDOW
# ─────────────────────────────────────────────

def tool_check_maintenance_window(hostname: str) -> dict:
    """
    Checks whether the current time falls within a server's maintenance window.
    Used by the agent before applying patches to verify timing.

    Args:
        hostname: Server to check

    Returns:
        dict with in_window: bool and window details
    """
    print(f"[TOOL] Checking maintenance window for {hostname}...")

    server = get_server_details(hostname)
    if not server:
        return {"error": f"Server {hostname} not found"}

    now = datetime.now()
    window = server["maintenance_window"]

    # Staging servers can be patched anytime
    if server["environment"] == "staging" or window == "Anytime":
        return {
            "hostname": hostname,
            "environment": server["environment"],
            "maintenance_window": window,
            "in_window": True,
            "current_time": now.strftime("%A %H:%M UTC"),
            "note": "Staging environment — patching allowed anytime",
        }

    # For production, check day of week and hour
    current_day = now.strftime("%A")  # e.g. "Sunday"
    current_hour = now.hour

    # Parse the maintenance window string (e.g. "Sunday 02:00-06:00")
    in_window = False
    if "Sunday" in window and current_day == "Sunday":
        start_hour = int(window.split(" ")[1].split("-")[0].split(":")[0])
        end_hour = int(window.split(" ")[1].split("-")[1].split(":")[0])
        in_window = start_hour <= current_hour < end_hour
    elif "Saturday" in window and current_day == "Saturday":
        start_hour = int(window.split(" ")[1].split("-")[0].split(":")[0])
        end_hour = int(window.split(" ")[1].split("-")[1].split(":")[0])
        in_window = start_hour <= current_hour < end_hour

    return {
        "hostname": hostname,
        "environment": server["environment"],
        "maintenance_window": window,
        "in_window": in_window,
        "current_time": now.strftime("%A %H:%M UTC"),
        "note": (
            "Within maintenance window — patching authorised"
            if in_window
            else f"Outside maintenance window. Next window: {window}"
        ),
    }


# ─────────────────────────────────────────────
#  TOOL 10: APPLY PATCHES TO AN ENTIRE BATCH
# ─────────────────────────────────────────────

def tool_apply_batch(
    batch_name: str,
    servers: list[str],
    approved: bool = False,
) -> dict:
    """
    Applies all pending patches to all servers in a named batch.
    This is the high-level "execute a full batch" tool.

    Sequence for each server in the batch:
      1. Check maintenance window
      2. Apply each pending patch in order (critical first)
      3. Run health check after all patches on that server
      4. If health check fails: rollback and mark server as failed
      5. Move to next server only if current server is healthy

    Args:
        batch_name: Human-readable name (e.g. 'Batch A - Production Web Servers')
        servers: List of hostnames to patch in this batch
        approved: Approval flag — must be True for production batches

    Returns:
        dict with per-server results and overall batch success/failure
    """
    print(f"\n[TOOL] ========== Starting batch: {batch_name} ==========")
    print(f"[TOOL] Servers in batch: {servers}")
    print(f"[TOOL] Approved: {approved}")

    batch_results = {
        "batch_name": batch_name,
        "started_at": datetime.now().isoformat(),
        "servers_requested": servers,
        "approved": approved,
        "server_results": [],
        "batch_success": True,
        "servers_patched": 0,
        "servers_failed": 0,
        "servers_rolled_back": 0,
    }

    for hostname in servers:
        print(f"\n[TOOL] --- Processing {hostname} ---")
        server_result = {
            "hostname": hostname,
            "patches_applied": [],
            "patches_failed": [],
            "patches_rolled_back": [],
            "health_check": None,
            "final_status": "pending",
        }

        # Step 1: Check maintenance window
        window_check = tool_check_maintenance_window(hostname)
        if not window_check.get("in_window", False) and not approved:
            server_result["final_status"] = "skipped_outside_window"
            server_result["note"] = window_check.get("note", "Outside maintenance window")
            batch_results["server_results"].append(server_result)
            print(f"[TOOL] {hostname}: SKIPPED — outside maintenance window")
            continue

        # Step 2: Get all pending patches for this server, sorted critical first
        pending_patches = get_available_patches(hostname)
        severity_order = {"critical": 0, "important": 1, "moderate": 2, "low": 3}
        pending_patches.sort(key=lambda p: severity_order.get(p["severity"], 99))

        if not pending_patches:
            server_result["final_status"] = "no_patches_needed"
            batch_results["server_results"].append(server_result)
            print(f"[TOOL] {hostname}: No patches pending, skipping")
            continue

        # Step 3: Apply each patch in order
        all_applied = True
        for patch in pending_patches:
            apply_result = tool_apply_patch(
                hostname=hostname,
                patch_id=patch["patch_id"],
                approved=approved,
            )

            if apply_result["success"]:
                server_result["patches_applied"].append({
                    "patch_id": patch["patch_id"],
                    "title": patch["title"],
                    "reboot_required": apply_result.get("reboot_required", False),
                })
            else:
                server_result["patches_failed"].append({
                    "patch_id": patch["patch_id"],
                    "error": apply_result.get("error", "Unknown error"),
                })
                all_applied = False
                print(f"[TOOL] {hostname}: Patch {patch['patch_id']} failed — stopping further patches on this server")
                break  # Don't continue patching if one fails

        # Step 4: Run health check after patches
        print(f"[TOOL] {hostname}: Running post-patch health check...")
        health = tool_run_health_check(hostname)
        server_result["health_check"] = health

        # Step 5: If health check fails, rollback
        if not health["healthy"]:
            print(f"[TOOL] {hostname}: UNHEALTHY — initiating rollback of applied patches")
            batch_results["batch_success"] = False

            for applied in server_result["patches_applied"]:
                rollback_result = tool_rollback_patch(
                    hostname=hostname,
                    patch_id=applied["patch_id"],
                    reason=f"Post-patch health check failed: {health.get('message', 'Server unhealthy')}",
                )
                if rollback_result["success"]:
                    server_result["patches_rolled_back"].append(applied["patch_id"])

            server_result["final_status"] = "rolled_back"
            batch_results["servers_rolled_back"] += 1
        elif not all_applied:
            server_result["final_status"] = "partial_success"
            batch_results["servers_failed"] += 1
        else:
            server_result["final_status"] = "success"
            batch_results["servers_patched"] += 1

        batch_results["server_results"].append(server_result)
        print(f"[TOOL] {hostname}: Final status — {server_result['final_status'].upper()}")

    batch_results["completed_at"] = datetime.now().isoformat()
    batch_results["summary"] = (
        f"Batch '{batch_name}' complete. "
        f"Patched: {batch_results['servers_patched']}, "
        f"Failed: {batch_results['servers_failed']}, "
        f"Rolled back: {batch_results['servers_rolled_back']}."
    )

    print(f"\n[TOOL] ========== Batch complete: {batch_results['summary']} ==========\n")
    return batch_results


# ─────────────────────────────────────────────
#  TOOL REGISTRY
#  Used by the agent to know what tools exist.
# ─────────────────────────────────────────────

TOOL_REGISTRY = {
    "scan_patch_inventory": tool_scan_patch_inventory,
    "build_patch_schedule": tool_build_patch_schedule,
    "apply_patch": tool_apply_patch,
    "run_health_check": tool_run_health_check,
    "rollback_patch": tool_rollback_patch,
    "get_server_patch_history": tool_get_server_patch_history,
    "query_knowledge_base": tool_query_kb,
    "generate_compliance_report": tool_generate_compliance_report,
    "check_maintenance_window": tool_check_maintenance_window,
    "apply_batch": tool_apply_batch,
}


def get_tool(name: str):
    """Returns a tool function by name. Used by the agent nodes."""
    return TOOL_REGISTRY.get(name)