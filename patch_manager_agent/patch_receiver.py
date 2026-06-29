"""
patch_receiver.py
=================
The patch intake layer for the Patch Manager Agent.

WHAT THIS FILE DOES:
  Watches a folder called patch_inbox/ for incoming patch files.
  When a new .json file drops in, it:
    1. Reads the patch details
    2. Checks the knowledge base — has this patch been seen before?
    3. If YES  → displays cached results immediately (no LLM needed)
    4. If NO   → sends it through the full agent (analyse → deploy → test)
    5. Logs the deployment result to patch_deployments.json

WHAT A PATCH FILE LOOKS LIKE (drop this in patch_inbox/):
  {
      "patch_id": "KB5034441",
      "title": "2024-01 Cumulative Update for Windows Server 2022",
      "severity": "critical",
      "cve_ids": ["CVE-2024-21338"],
      "cve_score": 9.8,
      "affected_os": ["Windows Server 2022"],
      "reboot_required": true,
      "release_date": "2024-01-09",
      "description": "Critical security update addressing remote code execution."
  }

HOW TO RUN:
  # Watch mode — keeps running and processes patches as they arrive
  python patch_receiver.py --watch

  # Process once — checks inbox right now and exits
  python patch_receiver.py --once

  # Drop a sample patch and process it
  python patch_receiver.py --demo
"""

import os
import json
import time
import shutil
import random
import argparse
from datetime import datetime
from pathlib import Path

from patch_knowledge_base import (
    initialise_knowledge_base,
    query_knowledge_base,
    store_patch_outcome,
)
from patch_inventory import AVAILABLE_PATCHES, simulate_health_check
from patch_agent import run_patch_agent


# ─────────────────────────────────────────────
#  FOLDER PATHS
#  All relative to patch_manager_agent/ folder.
# ─────────────────────────────────────────────

INBOX_DIR         = Path("patch_inbox")           # Drop new patch .json files here
PROCESSING_DIR    = Path("patch_processing")      # Moved here while being handled
DONE_DIR          = Path("patch_done")            # Moved here after success
FAILED_DIR        = Path("patch_failed")          # Moved here after failure
DEPLOYMENTS_FILE  = Path("patch_deployments.json") # Running log of all deployments


def ensure_folders():
    """Creates all required folders if they don't exist yet."""
    for folder in [INBOX_DIR, PROCESSING_DIR, DONE_DIR, FAILED_DIR]:
        folder.mkdir(exist_ok=True)


# ─────────────────────────────────────────────
#  DEPLOYMENT LOG
#  Every patch that gets processed is recorded
#  in patch_deployments.json so we have a full
#  audit trail.
# ─────────────────────────────────────────────

def load_deployments() -> list:
    """Loads the existing deployment log from disk."""
    if DEPLOYMENTS_FILE.exists():
        with open(DEPLOYMENTS_FILE, "r") as f:
            return json.load(f)
    return []


def save_deployment(record: dict):
    """
    Appends a deployment record to patch_deployments.json.
    Creates the file if it doesn't exist.
    """
    deployments = load_deployments()
    deployments.append(record)
    with open(DEPLOYMENTS_FILE, "w") as f:
        json.dump(deployments, f, indent=2)
    print(f"[LOG] Deployment record saved to {DEPLOYMENTS_FILE}")


# ─────────────────────────────────────────────
#  KNOWLEDGE BASE CHECK
#  Before running the full agent pipeline,
#  check if we already know about this patch.
# ─────────────────────────────────────────────

def check_kb_for_patch(patch: dict) -> dict:
    """
    Searches the knowledge base for information about this patch.

    Returns:
        dict with:
          - found: bool — whether we found relevant KB entries
          - results: list of matching KB entries
          - recommendation: str — what the KB says to do
          - past_deployments: list — any previous deployments of this patch
    """
    patch_id  = patch.get("patch_id", "")
    severity  = patch.get("severity", "")
    cve_ids   = patch.get("cve_ids", [])
    cve_score = patch.get("cve_score", 0)

    # Build a search query from the patch details
    query = f"{severity} patch {patch_id} CVE deployment procedure"
    if cve_score >= 9.0:
        query += " critical emergency zero-day"

    kb_results = query_knowledge_base(query, n_results=3)

    # Also check deployment history for this specific patch ID
    past_deployments = [
        d for d in load_deployments()
        if d.get("patch_id") == patch_id
    ]

    # Determine recommendation based on severity + past deployments
    if past_deployments:
        last = past_deployments[-1]
        if last["outcome"] == "success":
            recommendation = (
                f"✅ This patch was successfully deployed before on "
                f"{last['deployed_at'][:10]}. Safe to proceed using same approach."
            )
        else:
            recommendation = (
                f"⚠️  This patch FAILED on a previous deployment ({last['deployed_at'][:10]}). "
                f"Reason: {last.get('notes', 'Unknown')}. Review before redeployment."
            )
    elif cve_score >= 9.0:
        recommendation = "🔴 CRITICAL patch — deploy immediately following emergency procedure PB-014."
    elif cve_score >= 7.0:
        recommendation = "🟡 IMPORTANT patch — deploy within 14 days following standard procedure."
    else:
        recommendation = "🟢 MODERATE/LOW patch — schedule for next maintenance window."

    return {
        "found": len(kb_results) > 0,
        "results": kb_results,
        "recommendation": recommendation,
        "past_deployments": past_deployments,
        "past_deployment_count": len(past_deployments),
    }


# ─────────────────────────────────────────────
#  DISPLAY KB RESULTS
#  When the patch IS in KB, print a clean
#  summary so the user sees what we know.
# ─────────────────────────────────────────────

def display_kb_results(patch: dict, kb_check: dict):
    """Prints a formatted display of KB results for a known patch."""

    print(f"""
╔══════════════════════════════════════════════════════════════╗
║         PATCH FOUND IN KNOWLEDGE BASE                        ║
╚══════════════════════════════════════════════════════════════╝

PATCH DETAILS:
  ID:          {patch.get('patch_id', 'Unknown')}
  Title:       {patch.get('title', 'Unknown')}
  Severity:    {patch.get('severity', 'Unknown').upper()}
  CVE Score:   {patch.get('cve_score', 'N/A')}
  CVE IDs:     {', '.join(patch.get('cve_ids', [])) or 'None'}
  Affects:     {', '.join(patch.get('affected_os', [])) or 'Unknown'}
  Reboot:      {'Yes' if patch.get('reboot_required') else 'No'}
  Released:    {patch.get('release_date', 'Unknown')}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

RECOMMENDATION:
  {kb_check['recommendation']}

PAST DEPLOYMENTS: {kb_check['past_deployment_count']} previous deployment(s) found
""")

    if kb_check["past_deployments"]:
        print("  DEPLOYMENT HISTORY:")
        for d in kb_check["past_deployments"][-3:]:  # Show last 3
            status_icon = "✅" if d["outcome"] == "success" else "❌"
            print(f"    {status_icon} {d['deployed_at'][:10]} — {d['outcome'].upper()} "
                  f"on {d.get('servers_targeted', 'Unknown servers')}")
        print()

    print("RELEVANT KB PROCEDURES:")
    for r in kb_check["results"][:2]:
        print(f"  [{r['playbook_id']}] {r['title']}")
        print(f"  {r['content'][:200].strip()}...")
        print()

    print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")


# ─────────────────────────────────────────────
#  SIMULATE PATCH APPLY (FROM PATCH DATA DIRECTLY)  ⭐ NEW
#
#  WHY THIS EXISTS:
#  The original code called simulate_patch_apply(hostname, patch_id) from
#  patch_inventory.py, which only succeeds if patch_id already exists in
#  the hardcoded AVAILABLE_PATCHES list. That list only contains the 10
#  original hand-written demo patches (KB5034441, USN-6648-1, etc).
#
#  Patches pulled live from patch_feed_poller.py (real Ubuntu USNs from
#  Canonical's feed) are NEVER in that static list — so every one of them
#  used to fail immediately with "Patch {id} not found in patch library",
#  even though we already have the complete patch data sitting right here
#  in the `patch` dict (read straight from the inbox file).
#
#  This function simulates the patch apply using that data directly,
#  instead of requiring a redundant lookup in the static catalogue. Same
#  90% success / 10% failure simulation behaviour as before, so realism
#  (occasional failures, rollback triggers) is unchanged.
# ─────────────────────────────────────────────

def simulate_patch_apply_from_data(hostname: str, patch: dict) -> dict:
    """
    Simulates applying a patch to a server using the patch's own data
    dict directly, instead of looking it up by ID in the static
    AVAILABLE_PATCHES catalogue.

    This is what allows patches sourced from patch_feed_poller.py (real
    Ubuntu USNs pulled live from Canonical) to deploy correctly, since
    they are never added to AVAILABLE_PATCHES — that list only contains
    the original hand-written demo patches.
    """
    from patch_inventory import SERVER_REGISTRY, PATCH_HISTORY

    hostname = hostname.upper()
    server = SERVER_REGISTRY.get(hostname)
    patch_id = patch.get("patch_id", "UNKNOWN")

    if not server:
        return {"success": False, "error": f"Server {hostname} not found in registry"}

    # Simulate realistic success/failure — same 90% success rate as the
    # original simulate_patch_apply() in patch_inventory.py
    success = random.random() > 0.1

    if success:
        if hostname not in PATCH_HISTORY:
            PATCH_HISTORY[hostname] = []
        PATCH_HISTORY[hostname].append({
            "patch_id": patch_id,
            "applied_date": datetime.now().strftime("%Y-%m-%d"),
            "status": "success",
            "applied_by": "patch-agent",
        })
        SERVER_REGISTRY[hostname]["last_patched"] = datetime.now().strftime("%Y-%m-%d")

        return {
            "success": True,
            "hostname": hostname,
            "patch_id": patch_id,
            "patch_title": patch.get("title", patch_id),
            "reboot_required": patch.get("reboot_required", False),
            "duration_minutes": patch.get("estimated_duration_minutes", 20),
            "message": f"Patch {patch_id} successfully applied to {hostname}",
        }
    else:
        return {
            "success": False,
            "hostname": hostname,
            "patch_id": patch_id,
            "error": "Patch installation failed: simulated package manager error",
            "message": f"Patch {patch_id} FAILED on {hostname} — rollback initiated",
        }


# ─────────────────────────────────────────────
#  SIMULATE DEPLOYMENT
#  Since we are local/dev, deployment means:
#    1. Find which servers are affected
#    2. Mark the patch as deployed on each
#    3. Run a health check (from existing tools)
#    4. Log result to patch_deployments.json
# ─────────────────────────────────────────────

def deploy_patch_locally(patch: dict) -> dict:
    """
    Simulates deploying the patch to all compatible servers.
    Uses the existing simulate_health_check from patch_inventory.py.

    Returns a deployment result dict.
    """
    patch_id = patch.get("patch_id", "UNKNOWN")
    affected_os = patch.get("affected_os", [])

    print(f"\n[DEPLOY] Starting deployment of {patch_id}...")

    # Find servers that need this patch (matching OS)
    from patch_inventory import SERVER_REGISTRY
    targeted_servers = [
        hostname for hostname, server in SERVER_REGISTRY.items()
        if server["os"] in affected_os
    ]

    if not targeted_servers:
        return {
            "success": False,
            "patch_id": patch_id,
            "targeted_servers": [],
            "notes": f"No servers found running {affected_os}",
        }

    print(f"[DEPLOY] Targeting {len(targeted_servers)} servers: {targeted_servers}")

    server_results = []
    all_passed = True

    for hostname in targeted_servers:
        print(f"\n[DEPLOY] Applying {patch_id} to {hostname}...")

        # Apply the patch — simulate directly using the patch data we
        # already have (⭐ CHANGED), instead of requiring it to exist in
        # the static AVAILABLE_PATCHES catalogue. This is what lets
        # feed-sourced patches (pulled live from Canonical's USN feed)
        # deploy correctly, not just the original hand-written demo patches.
        apply_result = simulate_patch_apply_from_data(hostname, patch)

        if apply_result["success"]:
            print(f"[DEPLOY] ✅ Patch applied to {hostname}")

            # Run health check
            print(f"[DEPLOY] Running health check on {hostname}...")
            health = simulate_health_check(hostname)

            if health["healthy"]:
                print(f"[DEPLOY] ✅ {hostname} is healthy post-patch")
                server_results.append({
                    "hostname": hostname,
                    "patch_applied": True,
                    "health_check": "passed",
                    "cpu": health.get("cpu_percent"),
                    "memory": health.get("memory_percent"),
                    "services_up": health.get("services_up", []),
                })
            else:
                print(f"[DEPLOY] ❌ {hostname} UNHEALTHY after patch — rollback required")
                all_passed = False
                server_results.append({
                    "hostname": hostname,
                    "patch_applied": True,
                    "health_check": "failed",
                    "services_down": health.get("services_down", []),
                    "rollback_needed": True,
                })
        else:
            print(f"[DEPLOY] ❌ Patch failed on {hostname}: {apply_result.get('error')}")
            all_passed = False
            server_results.append({
                "hostname": hostname,
                "patch_applied": False,
                "health_check": "skipped",
                "error": apply_result.get("error"),
            })

    return {
        "success": all_passed,
        "patch_id": patch_id,
        "targeted_servers": targeted_servers,
        "server_results": server_results,
        "servers_passed": sum(1 for r in server_results if r.get("health_check") == "passed"),
        "servers_failed": sum(1 for r in server_results if r.get("health_check") != "passed"),
        "notes": "All servers healthy post-patch" if all_passed else "Some servers failed health check",
    }


# ─────────────────────────────────────────────
#  PRINT DEPLOYMENT RESULT
# ─────────────────────────────────────────────

def display_deployment_result(patch: dict, deployment: dict):
    """Prints a formatted deployment result summary."""

    overall = "✅ SUCCESS" if deployment["success"] else "❌ FAILED"

    print(f"""
╔══════════════════════════════════════════════════════════════╗
║              DEPLOYMENT RESULT                               ║
╚══════════════════════════════════════════════════════════════╝

Patch:    {patch.get('patch_id')} — {patch.get('title', '')}
Outcome:  {overall}
Servers:  {deployment.get('servers_passed', 0)} passed / {deployment.get('servers_failed', 0)} failed

SERVER RESULTS:""")

    for r in deployment.get("server_results", []):
        icon = "✅" if r.get("health_check") == "passed" else "❌"
        print(f"  {icon} {r['hostname']:<20} patch={'applied' if r.get('patch_applied') else 'failed':<8} "
              f"health={r.get('health_check', 'unknown')}")

    print(f"""
Notes: {deployment.get('notes', '')}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
""")


# ─────────────────────────────────────────────
#  PROCESS ONE PATCH FILE
#  The main logic that runs when a patch file
#  is detected in the inbox.
# ─────────────────────────────────────────────

def process_patch_file(filepath: Path):
    """
    Full processing pipeline for a single incoming patch file.

    Steps:
      1. Read and validate the patch JSON
      2. Move to processing/ so we don't double-process
      3. Check knowledge base
      4. If known → display results then deploy
      5. If new   → run full agent pipeline then deploy
      6. Log result
      7. Move to done/ or failed/
    """
    print(f"\n{'='*60}")
    print(f"NEW PATCH DETECTED: {filepath.name}")
    print(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*60}")

    # Step 1: Read the patch file
    try:
        with open(filepath, "r") as f:
            patch = json.load(f)
        print(f"[RECEIVER] Patch loaded: {patch.get('patch_id')} — {patch.get('title', '')}")
    except Exception as e:
        print(f"[RECEIVER] ❌ Failed to read patch file: {e}")
        shutil.move(str(filepath), str(FAILED_DIR / filepath.name))
        return

    # Validate required fields
    required = ["patch_id", "severity", "title"]
    missing = [f for f in required if f not in patch]
    if missing:
        print(f"[RECEIVER] ❌ Patch file missing required fields: {missing}")
        shutil.move(str(filepath), str(FAILED_DIR / filepath.name))
        return

    # Step 2: Move to processing
    processing_path = PROCESSING_DIR / filepath.name
    shutil.move(str(filepath), str(processing_path))
    print(f"[RECEIVER] Moved to processing: {processing_path}")

    # Step 3: Check knowledge base
    print(f"\n[RECEIVER] Checking knowledge base for {patch['patch_id']}...")
    initialise_knowledge_base()
    kb_check = check_kb_for_patch(patch)

    deployment_result = None
    outcome = "unknown"
    notes = ""

    try:
        if kb_check["found"] or kb_check["past_deployment_count"] > 0:
            # ── KNOWN PATCH ──────────────────────────────────────────
            print(f"[RECEIVER] ✅ Patch found in knowledge base!")
            display_kb_results(patch, kb_check)

            # Ask user if they want to proceed with deployment
            print("Knowledge base results shown above.")
            proceed = input("Proceed with deployment? (y/n): ").strip().lower()

            if proceed == "y":
                print(f"\n[RECEIVER] Deploying {patch['patch_id']}...")
                deployment_result = deploy_patch_locally(patch)
                display_deployment_result(patch, deployment_result)
                outcome = "success" if deployment_result["success"] else "failed"
                notes = deployment_result.get("notes", "")

                # Store outcome back in KB so we keep learning
                store_patch_outcome(
                    hostname="fleet",
                    patch_id=patch["patch_id"],
                    outcome=outcome,
                    notes=f"KB-assisted deployment. {notes}",
                )
            else:
                print("[RECEIVER] Deployment skipped by operator.")
                outcome = "skipped"
                notes = "Operator chose not to deploy after KB review"

        else:
            # ── NEW PATCH — run full agent pipeline ──────────────────
            print(f"[RECEIVER] 🆕 Patch not in knowledge base — running full agent analysis...")

            # Determine task type based on severity
            if patch.get("cve_score", 0) >= 9.0:
                task_type = "emergency_patch"
                force_approved = True
            else:
                task_type = "scan"
                force_approved = False

            # Run the full agent
            agent_result = run_patch_agent(
                task_type=task_type,
                task_input={"patch_id": patch["patch_id"]},
                test_mode=False,
                force_approved=force_approved,
            )

            print(f"\n[RECEIVER] Agent analysis complete. Status: {agent_result.get('agent_status')}")

            # Now deploy
            print(f"\n[RECEIVER] Proceeding with deployment...")
            deployment_result = deploy_patch_locally(patch)
            display_deployment_result(patch, deployment_result)
            outcome = "success" if deployment_result["success"] else "failed"
            notes = deployment_result.get("notes", "")

            # Store in KB so next time this patch arrives we know about it
            store_patch_outcome(
                hostname="fleet",
                patch_id=patch["patch_id"],
                outcome=outcome,
                notes=f"First-time deployment. Severity: {patch.get('severity')}. {notes}",
            )

        # Step 6: Log to patch_deployments.json
        deployment_record = {
            "patch_id": patch["patch_id"],
            "title": patch.get("title", ""),
            "severity": patch.get("severity", ""),
            "cve_score": patch.get("cve_score", 0),
            "deployed_at": datetime.now().isoformat(),
            "outcome": outcome,
            "servers_targeted": deployment_result.get("targeted_servers", []) if deployment_result else [],
            "servers_passed": deployment_result.get("servers_passed", 0) if deployment_result else 0,
            "servers_failed": deployment_result.get("servers_failed", 0) if deployment_result else 0,
            "kb_was_used": kb_check["found"] or kb_check["past_deployment_count"] > 0,
            "notes": notes,
            "source_file": filepath.name,
        }
        save_deployment(deployment_record)

        # Step 7: Move file to done or failed
        if outcome in ("success", "skipped"):
            shutil.move(str(processing_path), str(DONE_DIR / filepath.name))
            print(f"[RECEIVER] ✅ Patch file moved to done/")
        else:
            shutil.move(str(processing_path), str(FAILED_DIR / filepath.name))
            print(f"[RECEIVER] ❌ Patch file moved to failed/")

    except Exception as e:
        print(f"[RECEIVER] ❌ Unexpected error processing patch: {e}")
        import traceback
        traceback.print_exc()
        # Move to failed
        if processing_path.exists():
            shutil.move(str(processing_path), str(FAILED_DIR / filepath.name))


# ─────────────────────────────────────────────
#  INBOX WATCHER
#  Polls the patch_inbox/ folder every 5 seconds.
#  When a new .json file appears, processes it.
# ─────────────────────────────────────────────

def watch_inbox(poll_interval_seconds: int = 5):
    """
    Continuously watches patch_inbox/ for new patch files.
    Processes each file as it arrives.
    Press Ctrl+C to stop.
    """
    ensure_folders()
    print(f"""
╔══════════════════════════════════════════════════════════════╗
║          PATCH RECEIVER — WATCHING FOR INCOMING PATCHES      ║
╚══════════════════════════════════════════════════════════════╝

  Watching: {INBOX_DIR.absolute()}
  Interval: every {poll_interval_seconds} seconds
  
  DROP a patch .json file into the patch_inbox/ folder to trigger processing.
  Press Ctrl+C to stop watching.

{'='*60}
""")

    processed = set()  # Track files we've already processed this session

    try:
        while True:
            # Find all .json files in inbox that we haven't processed yet
            inbox_files = list(INBOX_DIR.glob("*.json"))
            new_files = [f for f in inbox_files if f.name not in processed]

            if new_files:
                for filepath in new_files:
                    processed.add(filepath.name)
                    process_patch_file(filepath)
                    print(f"\n[WATCHER] Waiting for next patch... (Ctrl+C to stop)")
            else:
                # No new files — print a dot to show we're alive
                print(f"\r[WATCHER] Watching... {datetime.now().strftime('%H:%M:%S')} "
                      f"(drop a .json file in patch_inbox/)", end="", flush=True)

            time.sleep(poll_interval_seconds)

    except KeyboardInterrupt:
        print(f"\n\n[WATCHER] Stopped watching. Goodbye!")


def check_inbox_once():
    """
    Checks the inbox once for any pending patch files and processes them.
    Exits after processing all current files.
    """
    ensure_folders()
    inbox_files = list(INBOX_DIR.glob("*.json"))

    if not inbox_files:
        print(f"[RECEIVER] No patch files found in {INBOX_DIR}/")
        print(f"[RECEIVER] Drop a .json patch file there and run again.")
        return

    print(f"[RECEIVER] Found {len(inbox_files)} patch file(s) in inbox.")
    for filepath in inbox_files:
        process_patch_file(filepath)


# ─────────────────────────────────────────────
#  DEMO MODE
#  Creates sample patch files so you can see
#  the full flow without making real files.
# ─────────────────────────────────────────────

SAMPLE_PATCHES = [
    {
        "patch_id": "KB5034441",
        "title": "2024-01 Cumulative Update for Windows Server 2022",
        "severity": "critical",
        "cve_ids": ["CVE-2024-21338", "CVE-2024-21345"],
        "cve_score": 9.8,
        "affected_os": ["Windows Server 2022"],
        "patch_type": "security",
        "reboot_required": True,
        "release_date": "2024-01-09",
        "description": "Critical security update addressing remote code execution in Windows kernel.",
    },
    {
        "patch_id": "USN-6648-1",
        "title": "Linux kernel vulnerabilities - Ubuntu 22.04 LTS",
        "severity": "critical",
        "cve_ids": ["CVE-2024-0193", "CVE-2024-0582"],
        "cve_score": 9.3,
        "affected_os": ["Ubuntu 22.04 LTS"],
        "patch_type": "security",
        "reboot_required": True,
        "release_date": "2024-01-12",
        "description": "Critical Linux kernel update addressing use-after-free vulnerability.",
    },
    {
        "patch_id": "USN-6626-1",
        "title": "curl vulnerabilities - Ubuntu 20.04 / 22.04",
        "severity": "moderate",
        "cve_ids": ["CVE-2023-46218"],
        "cve_score": 5.3,
        "affected_os": ["Ubuntu 20.04 LTS", "Ubuntu 22.04 LTS"],
        "patch_type": "security",
        "reboot_required": False,
        "release_date": "2024-01-05",
        "description": "Security update for curl addressing cookie mixing vulnerability.",
    },
]


def run_demo(patch_index: int = 0):
    """
    Drops a sample patch file into the inbox and processes it immediately.
    Great for showing the manager the full flow end to end.

    patch_index: 0 = critical Windows patch, 1 = critical Linux patch, 2 = moderate patch
    """
    ensure_folders()

    patch = SAMPLE_PATCHES[patch_index % len(SAMPLE_PATCHES)]
    filename = f"{patch['patch_id']}.json"
    filepath = INBOX_DIR / filename

    print(f"\n[DEMO] Creating sample patch file: {filename}")
    with open(filepath, "w") as f:
        json.dump(patch, f, indent=2)
    print(f"[DEMO] Dropped into {INBOX_DIR}/")

    # Process it immediately
    process_patch_file(filepath)


# ─────────────────────────────────────────────
#  SHOW DEPLOYMENT HISTORY
# ─────────────────────────────────────────────

def show_deployment_history():
    """Prints all past deployments from patch_deployments.json."""
    deployments = load_deployments()

    if not deployments:
        print("\n[HISTORY] No deployments recorded yet.")
        return

    print(f"\n{'='*70}")
    print(f"  PATCH DEPLOYMENT HISTORY — {len(deployments)} deployments")
    print(f"{'='*70}")
    print(f"  {'DATE':<12} {'PATCH ID':<15} {'SEVERITY':<12} {'OUTCOME':<10} {'SERVERS':<8} {'KB USED'}")
    print(f"  {'-'*12} {'-'*15} {'-'*12} {'-'*10} {'-'*8} {'-'*8}")

    for d in sorted(deployments, key=lambda x: x["deployed_at"], reverse=True)[:20]:
        outcome_icon = "✅" if d["outcome"] == "success" else ("⏭️" if d["outcome"] == "skipped" else "❌")
        kb_icon = "✅" if d.get("kb_was_used") else "🆕"
        print(
            f"  {d['deployed_at'][:10]:<12} "
            f"{d['patch_id']:<15} "
            f"{d['severity']:<12} "
            f"{outcome_icon} {d['outcome']:<8} "
            f"{d.get('servers_passed', 0)}/{d.get('servers_passed', 0) + d.get('servers_failed', 0):<6} "
            f"{kb_icon}"
        )

    print(f"{'='*70}")
    print("  ✅ = success  ❌ = failed  ⏭️ = skipped  🆕 = new patch (no KB entry)")


# ─────────────────────────────────────────────
#  MAIN
# ─────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Patch Receiver — watches for incoming patches and processes them",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python patch_receiver.py --watch          # Keep watching inbox for new patches
  python patch_receiver.py --once           # Check inbox once and exit
  python patch_receiver.py --demo           # Drop a sample critical patch and process it
  python patch_receiver.py --demo --patch 1 # Demo with Linux kernel patch
  python patch_receiver.py --demo --patch 2 # Demo with moderate curl patch
  python patch_receiver.py --history        # Show all past deployments
        """,
    )
    parser.add_argument("--watch",   action="store_true", help="Watch inbox continuously")
    parser.add_argument("--once",    action="store_true", help="Check inbox once and exit")
    parser.add_argument("--demo",    action="store_true", help="Run demo with a sample patch")
    parser.add_argument("--patch",   type=int, default=0, help="Demo patch index: 0=Windows critical, 1=Linux critical, 2=moderate")
    parser.add_argument("--history", action="store_true", help="Show deployment history")
    parser.add_argument("--interval", type=int, default=5, help="Watch poll interval in seconds (default: 5)")

    args = parser.parse_args()

    if args.history:
        show_deployment_history()
    elif args.demo:
        run_demo(patch_index=args.patch)
    elif args.once:
        check_inbox_once()
    elif args.watch:
        watch_inbox(poll_interval_seconds=args.interval)
    else:
        # Default: interactive menu
        print("\nPatch Receiver — What would you like to do?")
        print("  1. Watch inbox for incoming patches")
        print("  2. Check inbox once")
        print("  3. Run demo (drop a sample patch)")
        print("  4. Show deployment history")
        choice = input("\nEnter choice (1-4): ").strip()

        if choice == "1":
            watch_inbox()
        elif choice == "2":
            check_inbox_once()
        elif choice == "3":
            idx = input("Patch type (0=Windows critical, 1=Linux critical, 2=moderate): ").strip()
            run_demo(patch_index=int(idx) if idx.isdigit() else 0)
        elif choice == "4":
            show_deployment_history()
        else:
            print("Invalid choice.")