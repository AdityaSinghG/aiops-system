"""
patch_knowledge_base.py
=======================
ChromaDB-powered knowledge base for the Patch Manager Agent.

Stores and retrieves:
  - Patching playbooks (rules and procedures)
  - Batch sequencing rules (which servers patch in what order)
  - Rollback procedures
  - Post-patch validation checklists
  - Historical patch incidents and lessons learned
  - Severity classification guidelines

AZURE SWAP:
  Replace ChromaDB with Azure AI Search.
  The query_knowledge_base() function signature stays the same —
  only the internals change (use azure-search-documents SDK instead).
  The agent code does NOT need to change at all.
"""

import chromadb
from chromadb.utils import embedding_functions
import json
import os


# ─────────────────────────────────────────────
#  CHROMADB SETUP
#  Persistent storage in ./chroma_patch_db/
#  so knowledge survives between runs.
# ─────────────────────────────────────────────

CHROMA_DB_PATH = "./chroma_patch_db"
COLLECTION_NAME = "patch_manager_knowledge"


def get_chroma_client():
    """Returns a persistent ChromaDB client."""
    client = chromadb.PersistentClient(path=CHROMA_DB_PATH)
    return client


def get_collection():
    """
    Returns (or creates) the patch knowledge base collection.
    Uses the default sentence-transformer embeddings from ChromaDB.
    """
    client = get_chroma_client()

    # Use ChromaDB's built-in default embedding function
    # (no external API key required for local use)
    embedding_fn = embedding_functions.DefaultEmbeddingFunction()

    collection = client.get_or_create_collection(
        name=COLLECTION_NAME,
        embedding_function=embedding_fn,
        metadata={"description": "Patch Manager Agent knowledge base — playbooks and procedures"},
    )
    return collection


# ─────────────────────────────────────────────
#  KNOWLEDGE BASE CONTENT
#  15 playbooks covering the full patching
#  lifecycle. Each has an ID, category, title,
#  and rich content for the LLM to reason over.
# ─────────────────────────────────────────────

PATCH_PLAYBOOKS = [
    {
        "id": "PB-001",
        "category": "scheduling",
        "title": "Patch Scheduling and Maintenance Window Rules",
        "content": """
PATCH SCHEDULING RULES — Patch Manager Agent Standard Operating Procedure

1. PRODUCTION SERVERS: Never patch during business hours (09:00-18:00 Mon-Fri).
   All production patching must occur within the defined maintenance window.
   
2. MAINTENANCE WINDOWS by server role:
   - Web Servers (WEB-*): Sunday 02:00-06:00 UTC
   - Database Servers (DB-*): Saturday 01:00-05:00 UTC
   - Application Servers (APP-*): Sunday 02:00-06:00 UTC
   - Monitoring Servers (MON-*): Sunday 04:00-06:00 UTC
   - Management Servers: Saturday 03:00-05:00 UTC

3. STAGING SERVERS: Can be patched anytime. Always patch staging before production.
   Minimum 24-hour soak period required between staging and production patching.

4. EMERGENCY PATCHES (CVSS score >= 9.0): Can override normal schedule with change
   manager approval. Must still follow batch sequencing (see PB-002).

5. NEVER schedule patches for:
   - Last business day of the month (finance close period)
   - Known high-traffic events (product launches, major campaigns)
   - Within 48 hours of a production deployment
""",
    },
    {
        "id": "PB-002",
        "category": "batching",
        "title": "Batch Sequencing and Rolling Patch Strategy",
        "content": """
BATCH SEQUENCING RULES — Critical for zero-downtime patching

WHY BATCHING MATTERS:
Never patch all servers simultaneously. If a patch causes issues, you need healthy
servers to serve traffic while you roll back. Batching limits blast radius.

BATCH ORDER (always follow this sequence):
  1. STAGING (all environments) → Verify 24 hours → proceed
  2. BATCH A (production, less critical): WEB-PROD-01, APP-PROD-01, MON-PROD-01
  3. Wait 2 hours → verify Batch A servers healthy → proceed  
  4. BATCH B (production, secondary): WEB-PROD-02, APP-PROD-02, BACKUP-01, INFRA-MGMT-01
  5. Wait 2 hours → verify Batch B servers healthy → proceed
  6. BATCH C (critical data tier): DB-PROD-01, DB-PROD-02
  7. DB servers require ADDITIONAL manual sign-off from DBA team before patching

PARALLEL PATCHING WITHIN A BATCH:
  - Web and App servers in the same batch CAN be patched simultaneously
  - Database servers: NEVER patch primary and replica simultaneously
  - Patch DB-PROD-02 (replica) first, promote if needed, then patch DB-PROD-01

HEALTH CHECK BETWEEN BATCHES:
  After each batch, verify ALL of: CPU < 80%, memory < 85%, all key services running,
  HTTP health endpoint returning 200. Only proceed to next batch on full health confirmation.
""",
    },
    {
        "id": "PB-003",
        "category": "severity",
        "title": "Patch Severity Classification and Response Times",
        "content": """
PATCH SEVERITY CLASSIFICATION — Required Response Times

CRITICAL (CVSS 9.0-10.0):
  - Definition: Remote code execution, privilege escalation allowing full system compromise
  - Response time: Apply within 24 hours for staging, 72 hours for production
  - Approval required: Change manager notification (not blocking)
  - Examples: EternalBlue-class vulnerabilities, unauthenticated RCE

IMPORTANT / HIGH (CVSS 7.0-8.9):
  - Definition: Significant security risk but requires some user interaction or local access
  - Response time: Apply within 7 days for staging, 14 days for production
  - Approval required: Standard change process
  - Examples: Local privilege escalation, authenticated RCE

MODERATE (CVSS 4.0-6.9):
  - Definition: Limited exposure, partial system compromise possible
  - Response time: Apply within 30 days as part of regular monthly cycle
  - Approval required: Standard change process
  - Examples: Information disclosure, limited DoS

LOW (CVSS 0.1-3.9):
  - Definition: Minimal risk, difficult to exploit
  - Response time: Next quarterly maintenance window
  - Approval required: Standard change process

QUALITY / NON-SECURITY PATCHES:
  - Apply as part of regular monthly cycle regardless of CVSS (no CVE assigned)
  - Do not expedite. Follow standard scheduling.
""",
    },
    {
        "id": "PB-004",
        "category": "approval",
        "title": "Approval Workflow and Change Management",
        "content": """
APPROVAL WORKFLOW — All patching requires appropriate authorisation

STAGING ENVIRONMENT: No approval required. Patch-agent has autonomous authority.

PRODUCTION ENVIRONMENT — Tiered approval:
  1. CRITICAL patches (CVSS >= 9.0):
     - Notify change manager via alert (non-blocking for emergencies)
     - Log all actions in change management system
     - Auto-proceed after 30 minutes if no objection received
     
  2. IMPORTANT patches (CVSS 7.0-8.9):
     - Raise standard change request in ITSM system
     - Wait for change manager approval (standard SLA: 4 hours)
     - Do not proceed without confirmed approval

  3. DATABASE SERVERS (any severity):
     - Always require DBA team sign-off regardless of severity
     - DBA must confirm no active long-running transactions
     - Replica must be verified in sync before patching primary

  4. EMERGENCY OUT-OF-BAND PATCHING (zero-day exploits):
     - Patch-agent raises Priority 1 change request
     - Notifies on-call manager immediately
     - Can proceed within 1 hour if manager confirmed reachable

AUDIT TRAIL: Every patch action must be logged with:
  - Timestamp, patch ID, server name, operator (patch-agent), result, approver
""",
    },
    {
        "id": "PB-005",
        "category": "validation",
        "title": "Post-Patch Health Validation Checklist",
        "content": """
POST-PATCH VALIDATION PROCEDURE — Run after every patch application

IMMEDIATE CHECKS (within 5 minutes of patch completion):
  1. Server responds to ping (latency < 100ms)
  2. SSH or WinRM connection successful
  3. All critical services are in Running/Active state
  4. CPU utilisation < 80% (high CPU can indicate patch-related process issues)
  5. Available memory > 20% of total RAM
  6. No new critical event log entries in Windows Event Viewer / syslog

APPLICATION LAYER CHECKS (within 15 minutes):
  7. HTTP health endpoint returns HTTP 200 (web/app servers)
  8. Database accepts connections and simple query succeeds (DB servers)
  9. Load balancer health check passes (server back in rotation)
  10. Application log shows no new errors since patch

PERFORMANCE BASELINE COMPARISON:
  11. Response time within 20% of pre-patch baseline
  12. Throughput (requests/sec) within 10% of pre-patch baseline

DECLARATION CRITERIA:
  - ALL 12 checks must pass before batch is declared healthy
  - If any check fails: immediately trigger rollback procedure (PB-006)
  - If checks 1-6 pass but 7-12 partially fail: escalate to human, do not auto-rollback
""",
    },
    {
        "id": "PB-006",
        "category": "rollback",
        "title": "Patch Rollback Procedure",
        "content": """
ROLLBACK PROCEDURE — When and how to roll back a patch

AUTOMATIC ROLLBACK TRIGGERS (patch-agent initiates without human approval):
  - Server fails to respond to ping within 5 minutes of reboot
  - Any critical service fails to start within 10 minutes of patch
  - CPU > 95% sustained for more than 3 minutes post-patch
  - Available memory < 5% post-patch

HUMAN-ESCALATED ROLLBACK (patch-agent requests approval):
  - Application layer checks fail (items 7-12 in PB-005)
  - Rollback affects a database server (always needs DBA sign-off)
  - Uncertain if the issue is patch-related or pre-existing

ROLLBACK STEPS:
  1. Stop all active patch operations on this server
  2. Log rollback initiation with timestamp and reason
  3. Execute OS rollback (Windows: System Restore / DISM, Linux: dpkg/apt rollback)
  4. Reboot server if required
  5. Wait for server to come back online (max 15 minutes)
  6. Run full validation checklist (PB-005) on rolled-back server
  7. If rollback validation passes: mark server as excluded from current patch cycle
  8. Create incident ticket describing the failed patch and rollback
  9. Notify change manager and server owner of rollback

POST-ROLLBACK ACTIONS:
  - Investigate root cause of patch failure before next attempt
  - Check vendor KB for known issues with this patch on this OS version
  - Attempt re-patch only after root cause is understood and mitigated
""",
    },
    {
        "id": "PB-007",
        "category": "database",
        "title": "Database Server Patching Special Procedures",
        "content": """
DATABASE SERVER PATCHING — Special rules for DB-PROD-01 and DB-PROD-02

PRE-PATCH REQUIREMENTS (must verify ALL before starting):
  1. No long-running transactions (> 30 minutes) currently executing
  2. Replication lag between primary and replica < 30 seconds
  3. Last successful backup completed within 4 hours
  4. DBA on-call has confirmed availability to monitor
  5. Business confirmation that off-peak period is in effect

PATCH ORDER FOR HIGH-AVAILABILITY DATABASE PAIR:
  Step 1: Verify DB-PROD-02 (replica) is fully in sync with DB-PROD-01 (primary)
  Step 2: Patch DB-PROD-02 (replica) first — lower risk, no active writes
  Step 3: Validate DB-PROD-02 fully healthy (see PB-005) — takes 30 minutes
  Step 4: Verify replication resumed between patched replica and unpatched primary
  Step 5: Initiate planned failover — promote DB-PROD-02 as new primary
  Step 6: Verify application connections switch to new primary automatically
  Step 7: Now patch original primary DB-PROD-01 (now acting as replica)
  Step 8: Validate DB-PROD-01 healthy
  Step 9: Restore original primary/replica configuration (optional — may leave as-is)

NEVER DO:
  - Never patch both DB servers simultaneously
  - Never patch while replication is lagging > 60 seconds
  - Never initiate failover during a database backup window
  - Never patch a database server without a DBA available to respond

ESTIMATED TOTAL TIME: 4-6 hours for a full HA database pair patching cycle
""",
    },
    {
        "id": "PB-008",
        "category": "linux",
        "title": "Linux Server Patching Procedure (Ubuntu)",
        "content": """
LINUX PATCHING PROCEDURE — Ubuntu 20.04 LTS and 22.04 LTS

PRE-PATCH STEPS:
  1. Take a snapshot or backup if environment supports it
  2. Check current kernel version: uname -r
  3. Review pending updates: apt list --upgradable 2>/dev/null
  4. Check disk space: df -h / (need at least 2GB free)
  5. Record list of running services: systemctl list-units --type=service --state=running

APPLYING SECURITY PATCHES:
  # Update package lists
  sudo apt-get update
  
  # Apply only security patches (recommended for production):
  sudo apt-get install --only-upgrade $(apt-get --just-print upgrade 2>&1 | grep "^Inst" | grep -i security | awk '{print $2}')
  
  # OR apply all pending updates:
  sudo DEBIAN_FRONTEND=noninteractive apt-get upgrade -y
  
  # For specific USN patches, install the specific package:
  sudo apt-get install --only-upgrade <package-name>=<version>

KERNEL UPDATES (requires reboot):
  After installing a kernel update, schedule reboot during maintenance window.
  Do NOT use kexec for production kernel updates — always do a clean reboot.
  Check if reboot is required: cat /var/run/reboot-required

POST-PATCH STEPS:
  1. Verify kernel version updated if kernel patch applied: uname -r
  2. Verify services are running: systemctl status nginx gunicorn redis (etc.)
  3. Check auth.log and syslog for errors
  4. Verify application health endpoint responds correctly
  5. Clean up old kernels (keep last 2): sudo apt-get autoremove
""",
    },
    {
        "id": "PB-009",
        "category": "windows",
        "title": "Windows Server Patching Procedure",
        "content": """
WINDOWS SERVER PATCHING PROCEDURE — Windows Server 2019 and 2022

PRE-PATCH STEPS:
  1. Create system checkpoint or VM snapshot if available
  2. Check pending updates: Get-WindowsUpdate (requires PSWindowsUpdate module)
  3. Verify sufficient disk space on C: (need 10GB free minimum for Windows updates)
  4. Check Windows Update service is running: Get-Service wuauserv
  5. Export list of running services for comparison post-patch

APPLYING PATCHES via PowerShell (WSUS or Windows Update):
  # Install PSWindowsUpdate module if not present:
  Install-Module PSWindowsUpdate -Force
  
  # List available updates:
  Get-WindowsUpdate
  
  # Install all updates without auto-reboot:
  Install-WindowsUpdate -AcceptAll -IgnoreReboot
  
  # Install specific KB:
  Install-WindowsUpdate -KBArticleID "KB5034441" -AcceptAll -IgnoreReboot
  
  # Verify patch applied:
  Get-HotFix -Id KB5034441

POST-PATCH REBOOT SEQUENCE:
  1. Drain connections if behind load balancer (remove from rotation first)
  2. Schedule reboot: shutdown /r /t 300 /c "Scheduled patch reboot"
  3. Wait for server to come back online (max 20 minutes for Windows)
  4. Verify all services started: Get-Service | Where-Object {$_.Status -eq 'Running'}
  5. Add server back to load balancer rotation
  6. Confirm HTTP health endpoint responds before proceeding

VERIFYING PATCH APPLICATION:
  Get-HotFix | Sort-Object InstalledOn -Descending | Select -First 10
""",
    },
    {
        "id": "PB-010",
        "category": "incident",
        "title": "Patch-Related Incident Response",
        "content": """
PATCH-RELATED INCIDENT RESPONSE — When patching causes production issues

INCIDENT CLASSIFICATION:
  P1 — Complete service outage caused by patch: Immediate rollback, page on-call
  P2 — Partial service degradation: Rollback if > 20% error rate, escalate to team
  P3 — Minor issue (slow performance, non-critical service down): Monitor, may rollback
  P4 — Cosmetic/logging issue: Document, continue, fix in next cycle

IMMEDIATE RESPONSE STEPS (patch-agent handles autonomously):
  1. Stop all further patching operations across the fleet immediately
  2. Check if the issue is on multiple servers (systemic) or one server (isolated)
  3. If systemic (3+ servers affected): Pause entire batch, escalate to human
  4. If isolated (1 server): Trigger rollback per PB-006
  5. Create P1/P2 incident ticket with: affected server, patch ID, error details, timeline

COMMUNICATION TEMPLATE:
  [PATCH INCIDENT ALERT]
  Time: {timestamp}
  Severity: {p1/p2/p3}
  Affected: {server_name}
  Patch: {patch_id} — {patch_title}
  Issue: {description_of_problem}
  Action taken: {rollback/monitoring/escalation}
  Next step: {what_happens_next}

POST-INCIDENT REVIEW:
  - Root cause analysis within 24 hours
  - Check Microsoft/Ubuntu vendor advisories for known issues
  - Update patch compatibility notes in knowledge base
  - Consider creating exclusion rule for this patch on this OS version
""",
    },
    {
        "id": "PB-011",
        "category": "prioritisation",
        "title": "Patch Prioritisation Decision Framework",
        "content": """
PATCH PRIORITISATION FRAMEWORK — How to decide what patches to apply first

PRIORITY SCORE CALCULATION:
  Score = (CVE_Score × 10) + Environment_Weight + Recency_Weight + Exposure_Weight

  CVE_Score: 0-10 (CVSS v3 score, multiply by 10 = 0-100 points)
  
  Environment_Weight:
    production + critical role = 50 points
    production + high role = 40 points
    production + medium role = 25 points
    staging = 5 points
    
  Recency_Weight (days since patch was released):
    0-7 days old = 30 points (very fresh, verify stability first)
    8-30 days old = 50 points (stable, high priority)
    31-90 days old = 40 points (still important)
    90+ days old = 60 points (overdue, must patch now)
    
  Exposure_Weight (internet-facing vs internal):
    Internet-facing server = 30 points
    Internal server = 0 points

EXAMPLE CALCULATION:
  Web server (internet-facing, production, high role), CVSS 9.8, patch 15 days old:
  Score = (9.8 × 10) + 40 + 50 + 30 = 98 + 40 + 50 + 30 = 218 points → PATCH IMMEDIATELY

TOP PRIORITY INDICATORS (always patch these first regardless of score):
  - Any CVE with known active exploitation in the wild
  - Any patch labeled "Wormable" (can spread server-to-server without user interaction)
  - Any patch affecting authentication or encryption (SSH, TLS, Kerberos)
  - Microsoft Patch Tuesday "Critical" patches for systems not patched in 60+ days
""",
    },
    {
        "id": "PB-012",
        "category": "compliance",
        "title": "Patch Compliance Reporting Requirements",
        "content": """
PATCH COMPLIANCE REPORTING — Standards and audit requirements

COMPLIANCE TARGETS:
  Critical patches (CVSS >= 9.0): 100% of servers patched within 72 hours
  Important patches (CVSS 7.0-8.9): 100% of servers patched within 14 days
  Moderate patches (CVSS 4.0-6.9): 95% of servers patched within 30 days
  Low/Quality patches: 90% of servers patched within 90 days

COMPLIANCE METRICS TO TRACK:
  1. Mean Time to Patch (MTTP): Average time from patch release to deployment
  2. Patch Compliance Rate: % of applicable servers patched within SLA
  3. Failed Patch Rate: % of patch attempts that required rollback
  4. Reboot Compliance: % of servers rebooted to complete pending patches

MONTHLY COMPLIANCE REPORT CONTENTS:
  - Executive summary: overall compliance % vs target
  - Servers with overdue critical patches (RED status)
  - Servers with overdue important patches (AMBER status)
  - Patch deployment timeline for past month
  - Failed patches and root cause summary
  - Upcoming patches scheduled for next month

AUDIT EVIDENCE REQUIREMENTS:
  Each patch record must contain:
  - Date/time of patch application
  - Patch ID and CVE IDs addressed
  - Server name and environment
  - Applied by: patch-agent (automated) or human (manual)
  - Pre-patch health status
  - Post-patch health status
  - Approver name/ID
  - Any deviations from standard procedure and justification
""",
    },
    {
        "id": "PB-013",
        "category": "testing",
        "title": "Patch Testing and Staging Validation Procedure",
        "content": """
STAGING VALIDATION PROCEDURE — Required before any production patching

WHY STAGING FIRST IS NON-NEGOTIABLE:
  Patches occasionally break application functionality even when OS-level health is fine.
  Staging exists to catch these application-layer breaks before they hit production.
  Even "well-tested" vendor patches have caused production outages on enterprise systems.

STAGING TEST SEQUENCE:
  1. Apply patch to all staging servers (WEB-STG-01, APP-STG-01, DB-STG-01)
  2. Run automated smoke test suite against staging environment
  3. Verify staging application behaves identically to pre-patch behaviour
  4. Run load test at 50% of production peak load — check for performance regression
  5. Leave staging running for minimum 24 hours (soak period)
  6. Check application error rates vs pre-patch baseline in staging logs
  7. Only if ALL checks pass: proceed to production Batch A

WHAT TO TEST IN STAGING:
  - All critical application workflows (login, main transaction, data retrieval)
  - Database query performance (run top 10 slowest queries, compare timing)
  - SSL/TLS certificate validity (some patches affect TLS libraries)
  - Third-party integrations still functioning (APIs, webhooks, auth providers)
  - Scheduled jobs / cron tasks executing correctly

STAGING SIGN-OFF CRITERIA:
  - Zero new application errors introduced by the patch
  - Response time degradation < 10% vs pre-patch baseline
  - All automated smoke tests passing
  - No new errors in application log in the 4 hours before sign-off
""",
    },
    {
        "id": "PB-014",
        "category": "emergency",
        "title": "Emergency Zero-Day Patching Procedure",
        "content": """
EMERGENCY ZERO-DAY PATCH PROCEDURE — For actively exploited vulnerabilities

DEFINITION: A zero-day patch procedure is triggered when:
  - CISA adds vulnerability to Known Exploited Vulnerabilities (KEV) catalog
  - Vendor issues emergency out-of-band security advisory
  - Threat intelligence indicates active exploitation in the wild
  - CVSS score >= 9.5 with no mitigations available

IMMEDIATE ACTIONS (within 1 hour of vulnerability confirmation):
  1. Notify change manager, CISO, and infrastructure lead immediately
  2. Assess blast radius: which servers are affected and internet-facing?
  3. If patch available: initiate emergency change, skip standard scheduling
  4. If no patch yet available: implement mitigations (WAF rules, disable feature, network isolation)
  5. Internet-facing servers MUST be patched or mitigated within 24 hours, no exceptions

EMERGENCY PATCHING SEQUENCE:
  1. Apply to staging immediately (no 24-hour soak — emergency exception)
  2. Verify staging healthy (30-minute validation instead of 24-hour)
  3. Apply to production in single batch (emergency exception to normal batch sequencing)
  4. Post-emergency review to establish whether any exploitation occurred before patching

TEMPORARY MITIGATION OPTIONS (while waiting for patch):
  - Web Application Firewall (WAF) rules to block exploit patterns
  - Network segmentation to isolate vulnerable servers
  - Disable the vulnerable feature/service if business accepts the downtime
  - IDS/IPS signatures for the specific CVE

COMMUNICATION REQUIRED:
  - Every 2 hours until resolved: status update to change manager
  - Final report within 24 hours of resolution: what happened, what was done, timeline
""",
    },
    {
        "id": "PB-015",
        "category": "lessons",
        "title": "Historical Patch Incidents and Lessons Learned",
        "content": """
HISTORICAL PATCH INCIDENTS — Lessons learned for future operations

INCIDENT 1: KB5012599 caused IIS application pool crash (March 2023)
  Root cause: Patch updated ASP.NET runtime, breaking custom session handler
  Affected: WEB-PROD-01, WEB-PROD-02 — 45 minutes of service disruption
  Resolution: Rolled back patch, applied application code fix, re-patched 2 weeks later
  Lesson: Always test IIS-heavy patches in staging with full application workload

INCIDENT 2: Ubuntu kernel update broke network driver (June 2023)
  Root cause: Kernel 5.15.0-73 had regression in vmxnet3 driver used by VMware VMs
  Affected: APP-PROD-01 — 20 minutes offline, required manual reboot from console
  Resolution: Pinned kernel version, applied vendor hotfix, upgraded to 5.15.0-75
  Lesson: For VMware-hosted Linux VMs, verify kernel compatibility with vSphere version

INCIDENT 3: SQL Server patch triggered transaction log expansion (September 2023)
  Root cause: KB5029379 included schema changes requiring transaction log growth
  Affected: DB-PROD-01 — disk almost full, 15-minute performance degradation
  Resolution: Pre-expanded transaction log before patching DB servers
  Lesson: Always check SQL Server patch notes for schema changes; pre-expand log to 150% capacity

INCIDENT 4: Windows Defender update caused false-positive on application binary (November 2023)
  Root cause: New malware signature matched internal application executable
  Affected: All Windows servers — application quarantined and unavailable
  Resolution: Added application binary to Defender exclusion list, re-released
  Lesson: After Defender signature updates, immediately verify key application binaries still run

KNOWN COMPATIBILITY ISSUES (current):
  - KB5031539 on Server 2022 with older Intel NIC drivers: can cause NIC reset on reboot
    Mitigation: Update Intel NIC drivers to v26.7+ before applying KB5031539
  - USN-6607 on Ubuntu 20.04 with custom kernel modules: may need module recompilation
    Mitigation: Verify all custom kernel modules are compatible before applying kernel patch
""",
    },
]


# ─────────────────────────────────────────────
#  PUBLIC FUNCTIONS
# ─────────────────────────────────────────────

def initialise_knowledge_base(force_reload: bool = False) -> str:
    """
    Loads all patch playbooks into ChromaDB.
    Only reloads if the collection is empty or force_reload=True.
    Returns a status message.
    """
    collection = get_collection()

    # Check if already populated
    existing_count = collection.count()
    if existing_count >= len(PATCH_PLAYBOOKS) and not force_reload:
        return f"Knowledge base already populated ({existing_count} documents). Skipping reload."

    # Clear if force reloading
    if force_reload and existing_count > 0:
        client = get_chroma_client()
        client.delete_collection(COLLECTION_NAME)
        collection = get_collection()

    # Add all playbooks
    documents = [pb["content"] for pb in PATCH_PLAYBOOKS]
    metadatas = [
        {"id": pb["id"], "category": pb["category"], "title": pb["title"]}
        for pb in PATCH_PLAYBOOKS
    ]
    ids = [pb["id"] for pb in PATCH_PLAYBOOKS]

    collection.add(documents=documents, metadatas=metadatas, ids=ids)

    return f"Knowledge base initialised with {len(PATCH_PLAYBOOKS)} playbooks."


def query_knowledge_base(query: str, n_results: int = 3) -> list[dict]:
    """
    Queries the knowledge base with a natural language query.
    Returns the most relevant playbook excerpts for the agent to use.

    AZURE SWAP: Replace ChromaDB query with Azure AI Search:
      from azure.search.documents import SearchClient
      results = search_client.search(search_text=query, top=n_results)
    """
    collection = get_collection()

    if collection.count() == 0:
        initialise_knowledge_base()

    results = collection.query(
        query_texts=[query],
        n_results=min(n_results, collection.count()),
        include=["documents", "metadatas", "distances"],
    )

    formatted_results = []
    if results and results["documents"] and results["documents"][0]:
        for i, doc in enumerate(results["documents"][0]):
            formatted_results.append({
                "playbook_id": results["metadatas"][0][i]["id"],
                "category": results["metadatas"][0][i]["category"],
                "title": results["metadatas"][0][i]["title"],
                "content": doc,
                "relevance_score": round(1 - results["distances"][0][i], 3),
            })

    return formatted_results


def get_playbook_by_id(playbook_id: str) -> dict | None:
    """Retrieves a specific playbook by its ID (e.g. 'PB-001')."""
    return next((pb for pb in PATCH_PLAYBOOKS if pb["id"] == playbook_id), None)


def get_playbooks_by_category(category: str) -> list[dict]:
    """Returns all playbooks for a given category (e.g. 'rollback', 'scheduling')."""
    return [pb for pb in PATCH_PLAYBOOKS if pb["category"] == category]


def store_patch_outcome(
    hostname: str,
    patch_id: str,
    outcome: str,
    notes: str,
) -> str:
    """
    Stores the outcome of a patch operation in the knowledge base for future reference.
    This is how the agent learns from experience over time.

    outcome: 'success', 'failed', 'rolled_back'
    notes: free text describing what happened
    """
    collection = get_collection()

    doc_id = f"OUTCOME-{hostname}-{patch_id}-{len(collection.get()['ids'])}"
    document = f"""
PATCH OUTCOME RECORD
Server: {hostname}
Patch: {patch_id}
Outcome: {outcome}
Notes: {notes}
"""
    collection.add(
        documents=[document],
        metadatas=[{
            "id": doc_id,
            "category": "outcome",
            "title": f"Patch {patch_id} on {hostname}: {outcome}",
            "hostname": hostname,
            "patch_id": patch_id,
            "outcome": outcome,
        }],
        ids=[doc_id],
    )

    return f"Patch outcome recorded: {doc_id}"


if __name__ == "__main__":
    # Quick test: initialise and run a sample query
    print(initialise_knowledge_base())
    results = query_knowledge_base("how to rollback a failed patch on a production server")
    for r in results:
        print(f"\n[{r['playbook_id']}] {r['title']} (relevance: {r['relevance_score']})")
        print(r["content"][:300] + "...")