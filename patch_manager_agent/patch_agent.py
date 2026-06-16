"""
patch_agent.py
==============
The Patch Manager Agent — built with LangGraph.

ARCHITECTURE — 5 Nodes in a directed graph:

  [collect_data_node]
        |
        v
  [analyse_and_plan_node]  ← LLM first sees data here
        |
        v
  [approval_gate_node]     ← checks if approval needed
        |
        ├──(needs approval)──→ [request_approval_node] → END
        |
        └──(approved / staging)──→ [execute_patches_node]
                                          |
                                          v
                                   [report_node] → END

WHY THIS STRUCTURE:
  Following the lesson learned from Infra Monitoring Agent:
  Llama 3.2 via Ollama does NOT reliably call tools autonomously.
  So we never ask the LLM to decide "what tool to call next."
  Instead, Python calls the tools in collect_data_node,
  and the LLM only ever sees structured data and writes analysis.

AZURE SWAP:
  Only two changes needed when Azure access arrives:
  1. Replace OllamaLLM with AzureChatOpenAI in get_llm()
  2. The tool functions in patch_tools.py swap their data sources
  Nothing in this file changes.
"""

import json
from datetime import datetime
from typing import TypedDict, Optional, List, Any

from langchain_ollama import OllamaLLM
from langgraph.graph import StateGraph, END

from patch_tools import (
    tool_scan_patch_inventory,
    tool_build_patch_schedule,
    tool_query_kb,
    tool_generate_compliance_report,
    tool_apply_batch,
    tool_run_health_check,
    tool_get_server_patch_history,
    tool_check_maintenance_window,
)
from patch_knowledge_base import initialise_knowledge_base


# ─────────────────────────────────────────────
#  LLM SETUP
#  AZURE SWAP: Replace this function body with:
#    from langchain_openai import AzureChatOpenAI
#    return AzureChatOpenAI(
#        azure_deployment="gpt-4o",
#        azure_endpoint=os.getenv("AZURE_OPENAI_ENDPOINT"),
#        api_key=os.getenv("AZURE_OPENAI_KEY"),
#        api_version="2024-02-01",
#    )
# ─────────────────────────────────────────────

def get_llm():
    """Returns the LLM instance. Swap this for Azure in production."""
    return OllamaLLM(model="llama3.2", temperature=0.1)


# ─────────────────────────────────────────────
#  STATE SCHEMA
#  Everything the agent knows at any point in
#  its execution. Passed between all nodes.
# ─────────────────────────────────────────────

class PatchAgentState(TypedDict):
    # INPUT — set by whoever calls the agent
    task_type: str              # 'scan', 'patch_all', 'patch_server', 'compliance_report',
                                # 'patch_history', 'emergency_patch'
    task_input: dict            # Any extra parameters for the task
    test_mode: bool             # If True, never actually apply patches (dry run)
    force_approved: bool        # If True, skip approval gate (for testing)

    # DATA — populated by collect_data_node
    scan_results: Optional[dict]
    patch_schedule: Optional[dict]
    compliance_report: Optional[dict]
    server_history: Optional[dict]
    knowledge_base_results: Optional[list]
    maintenance_windows: Optional[dict]

    # ANALYSIS — populated by analyse_and_plan_node (LLM output)
    llm_analysis: Optional[str]
    patch_plan_summary: Optional[str]
    risk_assessment: Optional[str]
    recommended_action: Optional[str]

    # APPROVAL — populated by approval_gate_node
    needs_approval: bool
    approval_reason: Optional[str]
    approval_status: Optional[str]   # 'approved', 'pending', 'denied'

    # EXECUTION — populated by execute_patches_node
    execution_results: Optional[dict]
    patches_applied: int
    patches_failed: int
    patches_rolled_back: int

    # OUTPUT — final report (populated by report_node)
    final_report: Optional[str]
    agent_status: str            # 'running', 'awaiting_approval', 'complete', 'error'
    error_message: Optional[str]


# ─────────────────────────────────────────────
#  NODE 1: COLLECT DATA
#  Pure Python — NO LLM here.
#  Runs all necessary tool calls and stores
#  results in state for the LLM to read.
# ─────────────────────────────────────────────

def collect_data_node(state: PatchAgentState) -> PatchAgentState:
    """
    Collects all data the agent needs before the LLM is involved.
    This prevents the Ollama hallucination problem.
    The LLM will only ever see REAL data, never invent it.
    """
    print("\n" + "="*60)
    print("NODE 1: COLLECT DATA")
    print("="*60)

    task_type = state["task_type"]
    task_input = state.get("task_input", {})

    # Ensure knowledge base is ready before any queries
    initialise_knowledge_base()

    # ── SCAN task: get patch inventory for all servers
    if task_type in ("scan", "patch_all", "emergency_patch"):
        print("[Node 1] Scanning full patch inventory...")
        scan = tool_scan_patch_inventory(
            filter_severity=task_input.get("filter_severity")
        )
        state["scan_results"] = scan

        # Also build the deployment schedule so LLM can see the full picture
        if scan["total_servers_with_patches"] > 0:
            print("[Node 1] Building patch deployment schedule...")
            schedule = tool_build_patch_schedule(scan)
            state["patch_schedule"] = schedule

        # Get relevant playbooks for this type of task
        print("[Node 1] Querying knowledge base for patching procedures...")
        if task_type == "emergency_patch":
            kb_query = "emergency zero-day patching procedure urgent critical vulnerability"
        else:
            kb_query = "patch scheduling batching approval compliance production"
        kb_results = tool_query_kb(kb_query, n_results=3)
        state["knowledge_base_results"] = kb_results.get("playbooks", [])

    # ── COMPLIANCE_REPORT task: generate full fleet report
    elif task_type == "compliance_report":
        print("[Node 1] Generating compliance report...")
        report = tool_generate_compliance_report()
        state["compliance_report"] = report

        print("[Node 1] Also scanning for pending patches...")
        scan = tool_scan_patch_inventory()
        state["scan_results"] = scan

        kb_results = tool_query_kb("patch compliance reporting requirements audit", n_results=2)
        state["knowledge_base_results"] = kb_results.get("playbooks", [])

    # ── PATCH_SERVER task: targeted patching of one server
    elif task_type == "patch_server":
        hostname = task_input.get("hostname", "").upper()
        print(f"[Node 1] Getting patch info for specific server: {hostname}")

        # Get pending patches for just this server
        from patch_inventory import get_available_patches, get_server_details
        server = get_server_details(hostname)
        pending = get_available_patches(hostname)

        state["scan_results"] = {
            "scan_timestamp": datetime.now().isoformat(),
            "total_servers_with_patches": 1 if pending else 0,
            "total_pending_patches": len(pending),
            "critical_patch_count": sum(1 for p in pending if p["severity"] == "critical"),
            "important_patch_count": sum(1 for p in pending if p["severity"] == "important"),
            "servers": [{
                "hostname": hostname,
                "role": server["role"] if server else "Unknown",
                "os": server["os"] if server else "Unknown",
                "environment": server["environment"] if server else "Unknown",
                "criticality": server["criticality"] if server else "Unknown",
                "last_patched": server["last_patched"] if server else "Unknown",
                "maintenance_window": server["maintenance_window"] if server else "Unknown",
                "pending_patches": pending,
            }] if server else [],
            "summary": f"Server {hostname}: {len(pending)} patches pending",
        }

        # Check maintenance window
        if server:
            window_check = tool_check_maintenance_window(hostname)
            state["maintenance_windows"] = {hostname: window_check}

        kb_results = tool_query_kb(f"patching single server production approval procedure", n_results=2)
        state["knowledge_base_results"] = kb_results.get("playbooks", [])

    # ── PATCH_HISTORY task: show history for a server
    elif task_type == "patch_history":
        hostname = task_input.get("hostname", "").upper()
        print(f"[Node 1] Getting patch history for: {hostname}")

        history = tool_get_server_patch_history(hostname)
        state["server_history"] = history

        kb_results = tool_query_kb("patch history compliance audit server records", n_results=2)
        state["knowledge_base_results"] = kb_results.get("playbooks", [])

    print("[Node 1] Data collection complete.")
    state["agent_status"] = "running"
    return state


# ─────────────────────────────────────────────
#  NODE 2: ANALYSE AND PLAN
#  The LLM's first and main involvement.
#  It sees all the collected data and produces
#  an analysis, risk assessment, and plan.
# ─────────────────────────────────────────────

def analyse_and_plan_node(state: PatchAgentState) -> PatchAgentState:
    """
    The LLM reads all collected data and produces:
    - An analysis of the patch situation
    - A risk assessment
    - A recommended course of action
    - A plain-English summary of the patch plan
    """
    print("\n" + "="*60)
    print("NODE 2: ANALYSE AND PLAN (LLM)")
    print("="*60)

    llm = get_llm()
    task_type = state["task_type"]

    # Build context from collected data
    context_parts = []

   if state.get("scan_results"):
        scan = state["scan_results"]
        # Send compact summary only — full JSON is too large for llama3.2
        top_servers = scan.get('servers', [])[:5]  # top 5 only
        server_lines = "\n".join([
            f"  - {s['hostname']} ({s['environment']}, {s['criticality']}) "
            f"— {s['pending_patch_count']} patches, highest CVE: {s['highest_cve_score']}, "
            f"last patched: {s['days_since_patched']} days ago"
            for s in top_servers
        ])
        context_parts.append(f"""
=== PATCH SCAN RESULTS ===
Scan Time: {scan.get('scan_timestamp', 'Unknown')}
Servers with pending patches: {scan.get('total_servers_with_patches', 0)}
Total pending patches: {scan.get('total_pending_patches', 0)}
Critical patches: {scan.get('critical_patch_count', 0)}
Important patches: {scan.get('important_patch_count', 0)}

Top priority servers (showing 5 of {scan.get('total_servers_with_patches', 0)}):
{server_lines}
""")

    if state.get("patch_schedule"):
        sched = state["patch_schedule"]
        context_parts.append(f"""
=== DEPLOYMENT SCHEDULE ===
Total batches: {sched.get('batch_count', 0)}
Estimated total duration: {sched.get('estimated_total_duration_hours', 0)} hours
Schedule notes: {json.dumps(sched.get('schedule_notes', []), indent=2)}

Deployment plan:
{json.dumps(sched.get('deployment_plan', []), indent=2)}
""")

Batches: {[b['batch_name'] for b in sched.get('deployment_plan', [])]}
Estimated duration: {sched.get('estimated_total_duration_hours', 0)} hours
Notes: {sched.get('schedule_notes', [])[:3]}

    if state.get("compliance_report"):
        comp = state["compliance_report"]
        context_parts.append(f"""
=== COMPLIANCE REPORT ===
{json.dumps(comp, indent=2)}
""")

    if state.get("server_history"):
        hist = state["server_history"]
        context_parts.append(f"""
=== SERVER PATCH HISTORY ===
{json.dumps(hist, indent=2)}
""")

    if state.get("knowledge_base_results"):
        kb_content = "\n\n".join([
            f"[{r['playbook_id']}] {r['title']}:\n{r['content'][:600]}..."
            for r in state["knowledge_base_results"]
        ])
        context_parts.append(f"""
=== RELEVANT PROCEDURES FROM KNOWLEDGE BASE ===
{kb_content}
""")

    if state.get("maintenance_windows"):
        context_parts.append(f"""
=== MAINTENANCE WINDOW STATUS ===
{json.dumps(state['maintenance_windows'], indent=2)}
""")

    full_context = "\n".join(context_parts)

    # Task-specific instructions for the LLM
    task_instructions = {
        "scan": "Analyse the patch scan results. Identify the most urgent patches, explain the risk level, and outline the recommended patching approach.",
        "patch_all": "Review the scan results and deployment schedule. Assess risk, confirm the batch ordering is correct, and provide a clear go/no-go recommendation with reasoning.",
        "patch_server": "Analyse the pending patches for this specific server. Assess risk and provide a clear recommendation on whether to patch now or wait.",
        "compliance_report": "Analyse the compliance report. Identify servers most at risk, highlight overdue patches, and provide an executive summary with prioritised action items.",
        "patch_history": "Review the patch history for this server. Assess whether the patching cadence is acceptable, identify any gaps, and recommend next steps.",
        "emergency_patch": "This is an EMERGENCY patch scenario. Treat with highest urgency. Assess the critical vulnerabilities, recommend immediate action steps, and note any risks of rapid deployment.",
    }

    instruction = task_instructions.get(task_type, "Analyse the patch management situation and provide recommendations.")

    # Build the full prompt
    prompt = f"""You are the Patch Manager AI Agent for an enterprise IT operations platform.
Your job is to manage software patching across a fleet of 12 servers — web, application, database, 
monitoring, and management servers.

TASK TYPE: {task_type.upper()}
INSTRUCTION: {instruction}

Here is all the current data collected from the infrastructure:
{full_context}

Please provide your analysis in this EXACT format:

SITUATION SUMMARY:
[2-3 sentences describing the current patching situation]

RISK ASSESSMENT:
[What are the security/operational risks if patching is delayed or done incorrectly?]

PRIORITY PATCHES:
[List the top 3-5 most critical patches that need immediate attention, with justification]

RECOMMENDED ACTION:
[Clear, specific steps the agent should take. Be concrete — which servers, which patches, in what order]

APPROVAL REQUIRED:
[State clearly: YES or NO. If YES, explain why and what level of approval is needed]

ESTIMATED IMPACT:
[What is the expected impact on operations? Any downtime? Risk of rollback needed?]
"""

    print("[Node 2] Sending data to LLM for analysis...")
    print(f"[Node 2] Context size: {len(full_context)} characters")

    try:
        analysis = llm.invoke(prompt)
        state["llm_analysis"] = analysis

        # Extract key fields from LLM output
        lines = analysis.lower()

        # Check if LLM says approval is needed
        if "approval required:" in lines:
            approval_section = analysis[analysis.lower().find("approval required:"):].split("\n")[0]
            if "yes" in approval_section.lower():
                state["needs_approval"] = True
                state["approval_reason"] = "LLM analysis indicates approval required for production changes"
            else:
                state["needs_approval"] = False
        else:
            # Default: production patches need approval unless forced
            is_prod = any(
                s.get("environment") == "production"
                for s in state.get("scan_results", {}).get("servers", [])
            )
            state["needs_approval"] = is_prod and not state.get("force_approved", False)

        # Extract recommended action
        if "recommended action:" in lines:
            start = analysis.lower().find("recommended action:")
            end_markers = ["estimated impact:", "approval required:", "priority patches:"]
            end = len(analysis)
            for marker in end_markers:
                marker_pos = analysis.lower().find(marker, start + 1)
                if marker_pos != -1 and marker_pos < end:
                    end = marker_pos
            state["recommended_action"] = analysis[start:end].strip()

        print("[Node 2] LLM analysis complete.")
        print(f"\n{'='*50}\nLLM ANALYSIS:\n{'='*50}")
        print(analysis)
        print("="*50)

    except Exception as e:
        print(f"[Node 2] LLM error: {e}")
        state["llm_analysis"] = f"LLM analysis unavailable: {str(e)}"
        state["needs_approval"] = True  # Default to requiring approval on error
        state["error_message"] = str(e)

    return state


# ─────────────────────────────────────────────
#  NODE 3: APPROVAL GATE
#  Pure Python. Decides whether to proceed to
#  execution or pause for human approval.
# ─────────────────────────────────────────────

def approval_gate_node(state: PatchAgentState) -> PatchAgentState:
    """
    The approval gate. For production patches, either:
    A) Proceeds automatically if force_approved=True (testing mode)
    B) Pauses and requests human approval
    C) Auto-approves staging patches (no approval needed)

    This node sets approval_status which the conditional edge reads.
    """
    print("\n" + "="*60)
    print("NODE 3: APPROVAL GATE")
    print("="*60)

    task_type = state["task_type"]
    test_mode = state.get("test_mode", False)
    force_approved = state.get("force_approved", False)

    # In test mode: auto-approve everything but don't actually execute
    if test_mode:
        print("[Node 3] TEST MODE — Auto-approving (no real patches will be applied)")
        state["approval_status"] = "approved"
        state["approval_reason"] = "Test mode — automatic approval, no real execution"
        return state

    # Force approved flag (for integration testing)
    if force_approved:
        print("[Node 3] FORCE APPROVED — Proceeding to execution")
        state["approval_status"] = "approved"
        state["approval_reason"] = "Force approved flag set by caller"
        return state

    # Staging patches — always approved
    scan = state.get("scan_results", {})
    all_servers = scan.get("servers", [])
    all_staging = all(s.get("environment") in ("staging",) for s in all_servers)

    if all_staging and all_servers:
        print("[Node 3] All servers are staging — auto-approved")
        state["approval_status"] = "approved"
        state["approval_reason"] = "Staging environment — no approval required"
        return state

    # Emergency patch — still needs notification but can proceed faster
    if task_type == "emergency_patch":
        print("[Node 3] EMERGENCY PATCH — Change manager notification sent. Proceeding in 5 minutes if no objection.")
        state["approval_status"] = "approved"
        state["approval_reason"] = "Emergency patch procedure — change manager notified, auto-proceeding"
        return state

    # Production patches — need explicit approval
    if state.get("needs_approval", True):
        print("[Node 3] PRODUCTION CHANGES REQUIRE APPROVAL")
        print("[Node 3] Change request raised. Waiting for change manager approval...")
        state["approval_status"] = "pending"
        state["approval_reason"] = (
            "Production environment patch requires change manager approval. "
            "A change request has been raised. Re-run with force_approved=True "
            "once approval is confirmed, or set test_mode=True for a dry run."
        )
        state["agent_status"] = "awaiting_approval"
        return state

    # No approval needed
    state["approval_status"] = "approved"
    state["approval_reason"] = "No approval required for this operation"
    return state


# ─────────────────────────────────────────────
#  NODE 4: REQUEST APPROVAL (dead-end path)
#  Called when approval is still pending.
#  Generates the approval request message.
# ─────────────────────────────────────────────

def request_approval_node(state: PatchAgentState) -> PatchAgentState:
    """
    Generates a detailed change request / approval notification.
    This is where the agent pauses and hands control back to humans.
    The agent run ends here — humans re-trigger it once approved.
    """
    print("\n" + "="*60)
    print("NODE 4: REQUEST APPROVAL")
    print("="*60)

    scan = state.get("scan_results", {})
    schedule = state.get("patch_schedule", {})

    # Build the change request
    change_request = f"""
╔══════════════════════════════════════════════════════════════╗
║            PATCH MANAGER — CHANGE REQUEST                     ║
╚══════════════════════════════════════════════════════════════╝

REQUEST ID:    PCH-{datetime.now().strftime('%Y%m%d-%H%M%S')}
RAISED BY:     Patch Manager Agent (Automated)
DATE/TIME:     {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
PRIORITY:      {'CRITICAL' if scan.get('critical_patch_count', 0) > 0 else 'STANDARD'}

SCOPE OF CHANGE:
  Servers affected: {scan.get('total_servers_with_patches', 0)}
  Total patches:    {scan.get('total_pending_patches', 0)}
  Critical patches: {scan.get('critical_patch_count', 0)}
  Important patches:{scan.get('important_patch_count', 0)}

AFFECTED SERVERS:
{chr(10).join(f"  - {s['hostname']} ({s['role']}, {s['environment']})" for s in scan.get('servers', [])[:10])}

ESTIMATED DURATION: {schedule.get('estimated_total_duration_hours', 'Unknown')} hours

AGENT ANALYSIS:
{state.get('llm_analysis', 'Analysis not available')[:500]}...

APPROVAL REQUIRED FROM: Change Manager / Infrastructure Lead
APPROVAL METHOD: Re-run patch agent with force_approved=True

TO APPROVE:
  python run_patch_agent.py --task {state['task_type']} --force-approved

TO VIEW DRY RUN:
  python run_patch_agent.py --task {state['task_type']} --test-mode
"""

    print(change_request)
    state["final_report"] = change_request
    state["agent_status"] = "awaiting_approval"
    return state


# ─────────────────────────────────────────────
#  NODE 5: EXECUTE PATCHES
#  Only reached if approved.
#  If test_mode: simulates execution, no real changes.
# ─────────────────────────────────────────────

def execute_patches_node(state: PatchAgentState) -> PatchAgentState:
    """
    Executes the actual patch deployment.
    In test_mode: prints what would happen but applies nothing.
    In live mode: calls tool_apply_batch for each batch in the schedule.
    """
    print("\n" + "="*60)
    print("NODE 5: EXECUTE PATCHES")
    print("="*60)

    test_mode = state.get("test_mode", False)
    task_type = state["task_type"]
    task_input = state.get("task_input", {})
    scan = state.get("scan_results", {})
    schedule = state.get("patch_schedule", {})

    if test_mode:
        print("[Node 5] TEST MODE — Simulating execution without applying real patches")
        state["execution_results"] = {
            "mode": "test_mode_simulation",
            "note": "No real patches were applied. This is a dry run.",
            "would_have_patched": [
                {
                    "hostname": s["hostname"],
                    "patches": [p["patch_id"] for p in s.get("pending_patches", [])],
                }
                for s in scan.get("servers", [])
            ],
        }
        state["patches_applied"] = 0
        state["patches_failed"] = 0
        state["patches_rolled_back"] = 0
        return state

    # ── LIVE EXECUTION ──────────────────────────────────────────────

    all_results = []
    total_applied = 0
    total_failed = 0
    total_rolled_back = 0

    if task_type in ("patch_all", "emergency_patch") and schedule.get("deployment_plan"):
        # Execute the full deployment plan batch by batch
        for batch in schedule["deployment_plan"]:
            batch_name = batch["batch_name"]
            servers_in_batch = batch["servers"]

            print(f"\n[Node 5] Executing: {batch_name}")
            print(f"[Node 5] Servers: {servers_in_batch}")

            result = tool_apply_batch(
                batch_name=batch_name,
                servers=servers_in_batch,
                approved=True,  # Already approved — we passed the gate
            )
            all_results.append(result)

            total_applied += result.get("servers_patched", 0)
            total_failed += result.get("servers_failed", 0)
            total_rolled_back += result.get("servers_rolled_back", 0)

            # Stop if a batch had rollbacks — don't continue to next batch
            if not result.get("batch_success", True):
                print(f"[Node 5] ⚠️  Batch '{batch_name}' had failures — halting further batches")
                break

    elif task_type == "patch_server":
        # Single server patching
        hostname = task_input.get("hostname", "").upper()
        servers = [s for s in scan.get("servers", []) if s["hostname"] == hostname]

        result = tool_apply_batch(
            batch_name=f"Targeted patch of {hostname}",
            servers=[hostname],
            approved=True,
        )
        all_results.append(result)
        total_applied = result.get("servers_patched", 0)
        total_failed = result.get("servers_failed", 0)
        total_rolled_back = result.get("servers_rolled_back", 0)

    elif task_type in ("scan", "compliance_report", "patch_history"):
        # These tasks don't execute patches — they're read-only
        print(f"[Node 5] Task type '{task_type}' is read-only — no patches to apply")
        all_results = [{"note": "Read-only task — no patches applied"}]

    state["execution_results"] = {
        "batches_executed": len(all_results),
        "batch_details": all_results,
    }
    state["patches_applied"] = total_applied
    state["patches_failed"] = total_failed
    state["patches_rolled_back"] = total_rolled_back

    print(f"\n[Node 5] Execution complete: Applied={total_applied}, "
          f"Failed={total_failed}, Rolled_back={total_rolled_back}")
    return state


# ─────────────────────────────────────────────
#  NODE 6: REPORT
#  Final node. LLM generates the summary report.
# ─────────────────────────────────────────────

def report_node(state: PatchAgentState) -> PatchAgentState:
    """
    Final node. The LLM synthesises everything into a human-readable
    report covering what was done, what the results were, and what
    follow-up actions are needed.
    """
    print("\n" + "="*60)
    print("NODE 6: GENERATE REPORT")
    print("="*60)

    llm = get_llm()
    test_mode = state.get("test_mode", False)
    execution = state.get("execution_results", {})
    scan = state.get("scan_results", {})

    prompt = f"""You are the Patch Manager Agent. Generate a clear, professional patch management report.

TASK COMPLETED: {state['task_type'].upper()}
MODE: {'DRY RUN (Test Mode)' if test_mode else 'LIVE EXECUTION'}
TIMESTAMP: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

EXECUTION RESULTS:
  Servers patched successfully: {state.get('patches_applied', 0)}
  Servers failed: {state.get('patches_failed', 0)}
  Servers rolled back: {state.get('patches_rolled_back', 0)}

ORIGINAL SCAN DATA:
  Servers scanned: {scan.get('total_servers_with_patches', 'N/A')}
  Critical patches: {scan.get('critical_patch_count', 'N/A')}
  Important patches: {scan.get('important_patch_count', 'N/A')}

EXECUTION DETAILS:
{json.dumps(execution, indent=2)[:1500]}

PREVIOUS ANALYSIS:
{state.get('llm_analysis', 'Not available')[:500]}

Write a concise patch management report with these sections:
1. EXECUTIVE SUMMARY (2-3 sentences, what happened overall)
2. ACTIONS TAKEN (bullet list of what was done)
3. RESULTS (what succeeded, what failed, any rollbacks)
4. FOLLOW-UP REQUIRED (what needs human attention next)
5. COMPLIANCE STATUS (are we in a better compliance position now?)

Keep it professional and clear. This report will be read by the infrastructure manager."""

    try:
        report = llm.invoke(prompt)
    except Exception as e:
        report = f"Report generation failed: {e}. Manual review of execution_results required."

    # Build the final structured report
    final_report = f"""
╔══════════════════════════════════════════════════════════════╗
║          PATCH MANAGER AGENT — EXECUTION REPORT              ║
╚══════════════════════════════════════════════════════════════╝

Run ID:    PCH-EXEC-{datetime.now().strftime('%Y%m%d-%H%M%S')}
Task:      {state['task_type'].upper()}
Mode:      {'🧪 TEST MODE (Dry Run)' if test_mode else '⚡ LIVE EXECUTION'}
Status:    {'✅ COMPLETE' if state.get('patches_failed', 0) == 0 else '⚠️  COMPLETED WITH FAILURES'}
Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

METRICS:
  ✅ Servers patched:      {state.get('patches_applied', 0)}
  ❌ Servers failed:       {state.get('patches_failed', 0)}
  🔄 Servers rolled back:  {state.get('patches_rolled_back', 0)}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

{report}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
END OF REPORT — Patch Manager Agent v1.0
"""

    state["final_report"] = final_report
    state["agent_status"] = "complete"

    print("\n" + final_report)
    return state


# ─────────────────────────────────────────────
#  ROUTING FUNCTION
#  Decides which node to go to after approval gate
# ─────────────────────────────────────────────

def route_after_approval(state: PatchAgentState) -> str:
    """
    Conditional edge from approval_gate_node.
    Returns the name of the next node to run.
    """
    status = state.get("approval_status", "pending")

    if status == "approved":
        return "execute_patches"
    else:
        return "request_approval"


# ─────────────────────────────────────────────
#  BUILD THE GRAPH
# ─────────────────────────────────────────────

def build_patch_agent_graph():
    """
    Constructs the LangGraph state machine for the Patch Manager Agent.
    Call this once to get the compiled graph, then invoke it for each task.
    """
    graph = StateGraph(PatchAgentState)

    # Add all nodes
    graph.add_node("collect_data", collect_data_node)
    graph.add_node("analyse_and_plan", analyse_and_plan_node)
    graph.add_node("approval_gate", approval_gate_node)
    graph.add_node("request_approval", request_approval_node)
    graph.add_node("execute_patches", execute_patches_node)
    graph.add_node("report", report_node)

    # Define the main flow (edges)
    graph.set_entry_point("collect_data")
    graph.add_edge("collect_data", "analyse_and_plan")
    graph.add_edge("analyse_and_plan", "approval_gate")

    # Conditional edge after approval gate
    graph.add_conditional_edges(
        "approval_gate",
        route_after_approval,
        {
            "execute_patches": "execute_patches",
            "request_approval": "request_approval",
        },
    )

    # After execution and after approval request: go to report
    graph.add_edge("execute_patches", "report")
    graph.add_edge("request_approval", END)  # Ends here — human must re-trigger
    graph.add_edge("report", END)

    return graph.compile()


# ─────────────────────────────────────────────
#  MAIN ENTRY POINT (for direct testing)
# ─────────────────────────────────────────────

def run_patch_agent(
    task_type: str,
    task_input: dict = None,
    test_mode: bool = True,
    force_approved: bool = False,
) -> dict:
    """
    Main function to run the Patch Manager Agent.

    Args:
        task_type: One of 'scan', 'patch_all', 'patch_server',
                   'compliance_report', 'patch_history', 'emergency_patch'
        task_input: Optional dict with task parameters:
                    - For 'patch_server': {"hostname": "WEB-PROD-01"}
                    - For 'patch_history': {"hostname": "DB-PROD-01"}
                    - For 'scan': {"filter_severity": "critical"} (optional)
        test_mode: If True, never apply real patches (safe default)
        force_approved: If True, skip approval gate

    Returns:
        The final state dict after agent completion.
    """
    print(f"\n{'#'*60}")
    print(f"# PATCH MANAGER AGENT STARTING")
    print(f"# Task: {task_type.upper()}")
    print(f"# Test Mode: {test_mode}")
    print(f"# Force Approved: {force_approved}")
    print(f"{'#'*60}\n")

    agent = build_patch_agent_graph()

    initial_state: PatchAgentState = {
        "task_type": task_type,
        "task_input": task_input or {},
        "test_mode": test_mode,
        "force_approved": force_approved,
        "scan_results": None,
        "patch_schedule": None,
        "compliance_report": None,
        "server_history": None,
        "knowledge_base_results": None,
        "maintenance_windows": None,
        "llm_analysis": None,
        "patch_plan_summary": None,
        "risk_assessment": None,
        "recommended_action": None,
        "needs_approval": True,
        "approval_reason": None,
        "approval_status": None,
        "execution_results": None,
        "patches_applied": 0,
        "patches_failed": 0,
        "patches_rolled_back": 0,
        "final_report": None,
        "agent_status": "running",
        "error_message": None,
    }

    final_state = agent.invoke(initial_state)
    return final_state


if __name__ == "__main__":
    # Quick test: run a scan in test mode
    result = run_patch_agent(task_type="scan", test_mode=True)
    print(f"\nAgent status: {result['agent_status']}")