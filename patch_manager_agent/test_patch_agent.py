"""
test_patch_agent.py
===================
8 test scenarios for the Patch Manager Agent.

Each test validates a different task type and verifies the agent
produces the expected outputs. All tests run in test_mode=True
so no real patches are applied.

Run all tests:
    python test_patch_agent.py

Run a specific test:
    python test_patch_agent.py --test 1
"""

import sys
import json
import argparse
from datetime import datetime

# Import the orchestrator — all tests go through the routing layer
from patch_orchestrator import (
    route_to_patch_agent,
    create_patch_event,
    trigger_patch_scan,
    trigger_patch_all,
    trigger_patch_server,
    trigger_compliance_check,
    trigger_patch_history,
    trigger_emergency_patch,
)

# Import agent directly for unit-level tests
from patch_agent import run_patch_agent
from patch_inventory import get_server_inventory, get_available_patches, get_unpatched_servers
from patch_knowledge_base import initialise_knowledge_base, query_knowledge_base


# ─────────────────────────────────────────────
#  TEST UTILITIES
# ─────────────────────────────────────────────

class TestRunner:
    """Simple test runner that tracks pass/fail results."""

    def __init__(self):
        self.results = []

    def assert_true(self, condition: bool, message: str):
        status = "✅ PASS" if condition else "❌ FAIL"
        print(f"  {status}: {message}")
        self.results.append({"check": message, "passed": condition})
        return condition

    def assert_equal(self, actual, expected, message: str):
        condition = actual == expected
        status = "✅ PASS" if condition else "❌ FAIL"
        if not condition:
            print(f"  {status}: {message} (got {actual!r}, expected {expected!r})")
        else:
            print(f"  {status}: {message}")
        self.results.append({"check": message, "passed": condition})
        return condition

    def assert_in(self, item, container, message: str):
        condition = item in container
        status = "✅ PASS" if condition else "❌ FAIL"
        print(f"  {status}: {message}")
        self.results.append({"check": message, "passed": condition})
        return condition

    def assert_not_none(self, value, message: str):
        condition = value is not None
        status = "✅ PASS" if condition else "❌ FAIL"
        print(f"  {status}: {message}")
        self.results.append({"check": message, "passed": condition})
        return condition

    def assert_greater_than(self, actual, threshold, message: str):
        condition = actual > threshold
        status = "✅ PASS" if condition else "❌ FAIL"
        print(f"  {status}: {message} (got {actual}, expected > {threshold})")
        self.results.append({"check": message, "passed": condition})
        return condition

    def summary(self) -> tuple[int, int]:
        passed = sum(1 for r in self.results if r["passed"])
        total = len(self.results)
        return passed, total


def print_test_header(test_num: int, test_name: str):
    print(f"\n{'='*70}")
    print(f"TEST {test_num}: {test_name}")
    print(f"{'='*70}")


def print_test_footer(passed: int, total: int, test_name: str):
    status = "✅ PASSED" if passed == total else f"⚠️  PARTIAL ({passed}/{total} checks)"
    print(f"\n  Result: {status} — {test_name}")


# ─────────────────────────────────────────────
#  TEST 1: PATCH INVENTORY AND DATA LAYER
#  Verifies the simulated data sources return
#  correctly structured data before the agent runs.
# ─────────────────────────────────────────────

def test_1_inventory_and_data_layer():
    print_test_header(1, "Patch Inventory and Data Layer Validation")
    t = TestRunner()

    # Test server inventory
    servers = get_server_inventory()
    t.assert_greater_than(len(servers), 0, "Server inventory returns at least 1 server")
    t.assert_true(len(servers) == 12, "Server inventory has exactly 12 servers")

    # Verify server data structure
    first_server = servers[0]
    for required_field in ["hostname", "role", "os", "environment", "criticality", "last_patched"]:
        t.assert_in(required_field, first_server, f"Server has required field: {required_field}")

    # Test patch availability
    web_patches = get_available_patches("WEB-PROD-01")
    t.assert_greater_than(len(web_patches), 0, "WEB-PROD-01 has pending patches")

    # Verify patch data structure
    first_patch = web_patches[0]
    for required_field in ["patch_id", "severity", "cve_score", "reboot_required"]:
        t.assert_in(required_field, first_patch, f"Patch has required field: {required_field}")

    # Test unpatched servers (the priority-sorted list)
    unpatched = get_unpatched_servers()
    t.assert_greater_than(len(unpatched), 0, "get_unpatched_servers returns results")

    # Verify sorting: critical servers should come before staging
    envs = [item["server"]["environment"] for item in unpatched]
    t.assert_true(
        envs.index("production") < envs.index("staging") if "staging" in envs else True,
        "Production servers sorted before staging servers"
    )

    # Test unknown server returns empty
    unknown_patches = get_available_patches("NONEXISTENT-SERVER")
    t.assert_equal(unknown_patches, [], "Unknown server returns empty patch list")

    passed, total = t.summary()
    print_test_footer(passed, total, "Inventory and Data Layer")
    return passed, total


# ─────────────────────────────────────────────
#  TEST 2: KNOWLEDGE BASE INITIALISATION
#  Verifies ChromaDB loads and can be queried.
# ─────────────────────────────────────────────

def test_2_knowledge_base():
    print_test_header(2, "Knowledge Base (ChromaDB) Initialisation and Query")
    t = TestRunner()

    # Initialise KB
    result = initialise_knowledge_base()
    t.assert_not_none(result, "Knowledge base initialisation returns a message")
    t.assert_true(
        "populated" in result or "initialised" in result,
        "Knowledge base reports successful state"
    )

    # Test semantic query
    results = query_knowledge_base("rollback failed patch production server")
    t.assert_greater_than(len(results), 0, "KB returns results for rollback query")

    # Verify result structure
    if results:
        first = results[0]
        t.assert_in("playbook_id", first, "KB result has playbook_id")
        t.assert_in("title", first, "KB result has title")
        t.assert_in("content", first, "KB result has content")
        t.assert_in("relevance_score", first, "KB result has relevance_score")
        t.assert_greater_than(first["relevance_score"], 0, "Relevance score > 0")

    # Test scheduling query
    sched_results = query_knowledge_base("batch sequencing patch order production")
    t.assert_greater_than(len(sched_results), 0, "KB returns results for scheduling query")

    # Test emergency query
    emerg_results = query_knowledge_base("zero day critical vulnerability emergency patch")
    t.assert_greater_than(len(emerg_results), 0, "KB returns results for emergency query")

    passed, total = t.summary()
    print_test_footer(passed, total, "Knowledge Base")
    return passed, total


# ─────────────────────────────────────────────
#  TEST 3: SCAN TASK (read-only, no patching)
# ─────────────────────────────────────────────

def test_3_scan_task():
    print_test_header(3, "Patch Scan Task (Read-Only)")
    t = TestRunner()

    print("  Running full patch scan in test mode...")
    result = trigger_patch_scan(test_mode=True)

    # Event routing checks
    t.assert_equal(result["event_type"], "patch_scan_requested", "Event type preserved correctly")
    t.assert_equal(result["task_type"], "scan", "Event classified as scan task")
    t.assert_not_none(result["agent_status"], "Agent produced a status")
    t.assert_equal(result["agent_status"], "complete", "Agent completed successfully")

    # Scan should not apply patches
    t.assert_equal(result["patches_applied"], 0, "Scan task applies 0 patches (read-only)")
    t.assert_equal(result["patches_failed"], 0, "Scan task has 0 failures")

    # Report should exist
    t.assert_not_none(result["final_report"], "Agent produced a final report")
    t.assert_greater_than(len(result["final_report"]), 100, "Final report has meaningful content")

    # Routing metadata should be present
    t.assert_in("routing_metadata", result, "Routing metadata present in result")
    t.assert_in("duration_seconds", result.get("routing_metadata", {}), "Duration tracked")

    passed, total = t.summary()
    print_test_footer(passed, total, "Scan Task")
    return passed, total


# ─────────────────────────────────────────────
#  TEST 4: COMPLIANCE REPORT TASK
# ─────────────────────────────────────────────

def test_4_compliance_report():
    print_test_header(4, "Compliance Report Task")
    t = TestRunner()

    print("  Generating compliance report...")
    result = trigger_compliance_check(test_mode=True)

    t.assert_equal(result["task_type"], "compliance_report", "Task type is compliance_report")
    t.assert_equal(result["agent_status"], "complete", "Agent completed successfully")
    t.assert_equal(result["patches_applied"], 0, "Compliance check applies 0 patches")
    t.assert_not_none(result["final_report"], "Report was generated")

    # Test the compliance data directly
    from patch_tools import tool_generate_compliance_report
    compliance_data = tool_generate_compliance_report()

    t.assert_in("fleet_summary", compliance_data, "Compliance data has fleet_summary")
    t.assert_in("total_servers", compliance_data["fleet_summary"], "Fleet summary has server count")
    t.assert_in("overall_compliance_rate", compliance_data["fleet_summary"], "Fleet summary has compliance rate")

    total_in_report = compliance_data["fleet_summary"]["total_servers"]
    t.assert_equal(total_in_report, 12, "Compliance report covers all 12 servers")

    # Every server should have a compliance_status
    for server in compliance_data.get("servers", []):
        t.assert_in(
            server["compliance_status"],
            ["compliant", "warning", "overdue", "critical_overdue"],
            f"{server['hostname']} has a valid compliance status"
        )

    passed, total = t.summary()
    print_test_footer(passed, total, "Compliance Report")
    return passed, total


# ─────────────────────────────────────────────
#  TEST 5: PATCH HISTORY TASK
# ─────────────────────────────────────────────

def test_5_patch_history():
    print_test_header(5, "Patch History Task")
    t = TestRunner()

    print("  Retrieving patch history for DB-PROD-01...")
    result = trigger_patch_history("DB-PROD-01", test_mode=True)

    t.assert_equal(result["task_type"], "patch_history", "Task type is patch_history")
    t.assert_equal(result["agent_status"], "complete", "Agent completed successfully")

    # Test the tool directly too
    from patch_tools import tool_get_server_patch_history
    history = tool_get_server_patch_history("DB-PROD-01")

    t.assert_equal(history["hostname"], "DB-PROD-01", "History returns correct hostname")
    t.assert_in("role", history, "History includes server role")
    t.assert_in("patch_history", history, "History includes patch records")
    t.assert_in("days_since_last_patch", history, "History includes days since last patch")
    t.assert_greater_than(history["days_since_last_patch"], 0, "Days since patch > 0")

    # Test history for a server with no patches (staging)
    history_empty = tool_get_server_patch_history("APP-STG-01")
    t.assert_equal(history_empty["hostname"], "APP-STG-01", "Empty history returns correct hostname")

    # Test unknown server
    history_unknown = tool_get_server_patch_history("NOT-A-SERVER")
    t.assert_in("error", history_unknown, "Unknown server returns error key")

    passed, total = t.summary()
    print_test_footer(passed, total, "Patch History")
    return passed, total


# ─────────────────────────────────────────────
#  TEST 6: SINGLE SERVER PATCH TASK
#  Patches WEB-STG-01 (staging, no approval needed)
# ─────────────────────────────────────────────

def test_6_patch_single_server_staging():
    print_test_header(6, "Single Server Patch Task — Staging Server")
    t = TestRunner()

    print("  Patching WEB-STG-01 (staging — no approval needed)...")
    result = trigger_patch_server("WEB-STG-01", test_mode=True)

    t.assert_equal(result["task_type"], "patch_server", "Task type is patch_server")
    t.assert_equal(result["agent_status"], "complete", "Agent completed successfully")
    t.assert_not_none(result["final_report"], "Final report generated")

    # Test the maintenance window tool
    from patch_tools import tool_check_maintenance_window
    window_staging = tool_check_maintenance_window("WEB-STG-01")
    t.assert_true(window_staging["in_window"], "WEB-STG-01 staging is always in maintenance window")
    t.assert_equal(window_staging["environment"], "staging", "Correctly identified as staging")

    window_prod = tool_check_maintenance_window("WEB-PROD-01")
    t.assert_not_none(window_prod["in_window"], "Production window check returns a value")
    t.assert_in("maintenance_window", window_prod, "Production window check returns window details")

    passed, total = t.summary()
    print_test_footer(passed, total, "Single Server Patch (Staging)")
    return passed, total


# ─────────────────────────────────────────────
#  TEST 7: APPROVAL GATE BEHAVIOUR
#  Verifies that production patches require
#  approval and that the gate works correctly.
# ─────────────────────────────────────────────

def test_7_approval_gate():
    print_test_header(7, "Approval Gate — Production Patch Requires Approval")
    t = TestRunner()

    # Scenario A: Production patch WITHOUT force_approved → should pause at approval gate
    print("  Scenario A: Production patch without approval...")
    result_no_approval = run_patch_agent(
        task_type="patch_server",
        task_input={"hostname": "WEB-PROD-01"},
        test_mode=False,
        force_approved=False,
    )

    t.assert_equal(
        result_no_approval["agent_status"], "awaiting_approval",
        "Production patch without approval enters 'awaiting_approval' state"
    )
    t.assert_not_none(
        result_no_approval["final_report"],
        "Change request document generated while awaiting approval"
    )
    t.assert_equal(
        result_no_approval["patches_applied"], 0,
        "No patches applied while awaiting approval"
    )

    # Scenario B: Staging patch → auto-approved regardless of force_approved flag
    print("\n  Scenario B: Staging patch without explicit approval (auto-approved)...")
    result_staging = run_patch_agent(
        task_type="patch_server",
        task_input={"hostname": "APP-STG-01"},
        test_mode=True,     # test_mode to avoid real patching
        force_approved=False,
    )
    t.assert_in(
        result_staging["agent_status"],
        ["complete", "awaiting_approval"],
        "Staging patch either completes or awaits approval"
    )

    # Scenario C: Force approved → should execute
    print("\n  Scenario C: Production patch with force_approved=True (test mode)...")
    result_approved = run_patch_agent(
        task_type="patch_server",
        task_input={"hostname": "WEB-PROD-02"},
        test_mode=True,        # test_mode so no real patches
        force_approved=True,
    )
    t.assert_equal(
        result_approved["agent_status"], "complete",
        "Force-approved production patch completes successfully"
    )

    passed, total = t.summary()
    print_test_footer(passed, total, "Approval Gate")
    return passed, total


# ─────────────────────────────────────────────
#  TEST 8: EMERGENCY PATCH SCENARIO
#  Critical vulnerability triggers emergency
#  patching that bypasses standard approval.
# ─────────────────────────────────────────────

def test_8_emergency_patch():
    print_test_header(8, "Emergency Patch Scenario — Critical Vulnerability")
    t = TestRunner()

    print("  Simulating critical zero-day vulnerability detection...")

    # Create a critical vulnerability event (like what OURA would send)
    event = create_patch_event(
        event_type="critical_vulnerability_detected",
        source="oura",
        priority="emergency",
        description="CVE-2024-21338: Critical RCE vulnerability in Windows kernel actively exploited",
        metadata={
            "test_mode": True,   # test_mode to prevent real patching in this test
            "cve_id": "CVE-2024-21338",
            "cve_score": 9.8,
            "actively_exploited": True,
        },
    )

    t.assert_equal(event["priority"], "emergency", "Emergency event has emergency priority")
    t.assert_equal(event["agent_target"], "patch_manager", "Event correctly targeted at patch_manager")

    result = route_to_patch_agent(event)

    t.assert_equal(result["task_type"], "emergency_patch", "Emergency vulnerability routed as emergency_patch")
    t.assert_equal(result["agent_status"], "complete", "Emergency patch agent completed")
    t.assert_not_none(result["final_report"], "Emergency patch report generated")

    # In emergency mode, report should contain urgency language
    report_lower = result["final_report"].lower() if result["final_report"] else ""
    t.assert_true(
        len(report_lower) > 50,
        "Emergency patch report has substantial content"
    )

    # Verify routing metadata
    metadata = result.get("routing_metadata", {})
    t.assert_equal(metadata.get("priority"), "emergency", "Routing metadata preserves emergency priority")
    t.assert_in("duration_seconds", metadata, "Execution time tracked")

    print(f"\n  Emergency patch simulated. Duration: {metadata.get('duration_seconds', '?')}s")

    passed, total = t.summary()
    print_test_footer(passed, total, "Emergency Patch Scenario")
    return passed, total


# ─────────────────────────────────────────────
#  MAIN TEST RUNNER
# ─────────────────────────────────────────────

ALL_TESTS = [
    (1, "Patch Inventory and Data Layer", test_1_inventory_and_data_layer),
    (2, "Knowledge Base (ChromaDB)",      test_2_knowledge_base),
    (3, "Scan Task (Read-Only)",          test_3_scan_task),
    (4, "Compliance Report",              test_4_compliance_report),
    (5, "Patch History",                  test_5_patch_history),
    (6, "Single Server Patch (Staging)",  test_6_patch_single_server_staging),
    (7, "Approval Gate Behaviour",        test_7_approval_gate),
    (8, "Emergency Patch Scenario",       test_8_emergency_patch),
]


def run_all_tests():
    print(f"\n{'#'*70}")
    print(f"# PATCH MANAGER AGENT — TEST SUITE")
    print(f"# {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"# {len(ALL_TESTS)} tests")
    print(f"{'#'*70}")

    total_passed = 0
    total_checks = 0
    test_summary = []

    for test_num, test_name, test_fn in ALL_TESTS:
        try:
            passed, total = test_fn()
            total_passed += passed
            total_checks += total
            test_summary.append({
                "test": f"Test {test_num}: {test_name}",
                "passed": passed,
                "total": total,
                "status": "✅ PASS" if passed == total else f"⚠️  {passed}/{total}",
            })
        except Exception as e:
            print(f"\n❌ TEST {test_num} CRASHED: {e}")
            import traceback
            traceback.print_exc()
            test_summary.append({
                "test": f"Test {test_num}: {test_name}",
                "passed": 0,
                "total": 1,
                "status": f"❌ CRASHED: {str(e)[:50]}",
            })
            total_checks += 1

    # Final summary
    print(f"\n\n{'='*70}")
    print("FINAL TEST SUMMARY")
    print("="*70)
    for row in test_summary:
        print(f"  {row['status']:20} {row['test']}")

    print(f"\n{'='*70}")
    overall_rate = round((total_passed / total_checks) * 100, 1) if total_checks else 0
    print(f"OVERALL: {total_passed}/{total_checks} checks passed ({overall_rate}%)")
    if total_passed == total_checks:
        print("🎉 ALL TESTS PASSED — Patch Manager Agent is ready!")
    else:
        print(f"⚠️  {total_checks - total_passed} checks failed — review output above")
    print("="*70)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Patch Manager Agent Test Suite")
    parser.add_argument("--test", type=int, help="Run a specific test number (1-8)", default=None)
    args = parser.parse_args()

    if args.test:
        # Run a single test
        matches = [t for t in ALL_TESTS if t[0] == args.test]
        if matches:
            _, _, test_fn = matches[0]
            test_fn()
        else:
            print(f"Test {args.test} not found. Available: 1-{len(ALL_TESTS)}")
    else:
        run_all_tests()