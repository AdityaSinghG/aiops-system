# ─────────────────────────────────────────────────────────────────────────────
#  main.py
#
#  Entry point for the Infrastructure Monitoring Agent.
#
#  This file ties everything together:
#    - Runs a single health check or a continuous monitoring loop
#    - Displays results with colour-coded severity in the terminal
#    - Saves every check result to ChromaDB memory
#    - Logs escalation decisions
#    - Shows memory summary and recent history on startup
#
#  HOW TO RUN (run from the project ROOT, not from inside infra_monitoring/):
#    Single check   : python -m infra_monitoring.main
#    Continuous loop: python -m infra_monitoring.main --loop
#    Show history   : python -m infra_monitoring.main --history
#
#  LOCAL DEV  : Uses Ollama + psutil — zero cost, runs offline
#  PRODUCTION : Swap LLM config in agent/graph.py only — nothing here changes
# ─────────────────────────────────────────────────────────────────────────────

import argparse
import datetime
import logging
import sys
import time

from langchain_core.messages import HumanMessage
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich import box
from rich.rule import Rule

from infra_monitoring.agent.graph import infra_agent, run_and_escalate   # ⭐ CHANGED — added infra_monitoring. prefix + run_and_escalate
from infra_monitoring.agent.memory import (                   # ⭐ CHANGED — added infra_monitoring. prefix
    save_health_report,
    save_escalation_event,
    save_metric_snapshot,
    get_recent_reports,
    get_escalation_count,
    get_metric_trend,
    get_memory_summary
)

# ─────────────────────────────────────────────────────────────────────────────
#  SETUP
# ─────────────────────────────────────────────────────────────────────────────

console = Console()
logger = logging.getLogger(__name__)

# Check interval for continuous loop mode (seconds)
CHECK_INTERVAL_SECONDS = 30


# ─────────────────────────────────────────────────────────────────────────────
#  HELPER — get_severity_color
#  Maps severity levels to Rich terminal colours for display
# ─────────────────────────────────────────────────────────────────────────────

def get_severity_color(severity: str) -> str:
    return {
        "LOW":      "green",
        "MEDIUM":   "yellow",
        "HIGH":     "orange1",
        "CRITICAL": "red",
        "HEALTHY":  "green",
        "WARNING":  "yellow",
        "UNKNOWN":  "white"
    }.get(severity.upper(), "white")


# ─────────────────────────────────────────────────────────────────────────────
#  FUNCTION — print_startup_banner
#  Shown once when main.py starts. Displays memory summary and
#  recent escalation count so the operator has immediate context.
# ─────────────────────────────────────────────────────────────────────────────

def print_startup_banner():
    console.print()
    console.rule("[bold blue]AIOps — Infrastructure Monitoring Agent[/bold blue]")
    console.print(
        f"[dim]Started at: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}[/dim]\n"
    )

    # Memory summary
    memory = get_memory_summary()
    escalation_data = get_escalation_count(hours=24)

    summary_table = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
    summary_table.add_column("Key", style="dim")
    summary_table.add_column("Value", style="bold")

    summary_table.add_row("Total checks in memory",  str(memory.get("total_health_reports", 0)))
    summary_table.add_row("Total escalations ever",  str(memory.get("total_escalations", 0)))
    summary_table.add_row("Escalations (last 24h)",  str(escalation_data.get("count", 0)))
    summary_table.add_row("Metric snapshots stored", str(memory.get("total_metric_snapshots", 0)))
    summary_table.add_row("Memory location",         memory.get("memory_location", "unknown"))
    summary_table.add_row("LLM",                     "Ollama — llama3.2 (local, free)")
    summary_table.add_row("Metrics source",          "psutil (local system)")

    console.print(
        Panel(summary_table, title="[bold]Agent Memory Summary[/bold]", border_style="blue")
    )
    console.print()


# ─────────────────────────────────────────────────────────────────────────────
#  FUNCTION — print_history
#  Shows the last 5 health check reports stored in memory.
#  Called when running: python main.py --history
# ─────────────────────────────────────────────────────────────────────────────

def print_history():
    console.rule("[bold blue]Recent Health Check History[/bold blue]")
    reports = get_recent_reports(n=5)

    if not reports:
        console.print("[yellow]No health check history found in memory yet.[/yellow]")
        console.print("[dim]Run 'python main.py' to perform your first check.[/dim]\n")
        return

    for i, report in enumerate(reports, 1):
        meta = report.get("metadata", {})
        severity = meta.get("severity", "UNKNOWN")
        color = get_severity_color(severity)
        timestamp = meta.get("check_timestamp", "unknown time")
        escalated = meta.get("escalated", "False") == "True"
        escalation_badge = " [red]⚠ ESCALATED[/red]" if escalated else ""

        console.print(
            Panel(
                report.get("report_text", "No report text"),
                title=(
                    f"[bold {color}]Check #{i} — {severity} — {timestamp}"
                    f"[/bold {color}]{escalation_badge}"
                ),
                border_style=color,
                expand=False
            )
        )
        console.print()


# ─────────────────────────────────────────────────────────────────────────────
#  FUNCTION — run_single_check
#  Runs one complete infrastructure health check:
#    1. Invokes the LangGraph agent
#    2. Displays the report with colour coding
#    3. Saves to memory
#    4. Handles escalation output
#  Returns the full result dict for use by the continuous loop.
# ─────────────────────────────────────────────────────────────────────────────

def run_single_check() -> dict:
    console.rule(
        f"[bold blue]Health Check — "
        f"{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}[/bold blue]"
    )
    console.print("[dim]Invoking agent... collecting metrics...[/dim]\n")

    # ── Invoke the agent graph ──────────────────────────────────────────────
    try:
        result = infra_agent.invoke({
            "messages": [
                HumanMessage(
                    content=(
                        "Run a complete infrastructure health check right now. "
                        "Use ALL of your tools — get_cpu_metrics, get_memory_metrics, "
                        "get_disk_metrics, get_network_metrics, and get_top_processes. "
                        "Do not skip any tool. After collecting all metrics, produce "
                        "the full structured health report exactly as specified."
                    )
                )
            ],
            "escalate": False,
            "severity": "LOW",
            "overall_status": "HEALTHY",
            "report": "",
            "check_timestamp": datetime.datetime.now().isoformat(),
            "error": ""
        })

    except Exception as e:
        error_msg = f"Agent invocation failed: {str(e)}"
        logger.error(error_msg)
        console.print(f"[bold red]ERROR: {error_msg}[/bold red]")
        return {"error": error_msg}

    # ── Extract results ─────────────────────────────────────────────────────
    report        = result.get("report", "No report generated")
    severity      = result.get("severity", "UNKNOWN")
    overall_status = result.get("overall_status", "UNKNOWN")
    escalate      = result.get("escalate", False)
    timestamp     = result.get("check_timestamp", datetime.datetime.now().isoformat())
    error         = result.get("error", "")

    color = get_severity_color(severity)

    # ── Display the report ──────────────────────────────────────────────────
    console.print(
        Panel(
            report,
            title=(
                f"[bold {color}]Infrastructure Health Report — "
                f"Severity: {severity} — Status: {overall_status}[/bold {color}]"
            ),
            border_style=color,
            expand=True
        )
    )

    # ── Escalation notice ───────────────────────────────────────────────────
    if escalate:
        console.print()
        console.print(
            Panel(
                "[bold red]⚠  ESCALATION TRIGGERED[/bold red]\n\n"
                "The agent has determined this incident requires immediate attention.\n"
                "In the full AIOps system this would automatically route to the\n"
                "[bold]Incident Resolver Agent[/bold] for autonomous remediation.",
                title="[bold red]ESCALATION[/bold red]",
                border_style="red"
            )
        )
        logger.warning(
            f"ESCALATION TRIGGERED — Severity: {severity} | "
            f"Status: {overall_status} | Time: {timestamp}"
        )
    else:
        console.print(
            f"\n[bold {color}]✓ No escalation needed — "
            f"Status: {overall_status}[/bold {color}]"
        )

    # ── Save to memory ──────────────────────────────────────────────────────
    report_id = save_health_report(
        report=report,
        severity=severity,
        overall_status=overall_status,
        escalated=escalate,
        check_timestamp=timestamp
    )

    if escalate:
        save_escalation_event(
            report_id=report_id,
            severity=severity,
            reason=f"Agent escalated with overall status: {overall_status}",
            affected_resource="See full report",
            check_timestamp=timestamp
        )

    # Save a lightweight metric snapshot
    # We use placeholder values here — in a future iteration
    # we will parse the actual metric values from the report
    save_metric_snapshot(
        cpu_percent=0.0,
        memory_percent=0.0,
        disk_percent_max=0.0,
        network_errors=0,
        check_timestamp=timestamp
    )

    if error:
        console.print(f"\n[red]Agent error recorded: {error}[/red]")

    console.print()
    return result


# ─────────────────────────────────────────────────────────────────────────────
#  FUNCTION — run_continuous_loop
#  Runs health checks every CHECK_INTERVAL_SECONDS indefinitely.
#  Press Ctrl+C to stop. Called with: python main.py --loop
# ─────────────────────────────────────────────────────────────────────────────

def run_continuous_loop():
    console.print(
        Panel(
            f"[bold green]Continuous monitoring mode active.[/bold green]\n"
            f"Running a health check every [bold]{CHECK_INTERVAL_SECONDS} seconds[/bold].\n"
            f"Press [bold]Ctrl+C[/bold] to stop.",
            title="[bold]Continuous Loop[/bold]",
            border_style="green"
        )
    )
    console.print()

    check_number = 0

    try:
        while True:
            check_number += 1
            console.print(f"[dim]Check #{check_number}[/dim]")
            run_single_check()

            # Show escalation summary every 5 checks
            if check_number % 5 == 0:
                esc_data = get_escalation_count(hours=1)
                if esc_data["count"] > 0:
                    console.print(
                        f"[bold yellow]⚠ {esc_data['count']} escalation(s) "
                        f"in the last hour[/bold yellow]\n"
                    )

            console.print(
                f"[dim]Next check in {CHECK_INTERVAL_SECONDS} seconds... "
                f"(Ctrl+C to stop)[/dim]\n"
            )
            time.sleep(CHECK_INTERVAL_SECONDS)

    except KeyboardInterrupt:
        console.print("\n[bold yellow]Monitoring stopped by user.[/bold yellow]")
        console.print(
            f"[dim]Total checks completed this session: {check_number}[/dim]\n"
        )
        sys.exit(0)


# ─────────────────────────────────────────────────────────────────────────────
#  ENTRY POINT
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="AIOps Infrastructure Monitoring Agent"
    )
    parser.add_argument(
        "--loop",
        action="store_true",
        help="Run continuous monitoring loop (checks every 30 seconds)"
    )
    parser.add_argument(
        "--history",
        action="store_true",
        help="Show recent health check history from memory and exit"
    )
    args = parser.parse_args()

    # Always show the startup banner
    print_startup_banner()

    if args.history:
        print_history()
        sys.exit(0)
    elif args.loop:
        run_continuous_loop()
    else:
        check_result = run_single_check()

        # ⭐ NEW — actually run the escalation logic (incident escalation +
        # patch escalation), reusing the result we already computed above
        # instead of invoking the LLM a second time. run_single_check()
        # handles the pretty display; run_and_escalate() is what fires the
        # real escalation pipeline that routes events through OURA to
        # Incident Resolver / Patch Manager.
        console.print()
        console.rule("[bold blue]Escalation Pipeline[/bold blue]")
        run_and_escalate(result=check_result)