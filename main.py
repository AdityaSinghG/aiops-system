import sys
import os

from shared.event_schema import (
    make_cpu_incident, make_memory_incident, make_db_incident,
    make_disk_incident, make_network_incident, make_unknown_incident
)
from app_orchestrator import route_event


def print_result(result, test_name):
    print(f"\nFinal Status : {result.resolution_status}")
    summary = result.resolution_summary or ""
    if result.resolution_status == "escalated_to_human":
        confidence = "LOW — escalated to human"
    elif "runbook" in summary.lower() or any(
        word in summary.lower() for word in ["restart", "kill", "flush", "clean"]
    ):
        confidence = "HIGH — runbook matched and action executed"
    else:
        confidence = "MEDIUM — action taken without direct runbook match"
    print(f"Confidence   : {confidence}")
    print(f"Summary      : {summary[:200] if summary else 'N/A'}")


def run_live():
    from infra_monitoring.agent.graph import run_and_escalate
    from infra_monitoring.agent.memory import get_memory_summary, get_metric_trend

    print("=" * 60)
    print("  AIOps System — Live Run")
    print("=" * 60)

    mem = get_memory_summary()
    print(f"\n[Memory] Reports: {mem['total_health_reports']} | "
          f"Escalations: {mem['total_escalations']} | "
          f"Snapshots: {mem['total_metric_snapshots']}")

    trend = get_metric_trend(n=5)
    print(f"[Memory] Trend: {trend['trend']}")

    result = run_and_escalate()

    if result:
        print_result(result, "Live Run")
    else:
        print("\nNo incidents detected. System is healthy.")


def run_tests():
    from infra_monitoring.agent.memory import get_escalation_count

    print("=" * 60)
    print("  AIOps System — Test Run")
    print("=" * 60)

    tests = [
        ("High CPU",          make_cpu_incident("web-prod-03", 94.0, 4)),
        ("Memory Exhaustion", make_memory_incident("api-prod-01", 96.0)),
        ("PostgreSQL Down",   make_db_incident(
            "db-prod-01", "postgresql",
            "PostgreSQL not accepting connections on port 5432.", "P1"
        )),
        ("Disk Critical",    make_disk_incident("storage-prod-01", "/var/log", 93.0)),
        ("Network Errors",   make_network_incident("proxy-prod-01", 47)),
        ("Redis Down",       make_db_incident(
            "cache-prod-01", "redis",
            "Redis not responding on port 6379. Connection refused.", "P2"
        )),
        ("Nginx Down",       make_db_incident(
            "web-prod-01", "nginx",
            "502 Bad Gateway errors, nginx worker process crashed.", "P2"
        )),
        ("Unknown Incident", make_unknown_incident(
            "db-prod-02",
            "Kernel panic detected in dmesg logs. System may be unstable.",
            "P1"
        )),
        ("SSL Expiry",       make_db_incident(
            "web-prod-02", "ssl",
            "SSL certificate expiring in 5 days. HTTPS will break.", "P2"
        )),
    ]

    for name, event in tests:
        print(f"\n\n── TEST: {name} ──")
        result = route_event(event)
        print_result(result, name)

    print("\n\n" + "=" * 60)
    print("  ESCALATION SUMMARY")
    print("=" * 60)
    recent = get_escalation_count(hours=24)
    print(f"Total escalations in last 24h: {recent['count']}")


def main():

    mode = sys.argv[1] if len(sys.argv) > 1 else "live"

    if mode == "test":
        run_tests()
    elif mode == "live":
        run_live()
    else:
        print("Usage: python main.py [live|test]")


if __name__ == "__main__":
    main()