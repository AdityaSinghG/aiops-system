from pydantic import BaseModel, Field
from typing import Optional, Dict, Any, Literal
from datetime import datetime
import uuid


class MetricsSnapshot(BaseModel):
    cpu_percent: Optional[float] = None
    memory_percent: Optional[float] = None
    disk_percent: Optional[float] = None
    network_latency_ms: Optional[float] = None
    error_rate_percent: Optional[float] = None
    active_connections: Optional[int] = None
    extra: Dict[str, Any] = Field(default_factory=dict)


class AIOpsEvent(BaseModel):
    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = Field(default_factory=lambda: datetime.utcnow().isoformat())

    event_type: Literal["incident", "cost_alert", "patch_needed", "deploy_request", "prediction"] = "incident"
    source_agent: str
    severity: Literal["P1", "P2", "P3", "P4"]

    target_host: str
    target_service: Optional[str] = None
    environment: Literal["production", "staging", "dev"] = "production"

    alert_title: str
    alert_description: str
    metrics: Optional[MetricsSnapshot] = None

    routing_hops: int = 0

    resolution_status: Optional[Literal["resolved", "escalated_to_human", "failed"]] = None
    resolution_summary: Optional[str] = None


def make_cpu_incident(host: str, cpu_percent: float, duration_mins: int) -> AIOpsEvent:
    severity = "P1" if cpu_percent >= 95 else "P2" if cpu_percent >= 85 else "P3"
    return AIOpsEvent(
        event_type="incident",
        source_agent="infra_monitoring",
        severity=severity,
        target_host=host,
        target_service="system",
        alert_title=f"High CPU on {host}",
        alert_description=(
            f"CPU usage has been at {cpu_percent}% for {duration_mins} minutes "
            f"on host {host}. Threshold breach sustained beyond acceptable window."
        ),
        metrics=MetricsSnapshot(cpu_percent=cpu_percent),
    )


def make_memory_incident(host: str, memory_percent: float) -> AIOpsEvent:
    severity = "P1" if memory_percent >= 95 else "P2"
    return AIOpsEvent(
        event_type="incident",
        source_agent="infra_monitoring",
        severity=severity,
        target_host=host,
        target_service="system",
        alert_title=f"Memory exhaustion on {host}",
        alert_description=(
            f"Memory usage at {memory_percent}% on {host}. "
            f"Risk of OOM kill and service crash."
        ),
        metrics=MetricsSnapshot(memory_percent=memory_percent),
    )


def make_db_incident(host: str, service: str, description: str, severity: str = "P1") -> AIOpsEvent:
    return AIOpsEvent(
        event_type="incident",
        source_agent="infra_monitoring",
        severity=severity,
        target_host=host,
        target_service=service,
        alert_title=f"{service} incident on {host}",
        alert_description=description,
    )
def make_disk_incident(host: str, mountpoint: str, disk_percent: float) -> AIOpsEvent:
    severity = "P1" if disk_percent >= 90 else "P2"
    return AIOpsEvent(
        event_type="incident",
        source_agent="infra_monitoring",
        severity=severity,
        target_host=host,
        target_service="disk",
        alert_title=f"Disk critical on {host} at {mountpoint}",
        alert_description=(
            f"Disk usage at {disk_percent}% on partition {mountpoint} of host {host}. "
            f"Services may start failing immediately."
        ),
        metrics=MetricsSnapshot(disk_percent=disk_percent),
    )


def make_network_incident(host: str, errors: int) -> AIOpsEvent:
    severity = "P1" if errors >= 50 else "P2"
    return AIOpsEvent(
        event_type="incident",
        source_agent="infra_monitoring",
        severity=severity,
        target_host=host,
        target_service="network",
        alert_title=f"Network errors spiking on {host}",
        alert_description=(
            f"Network interface on {host} reporting {errors} errors. "
            f"Packet loss and connectivity issues likely."
        ),
        metrics=MetricsSnapshot(error_rate_percent=float(errors)),
    )


def make_unknown_incident(host: str, description: str, severity: str = "P1") -> AIOpsEvent:
    return AIOpsEvent(
        event_type="incident",
        source_agent="infra_monitoring",
        severity=severity,
        target_host=host,
        target_service="unknown",
        alert_title=f"Unknown critical incident on {host}",
        alert_description=description,
    )