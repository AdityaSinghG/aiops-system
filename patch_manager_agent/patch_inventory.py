"""
patch_inventory.py
==================
Simulated patch inventory and server registry for the Patch Manager Agent.

In production (Azure), this module's functions get replaced with calls to:
  - Azure Update Manager API
  - WSUS / SCCM connectors
  - Azure Resource Graph for server inventory

For local development, we simulate a realistic enterprise environment with:
  - 12 servers across different roles (web, database, app, monitoring)
  - A library of realistic Windows and Linux patches
  - CVE severity scores, compatibility flags, reboot requirements
  - Historical patch records per server

HOW TO SWAP FOR AZURE:
  Replace get_server_inventory() with an Azure Resource Graph query.
  Replace get_available_patches() with Azure Update Manager compliance data.
  Replace get_patch_history() with Azure Update Manager deployment history.
  Everything else in the agent stays the same.
"""

from datetime import datetime, timedelta
import random


# ─────────────────────────────────────────────
#  SERVER REGISTRY
#  Simulates the enterprise server fleet.
#  Each server has: role, OS, environment, last
#  patch date, and current health status.
# ─────────────────────────────────────────────

SERVER_REGISTRY = {
    "WEB-PROD-01": {
        "hostname": "WEB-PROD-01",
        "role": "Web Server",
        "os": "Windows Server 2022",
        "os_family": "windows",
        "environment": "production",
        "ip_address": "10.0.1.10",
        "cpu_cores": 8,
        "ram_gb": 32,
        "last_patched": (datetime.now() - timedelta(days=45)).strftime("%Y-%m-%d"),
        "patch_group": "batch_a",          # Batch A patches first (less critical)
        "maintenance_window": "Sunday 02:00-06:00",
        "auto_reboot_allowed": True,
        "health_status": "healthy",
        "services_running": ["IIS", "W3SVC", "MSSQLSERVER"],
        "criticality": "high",
    },
    "WEB-PROD-02": {
        "hostname": "WEB-PROD-02",
        "role": "Web Server",
        "os": "Windows Server 2022",
        "os_family": "windows",
        "environment": "production",
        "ip_address": "10.0.1.11",
        "cpu_cores": 8,
        "ram_gb": 32,
        "last_patched": (datetime.now() - timedelta(days=45)).strftime("%Y-%m-%d"),
        "patch_group": "batch_b",          # Batch B patches after A is verified
        "maintenance_window": "Sunday 02:00-06:00",
        "auto_reboot_allowed": True,
        "health_status": "healthy",
        "services_running": ["IIS", "W3SVC"],
        "criticality": "high",
    },
    "DB-PROD-01": {
        "hostname": "DB-PROD-01",
        "role": "Database Server",
        "os": "Windows Server 2019",
        "os_family": "windows",
        "environment": "production",
        "ip_address": "10.0.2.10",
        "cpu_cores": 16,
        "ram_gb": 128,
        "last_patched": (datetime.now() - timedelta(days=60)).strftime("%Y-%m-%d"),
        "patch_group": "batch_c",          # DB servers always patch last
        "maintenance_window": "Saturday 01:00-05:00",
        "auto_reboot_allowed": False,      # DB servers need manual reboot approval
        "health_status": "healthy",
        "services_running": ["MSSQLSERVER", "SQLAgent", "SQLTELEMETRY"],
        "criticality": "critical",
    },
    "DB-PROD-02": {
        "hostname": "DB-PROD-02",
        "role": "Database Server (Replica)",
        "os": "Windows Server 2019",
        "os_family": "windows",
        "environment": "production",
        "ip_address": "10.0.2.11",
        "cpu_cores": 16,
        "ram_gb": 128,
        "last_patched": (datetime.now() - timedelta(days=60)).strftime("%Y-%m-%d"),
        "patch_group": "batch_c",
        "maintenance_window": "Saturday 01:00-05:00",
        "auto_reboot_allowed": False,
        "health_status": "healthy",
        "services_running": ["MSSQLSERVER", "SQLAgent"],
        "criticality": "critical",
    },
    "APP-PROD-01": {
        "hostname": "APP-PROD-01",
        "role": "Application Server",
        "os": "Ubuntu 22.04 LTS",
        "os_family": "linux",
        "environment": "production",
        "ip_address": "10.0.3.10",
        "cpu_cores": 8,
        "ram_gb": 64,
        "last_patched": (datetime.now() - timedelta(days=30)).strftime("%Y-%m-%d"),
        "patch_group": "batch_a",
        "maintenance_window": "Sunday 02:00-06:00",
        "auto_reboot_allowed": True,
        "health_status": "healthy",
        "services_running": ["nginx", "gunicorn", "redis"],
        "criticality": "high",
    },
    "APP-PROD-02": {
        "hostname": "APP-PROD-02",
        "role": "Application Server",
        "os": "Ubuntu 22.04 LTS",
        "os_family": "linux",
        "environment": "production",
        "ip_address": "10.0.3.11",
        "cpu_cores": 8,
        "ram_gb": 64,
        "last_patched": (datetime.now() - timedelta(days=30)).strftime("%Y-%m-%d"),
        "patch_group": "batch_b",
        "maintenance_window": "Sunday 02:00-06:00",
        "auto_reboot_allowed": True,
        "health_status": "healthy",
        "services_running": ["nginx", "gunicorn"],
        "criticality": "high",
    },
    "MON-PROD-01": {
        "hostname": "MON-PROD-01",
        "role": "Monitoring Server",
        "os": "Ubuntu 20.04 LTS",
        "os_family": "linux",
        "environment": "production",
        "ip_address": "10.0.4.10",
        "cpu_cores": 4,
        "ram_gb": 16,
        "last_patched": (datetime.now() - timedelta(days=20)).strftime("%Y-%m-%d"),
        "patch_group": "batch_a",
        "maintenance_window": "Sunday 04:00-06:00",
        "auto_reboot_allowed": True,
        "health_status": "healthy",
        "services_running": ["prometheus", "grafana", "alertmanager"],
        "criticality": "medium",
    },
    "WEB-STG-01": {
        "hostname": "WEB-STG-01",
        "role": "Web Server (Staging)",
        "os": "Windows Server 2022",
        "os_family": "windows",
        "environment": "staging",
        "ip_address": "10.1.1.10",
        "cpu_cores": 4,
        "ram_gb": 16,
        "last_patched": (datetime.now() - timedelta(days=10)).strftime("%Y-%m-%d"),
        "patch_group": "batch_a",
        "maintenance_window": "Anytime",
        "auto_reboot_allowed": True,
        "health_status": "healthy",
        "services_running": ["IIS", "W3SVC"],
        "criticality": "low",
    },
    "APP-STG-01": {
        "hostname": "APP-STG-01",
        "role": "Application Server (Staging)",
        "os": "Ubuntu 22.04 LTS",
        "os_family": "linux",
        "environment": "staging",
        "ip_address": "10.1.3.10",
        "cpu_cores": 4,
        "ram_gb": 16,
        "last_patched": (datetime.now() - timedelta(days=5)).strftime("%Y-%m-%d"),
        "patch_group": "batch_a",
        "maintenance_window": "Anytime",
        "auto_reboot_allowed": True,
        "health_status": "healthy",
        "services_running": ["nginx", "gunicorn"],
        "criticality": "low",
    },
    "DB-STG-01": {
        "hostname": "DB-STG-01",
        "role": "Database Server (Staging)",
        "os": "Windows Server 2019",
        "os_family": "windows",
        "environment": "staging",
        "ip_address": "10.1.2.10",
        "cpu_cores": 4,
        "ram_gb": 32,
        "last_patched": (datetime.now() - timedelta(days=8)).strftime("%Y-%m-%d"),
        "patch_group": "batch_a",
        "maintenance_window": "Anytime",
        "auto_reboot_allowed": True,
        "health_status": "healthy",
        "services_running": ["MSSQLSERVER"],
        "criticality": "low",
    },
    "INFRA-MGMT-01": {
        "hostname": "INFRA-MGMT-01",
        "role": "Infrastructure Management",
        "os": "Windows Server 2022",
        "os_family": "windows",
        "environment": "management",
        "ip_address": "10.0.5.10",
        "cpu_cores": 4,
        "ram_gb": 16,
        "last_patched": (datetime.now() - timedelta(days=15)).strftime("%Y-%m-%d"),
        "patch_group": "batch_b",
        "maintenance_window": "Saturday 03:00-05:00",
        "auto_reboot_allowed": True,
        "health_status": "healthy",
        "services_running": ["WSUS", "WinRM"],
        "criticality": "medium",
    },
    "BACKUP-01": {
        "hostname": "BACKUP-01",
        "role": "Backup Server",
        "os": "Ubuntu 20.04 LTS",
        "os_family": "linux",
        "environment": "production",
        "ip_address": "10.0.6.10",
        "cpu_cores": 4,
        "ram_gb": 16,
        "last_patched": (datetime.now() - timedelta(days=25)).strftime("%Y-%m-%d"),
        "patch_group": "batch_b",
        "maintenance_window": "Sunday 05:00-07:00",
        "auto_reboot_allowed": True,
        "health_status": "healthy",
        "services_running": ["bacula", "rsync"],
        "criticality": "medium",
    },
}


# ─────────────────────────────────────────────
#  PATCH LIBRARY
#  Simulates patches available from Microsoft
#  Update / Ubuntu apt, with realistic KB IDs,
#  CVE references, and severity ratings.
# ─────────────────────────────────────────────

AVAILABLE_PATCHES = [
    # ── CRITICAL WINDOWS PATCHES ────────────────────────────────────
    {
        "patch_id": "KB5034441",
        "title": "2024-01 Cumulative Update for Windows Server 2022",
        "severity": "critical",
        "cve_ids": ["CVE-2024-21338", "CVE-2024-21345", "CVE-2024-21371"],
        "cve_score": 9.8,
        "affected_os": ["Windows Server 2022"],
        "patch_type": "security",
        "reboot_required": True,
        "estimated_duration_minutes": 45,
        "size_mb": 512,
        "release_date": "2024-01-09",
        "compatible_with": ["WEB-PROD-01", "WEB-PROD-02", "WEB-STG-01", "INFRA-MGMT-01"],
        "description": "Critical security update addressing remote code execution vulnerabilities in Windows kernel.",
    },
    {
        "patch_id": "KB5034122",
        "title": "2024-01 Cumulative Update for Windows Server 2019",
        "severity": "critical",
        "cve_ids": ["CVE-2024-21307", "CVE-2024-21318"],
        "cve_score": 9.1,
        "affected_os": ["Windows Server 2019"],
        "patch_type": "security",
        "reboot_required": True,
        "estimated_duration_minutes": 40,
        "size_mb": 480,
        "release_date": "2024-01-09",
        "compatible_with": ["DB-PROD-01", "DB-PROD-02", "DB-STG-01"],
        "description": "Critical update addressing privilege escalation and remote code execution in Windows Server 2019.",
    },
    {
        "patch_id": "KB5032198",
        "title": "Security Update for Windows Server 2022 - .NET Framework",
        "severity": "important",
        "cve_ids": ["CVE-2024-20652"],
        "cve_score": 7.5,
        "affected_os": ["Windows Server 2022"],
        "patch_type": "security",
        "reboot_required": True,
        "estimated_duration_minutes": 20,
        "size_mb": 128,
        "release_date": "2024-01-09",
        "compatible_with": ["WEB-PROD-01", "WEB-PROD-02", "WEB-STG-01"],
        "description": "Security update for .NET Framework 4.8 addressing information disclosure vulnerability.",
    },
    {
        "patch_id": "KB5031539",
        "title": "Windows Server 2022 Cumulative Update Preview",
        "severity": "moderate",
        "cve_ids": [],
        "cve_score": 0.0,
        "affected_os": ["Windows Server 2022"],
        "patch_type": "quality",
        "reboot_required": True,
        "estimated_duration_minutes": 35,
        "size_mb": 420,
        "release_date": "2023-12-12",
        "compatible_with": ["WEB-PROD-01", "WEB-PROD-02", "INFRA-MGMT-01", "WEB-STG-01"],
        "description": "Non-security quality improvements for Windows Server 2022 including reliability fixes.",
    },
    {
        "patch_id": "KB5034396",
        "title": "Windows Defender Antimalware Platform Update",
        "severity": "important",
        "cve_ids": ["CVE-2024-21355"],
        "cve_score": 7.8,
        "affected_os": ["Windows Server 2022", "Windows Server 2019"],
        "patch_type": "security",
        "reboot_required": False,
        "estimated_duration_minutes": 10,
        "size_mb": 64,
        "release_date": "2024-01-10",
        "compatible_with": ["WEB-PROD-01", "WEB-PROD-02", "DB-PROD-01", "DB-PROD-02",
                            "WEB-STG-01", "DB-STG-01", "INFRA-MGMT-01"],
        "description": "Security update for Windows Defender addressing elevation of privilege vulnerability.",
    },
    # ── CRITICAL LINUX PATCHES ──────────────────────────────────────
    {
        "patch_id": "USN-6648-1",
        "title": "Linux kernel (OEM) vulnerabilities - Ubuntu 22.04 LTS",
        "severity": "critical",
        "cve_ids": ["CVE-2024-0193", "CVE-2024-0582"],
        "cve_score": 9.3,
        "affected_os": ["Ubuntu 22.04 LTS"],
        "patch_type": "security",
        "reboot_required": True,
        "estimated_duration_minutes": 30,
        "size_mb": 85,
        "release_date": "2024-01-12",
        "compatible_with": ["APP-PROD-01", "APP-PROD-02", "APP-STG-01"],
        "description": "Critical Linux kernel security update addressing use-after-free vulnerability in nftables.",
    },
    {
        "patch_id": "USN-6619-1",
        "title": "OpenSSH vulnerabilities - Ubuntu 22.04 LTS",
        "severity": "important",
        "cve_ids": ["CVE-2023-51385", "CVE-2023-48795"],
        "cve_score": 8.1,
        "affected_os": ["Ubuntu 22.04 LTS"],
        "patch_type": "security",
        "reboot_required": False,
        "estimated_duration_minutes": 5,
        "size_mb": 12,
        "release_date": "2024-01-08",
        "compatible_with": ["APP-PROD-01", "APP-PROD-02", "APP-STG-01"],
        "description": "Security update for OpenSSH addressing prefix truncation attack in the SSH Binary Packet Protocol.",
    },
    {
        "patch_id": "USN-6607-1",
        "title": "Linux kernel vulnerabilities - Ubuntu 20.04 LTS",
        "severity": "critical",
        "cve_ids": ["CVE-2023-6817", "CVE-2024-0193"],
        "cve_score": 9.1,
        "affected_os": ["Ubuntu 20.04 LTS"],
        "patch_type": "security",
        "reboot_required": True,
        "estimated_duration_minutes": 30,
        "size_mb": 78,
        "release_date": "2024-01-10",
        "compatible_with": ["MON-PROD-01", "BACKUP-01"],
        "description": "Critical kernel update for Ubuntu 20.04 addressing privilege escalation vulnerabilities.",
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
        "estimated_duration_minutes": 3,
        "size_mb": 8,
        "release_date": "2024-01-05",
        "compatible_with": ["APP-PROD-01", "APP-PROD-02", "MON-PROD-01", "BACKUP-01", "APP-STG-01"],
        "description": "Security update for curl addressing cookie mixing vulnerability.",
    },
    {
        "patch_id": "USN-6588-1",
        "title": "OpenSSL vulnerabilities - Ubuntu 20.04 / 22.04",
        "severity": "important",
        "cve_ids": ["CVE-2023-5678"],
        "cve_score": 7.5,
        "affected_os": ["Ubuntu 20.04 LTS", "Ubuntu 22.04 LTS"],
        "patch_type": "security",
        "reboot_required": False,
        "estimated_duration_minutes": 5,
        "size_mb": 15,
        "release_date": "2024-01-03",
        "compatible_with": ["APP-PROD-01", "APP-PROD-02", "MON-PROD-01", "BACKUP-01", "APP-STG-01"],
        "description": "Security update for OpenSSL addressing denial of service vulnerability in DH key generation.",
    },
]


# ─────────────────────────────────────────────
#  PATCH HISTORY
#  Simulates what has already been patched.
#  In Azure this comes from Update Manager logs.
# ─────────────────────────────────────────────

PATCH_HISTORY = {
    "WEB-PROD-01": [
        {"patch_id": "KB5031539", "applied_date": "2023-12-15", "status": "success", "applied_by": "patch-agent"},
        {"patch_id": "KB5028185", "applied_date": "2023-11-14", "status": "success", "applied_by": "patch-agent"},
    ],
    "WEB-PROD-02": [
        {"patch_id": "KB5031539", "applied_date": "2023-12-15", "status": "success", "applied_by": "patch-agent"},
    ],
    "DB-PROD-01": [
        {"patch_id": "KB5028948", "applied_date": "2023-11-14", "status": "success", "applied_by": "manual"},
        {"patch_id": "KB5026764", "applied_date": "2023-10-10", "status": "success", "applied_by": "manual"},
    ],
    "DB-PROD-02": [
        {"patch_id": "KB5028948", "applied_date": "2023-11-14", "status": "success", "applied_by": "manual"},
    ],
    "APP-PROD-01": [
        {"patch_id": "USN-6548-1", "applied_date": "2023-12-20", "status": "success", "applied_by": "patch-agent"},
    ],
    "APP-PROD-02": [
        {"patch_id": "USN-6548-1", "applied_date": "2023-12-20", "status": "success", "applied_by": "patch-agent"},
    ],
    "MON-PROD-01": [
        {"patch_id": "USN-6570-1", "applied_date": "2024-01-02", "status": "success", "applied_by": "patch-agent"},
    ],
    "WEB-STG-01": [],
    "APP-STG-01": [],
    "DB-STG-01": [],
    "INFRA-MGMT-01": [
        {"patch_id": "KB5031539", "applied_date": "2023-12-16", "status": "success", "applied_by": "patch-agent"},
    ],
    "BACKUP-01": [
        {"patch_id": "USN-6548-1", "applied_date": "2023-12-22", "status": "success", "applied_by": "patch-agent"},
    ],
}


# ─────────────────────────────────────────────
#  PUBLIC FUNCTIONS
#  These are what patch_tools.py imports and
#  calls. Swap these out for Azure API calls.
# ─────────────────────────────────────────────

def get_server_inventory() -> list[dict]:
    """
    Returns the full list of all servers in the fleet with their metadata.
    AZURE SWAP: Replace with Azure Resource Graph query:
      az graph query -q "Resources | where type == 'microsoft.compute/virtualmachines'"
    """
    return list(SERVER_REGISTRY.values())


def get_server_details(hostname: str) -> dict | None:
    """
    Returns detailed info about a single server.
    Returns None if the hostname is not found.
    """
    return SERVER_REGISTRY.get(hostname.upper())


def get_available_patches(hostname: str = None) -> list[dict]:
    """
    Returns patches available for a specific server, or all patches if no hostname given.
    AZURE SWAP: Replace with:
      Azure Update Manager - GET /subscriptions/{sub}/providers/Microsoft.Maintenance/updates
    """
    if hostname is None:
        return AVAILABLE_PATCHES

    server = SERVER_REGISTRY.get(hostname.upper())
    if not server:
        return []

    applicable = []
    for patch in AVAILABLE_PATCHES:
        if hostname.upper() in patch["compatible_with"]:
            applicable.append(patch)

    return applicable


def get_patch_history(hostname: str) -> list[dict]:
    """
    Returns all past patch records for a server.
    AZURE SWAP: Replace with Azure Update Manager deployment history API.
    """
    hostname = hostname.upper()
    history = PATCH_HISTORY.get(hostname, [])
    return sorted(history, key=lambda x: x["applied_date"], reverse=True)


def get_unpatched_servers() -> list[dict]:
    """
    Returns servers that have pending patches, sorted by criticality.
    Each entry includes the server plus its list of available patches.
    """
    unpatched = []
    for hostname, server in SERVER_REGISTRY.items():
        patches = get_available_patches(hostname)
        if patches:
            unpatched.append({
                "server": server,
                "pending_patches": patches,
                "critical_count": sum(1 for p in patches if p["severity"] == "critical"),
                "important_count": sum(1 for p in patches if p["severity"] == "important"),
                "highest_cve_score": max((p["cve_score"] for p in patches), default=0),
            })

    # Sort: critical environments first, then by highest CVE score
    def sort_key(item):
        env_priority = {"production": 0, "management": 1, "staging": 2}
        criticality_priority = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        env = env_priority.get(item["server"]["environment"], 99)
        crit = criticality_priority.get(item["server"]["criticality"], 99)
        cve = -item["highest_cve_score"]  # negative so higher CVE sorts first
        return (env, crit, cve)

    unpatched.sort(key=sort_key)
    return unpatched


def simulate_patch_apply(hostname: str, patch_id: str) -> dict:
    """
    Simulates applying a patch to a server. Returns success/failure result.
    AZURE SWAP: Replace with Azure Update Manager deployment API call.

    In simulation: 90% success rate, 10% failure (realistic).
    On success, adds the patch to history.
    """
    hostname = hostname.upper()
    server = SERVER_REGISTRY.get(hostname)
    patch = next((p for p in AVAILABLE_PATCHES if p["patch_id"] == patch_id), None)

    if not server:
        return {"success": False, "error": f"Server {hostname} not found in registry"}
    if not patch:
        return {"success": False, "error": f"Patch {patch_id} not found in patch library"}

    # Simulate realistic success/failure
    success = random.random() > 0.1  # 90% success rate

    if success:
        # Add to patch history
        if hostname not in PATCH_HISTORY:
            PATCH_HISTORY[hostname] = []
        PATCH_HISTORY[hostname].append({
            "patch_id": patch_id,
            "applied_date": datetime.now().strftime("%Y-%m-%d"),
            "status": "success",
            "applied_by": "patch-agent",
        })
        # Update last_patched on server
        SERVER_REGISTRY[hostname]["last_patched"] = datetime.now().strftime("%Y-%m-%d")

        return {
            "success": True,
            "hostname": hostname,
            "patch_id": patch_id,
            "patch_title": patch["title"],
            "reboot_required": patch["reboot_required"],
            "duration_minutes": patch["estimated_duration_minutes"],
            "message": f"Patch {patch_id} successfully applied to {hostname}",
        }
    else:
        return {
            "success": False,
            "hostname": hostname,
            "patch_id": patch_id,
            "error": "Patch installation failed: CBS package installation returned error 0x80070002",
            "message": f"Patch {patch_id} FAILED on {hostname} — rollback initiated",
        }


def simulate_health_check(hostname: str) -> dict:
    """
    Simulates a post-patch health check on a server.
    AZURE SWAP: Replace with Azure Monitor metric query or custom script.

    Checks: CPU, memory, key services running, ping response.
    95% chance of healthy result post-patch.
    """
    hostname = hostname.upper()
    server = SERVER_REGISTRY.get(hostname)
    if not server:
        return {"healthy": False, "error": f"Server {hostname} not found"}

    # Simulate health check results
    is_healthy = random.random() > 0.05  # 95% healthy after patch

    if is_healthy:
        return {
            "healthy": True,
            "hostname": hostname,
            "cpu_percent": round(random.uniform(5, 40), 1),
            "memory_percent": round(random.uniform(20, 65), 1),
            "disk_percent": round(random.uniform(30, 70), 1),
            "ping_ms": round(random.uniform(1, 15), 1),
            "services_up": server["services_running"],
            "services_down": [],
            "message": f"{hostname} is healthy post-patch",
        }
    else:
        failed_service = random.choice(server["services_running"]) if server["services_running"] else "unknown"
        return {
            "healthy": False,
            "hostname": hostname,
            "cpu_percent": round(random.uniform(80, 99), 1),
            "memory_percent": round(random.uniform(85, 99), 1),
            "disk_percent": round(random.uniform(30, 70), 1),
            "ping_ms": round(random.uniform(200, 2000), 1),
            "services_up": [s for s in server["services_running"] if s != failed_service],
            "services_down": [failed_service],
            "message": f"{hostname} UNHEALTHY post-patch — {failed_service} not responding",
        }


def simulate_rollback(hostname: str, patch_id: str) -> dict:
    """
    Simulates rolling back a patch on a server.
    AZURE SWAP: Replace with Azure Update Manager rollback API.
    Always succeeds in simulation (rollback is reliable).
    """
    hostname = hostname.upper()

    # Remove from patch history if present
    if hostname in PATCH_HISTORY:
        PATCH_HISTORY[hostname] = [
            p for p in PATCH_HISTORY[hostname] if p["patch_id"] != patch_id
        ]

    return {
        "success": True,
        "hostname": hostname,
        "patch_id": patch_id,
        "message": f"Rollback of {patch_id} on {hostname} completed successfully",
        "rollback_duration_minutes": 15,
    }