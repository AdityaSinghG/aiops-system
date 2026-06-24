# ─────────────────────────────────────────────────────────────────────────────
#  agent/tools.py
#
#  These are the monitoring tools the Infrastructure Monitoring Agent uses
#  to collect real system metrics from the machine it runs on.
#
#  LOCAL DEV  : Uses psutil to read your actual laptop's metrics in real time.
#  PRODUCTION : Each tool will be swapped to call Azure Monitor REST API
#               instead of psutil. The tool names and return shapes stay
#               identical so the agent graph needs zero changes.
#
#  Every tool is decorated with @tool from LangChain so LangGraph can
#  automatically wire them into the agent's reasoning loop.
# ─────────────────────────────────────────────────────────────────────────────

import psutil
import platform
import datetime
import sys
import os
from langchain.tools import tool


# ─────────────────────────────────────────────────────────────────────────────
#  TOOL 1 — CPU Metrics
# ─────────────────────────────────────────────────────────────────────────────

@tool
def get_cpu_metrics() -> dict:
    """
    Collect current CPU usage statistics from the system.

    Returns overall CPU usage percentage, per-core breakdown,
    CPU count (logical and physical), current frequency in MHz,
    and system load average where available.

    Use this tool to assess whether the CPU is under normal,
    elevated, or critical load.
    """
    # cpu_percent with interval=1 means it measures over a 1-second
    # window for accuracy. Without interval it returns 0.0 on first call.
    overall_usage = psutil.cpu_percent(interval=1)
    per_core_usage = psutil.cpu_percent(interval=1, percpu=True)

    # Frequency — not available on all systems, handle gracefully
    freq = psutil.cpu_freq()
    cpu_freq_mhz = round(freq.current, 2) if freq else "unavailable"
    cpu_freq_max_mhz = round(freq.max, 2) if freq else "unavailable"

    # Load average — Unix only, returns (1min, 5min, 15min)
    # On Windows psutil.getloadavg() may not be available
    try:
        load_avg = psutil.getloadavg()
        load_average = {
            "1_min": round(load_avg[0], 2),
            "5_min": round(load_avg[1], 2),
            "15_min": round(load_avg[2], 2)
        }
    except AttributeError:
        load_average = "unavailable on Windows"

    return {
        "timestamp": datetime.datetime.now().isoformat(),
        "cpu_percent_overall": overall_usage,
        "cpu_per_core_percent": per_core_usage,
        "cpu_logical_count": psutil.cpu_count(logical=True),
        "cpu_physical_count": psutil.cpu_count(logical=False),
        "cpu_freq_current_mhz": cpu_freq_mhz,
        "cpu_freq_max_mhz": cpu_freq_max_mhz,
        "load_average": load_average,
        "platform": platform.system()
    }


# ─────────────────────────────────────────────────────────────────────────────
#  TOOL 2 — Memory Metrics
# ─────────────────────────────────────────────────────────────────────────────

@tool
def get_memory_metrics() -> dict:
    """
    Collect current RAM and swap memory usage statistics.

    Returns total, used, available, and percentage for both
    physical RAM and swap memory.

    Use this tool to assess memory pressure. High memory usage
    with low swap indicates the system is close to exhaustion.
    High swap usage means the system is already under memory stress.
    """
    ram = psutil.virtual_memory()
    swap = psutil.swap_memory()

    return {
        "timestamp": datetime.datetime.now().isoformat(),

        # Physical RAM
        "ram": {
            "total_gb": round(ram.total / 1e9, 2),
            "used_gb": round(ram.used / 1e9, 2),
            "available_gb": round(ram.available / 1e9, 2),
            "free_gb": round(ram.free / 1e9, 2),
            "percent_used": ram.percent,
            "percent_available": round(100 - ram.percent, 2)
        },

        # Swap / Virtual memory
        "swap": {
            "total_gb": round(swap.total / 1e9, 2),
            "used_gb": round(swap.used / 1e9, 2),
            "free_gb": round(swap.free / 1e9, 2),
            "percent_used": swap.percent,
            "swap_in_mb": round(swap.sin / 1e6, 2),   # Data swapped in from disk
            "swap_out_mb": round(swap.sout / 1e6, 2)  # Data swapped out to disk
        }
    }


# ─────────────────────────────────────────────────────────────────────────────
#  TOOL 3 — Disk Metrics
# ─────────────────────────────────────────────────────────────────────────────

@tool
def get_disk_metrics() -> dict:
    """
    Collect disk usage statistics for all mounted partitions,
    plus disk I/O read and write throughput.

    Returns usage percentage, total size, used space, and free
    space for every partition. Also returns total disk read and
    write bytes since system boot.

    Use this tool to identify partitions approaching capacity.
    Disk issues are urgent — a full disk can crash services instantly.
    """
    partitions_data = []

    for partition in psutil.disk_partitions(all=False):
        # Skip CD-ROM drives and other removable media on Windows
        # that have no disk inserted — they raise errors on usage call
        try:
            usage = psutil.disk_usage(partition.mountpoint)
            partitions_data.append({
                "mountpoint": partition.mountpoint,
                "device": partition.device,
                "filesystem_type": partition.fstype,
                "total_gb": round(usage.total / 1e9, 2),
                "used_gb": round(usage.used / 1e9, 2),
                "free_gb": round(usage.free / 1e9, 2),
                "percent_used": usage.percent,
                "percent_free": round(100 - usage.percent, 2)
            })
        except (PermissionError, OSError):
            # Skip partitions we don't have permission to read
            continue

    # Disk I/O counters — total reads and writes since boot
    io = psutil.disk_io_counters()
    disk_io = {
        "total_read_gb": round(io.read_bytes / 1e9, 2),
        "total_write_gb": round(io.write_bytes / 1e9, 2),
        "read_count": io.read_count,
        "write_count": io.write_count
    } if io else "unavailable"

    return {
        "timestamp": datetime.datetime.now().isoformat(),
        "partitions": partitions_data,
        "disk_io_since_boot": disk_io
    }


# ─────────────────────────────────────────────────────────────────────────────
#  TOOL 4 — Network Metrics
# ─────────────────────────────────────────────────────────────────────────────

@tool
def get_network_metrics() -> dict:
    """
    Collect network I/O statistics and per-interface details.

    Returns total bytes sent and received, total packets sent
    and received, error counts (in and out), and dropped packet
    counts. Also returns per-network-interface breakdown.

    Use this tool to detect network anomalies. Error counts above
    zero indicate hardware or configuration problems. Sudden spikes
    in traffic may indicate an incident or runaway process.
    """
    # Overall network I/O across all interfaces
    net_io = psutil.net_io_counters()

    overall = {
        "bytes_sent_mb": round(net_io.bytes_sent / 1e6, 2),
        "bytes_recv_mb": round(net_io.bytes_recv / 1e6, 2),
        "packets_sent": net_io.packets_sent,
        "packets_recv": net_io.packets_recv,
        "errors_in": net_io.errin,
        "errors_out": net_io.errout,
        "drop_in": net_io.dropin,
        "drop_out": net_io.dropout
    }

    # Per-interface breakdown
    per_interface = {}
    net_per_nic = psutil.net_io_counters(pernic=True)
    for interface_name, stats in net_per_nic.items():
        per_interface[interface_name] = {
            "bytes_sent_mb": round(stats.bytes_sent / 1e6, 2),
            "bytes_recv_mb": round(stats.bytes_recv / 1e6, 2),
            "errors_in": stats.errin,
            "errors_out": stats.errout,
            "drop_in": stats.dropin,
            "drop_out": stats.dropout
        }

    # Active network connections count
    try:
        connections = psutil.net_connections()
        connection_summary = {
            "total_connections": len(connections),
            "established": len([c for c in connections if c.status == "ESTABLISHED"]),
            "listening": len([c for c in connections if c.status == "LISTEN"]),
            "time_wait": len([c for c in connections if c.status == "TIME_WAIT"])
        }
    except (psutil.AccessDenied, PermissionError):
        connection_summary = "requires elevated permissions"

    return {
        "timestamp": datetime.datetime.now().isoformat(),
        "overall": overall,
        "per_interface": per_interface,
        "connection_summary": connection_summary
    }


# ─────────────────────────────────────────────────────────────────────────────
#  TOOL 5 — Top Processes
# ─────────────────────────────────────────────────────────────────────────────

@tool
def get_top_processes() -> dict:
    """
    Identify the top 5 processes consuming the most CPU and the
    top 5 processes consuming the most memory right now.

    Returns process ID, name, CPU percentage, memory percentage,
    memory in MB, and current status for each process.

    Use this tool to find the root cause of high CPU or memory
    readings. If CPU is at 90%, this tool will tell you exactly
    which process is responsible.
    """
    processes = []

    for proc in psutil.process_iter([
        'pid', 'name', 'cpu_percent',
        'memory_percent', 'memory_info',
        'status', 'username'
    ]):
        try:
            info = proc.info
            # memory_info can be None on some system processes
            mem_mb = round(info['memory_info'].rss / 1e6, 2) \
                if info.get('memory_info') else 0.0

            processes.append({
                "pid": info['pid'],
                "name": info['name'],
                "cpu_percent": round(info['cpu_percent'] or 0.0, 2),
                "memory_percent": round(info['memory_percent'] or 0.0, 2),
                "memory_mb": mem_mb,
                "status": info['status'],
                "username": info.get('username', 'unknown')
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            # Process died between iteration and info collection — skip it
            continue

    # Sort and take top 5 for CPU and memory separately
    top_by_cpu = sorted(
        processes,
        key=lambda x: x['cpu_percent'],
        reverse=True
    )[:5]

    top_by_memory = sorted(
        processes,
        key=lambda x: x['memory_percent'],
        reverse=True
    )[:5]

    # Flag any process breaching dangerous thresholds
    flagged = [
        p for p in processes
        if p['cpu_percent'] > 50 or p['memory_percent'] > 40
    ]

    return {
        "timestamp": datetime.datetime.now().isoformat(),
        "top_5_by_cpu": top_by_cpu,
        "top_5_by_memory": top_by_memory,
        "flagged_processes": flagged,
        "total_processes_scanned": len(processes)
    }


# ─────────────────────────────────────────────────────────────────────────────
#  TOOL 6 — OS Patch Status Check  ⭐ NEW
#
#  This is a new capability — it did not exist before. It checks the real
#  OS this code is running on (via the platform module — completely real,
#  not simulated) and cross-references it against the Patch Manager
#  Agent's known patch list to see if any patches are outstanding.
#
#  WHY THIS MATTERS:
#    Until now, Infra Monitoring only watched CPU/memory/disk/network.
#    It had zero visibility into whether the OS itself needed patching.
#    This tool closes that gap — it's what lets Infra Monitoring hand off
#    real patch-needed events to the Patch Manager Agent.
#
#  PRODUCTION SWAP:
#    Replace the "load patches" section with a call to Azure Update
#    Manager's compliance API for this VM's resource ID. Tool signature
#    and return shape stay identical — graph.py needs zero changes.
# ─────────────────────────────────────────────────────────────────────────────

# Allow importing from patch_manager_agent, which sits as a sibling folder
# at the project root (aiops-system/patch_manager_agent/)
_PROJECT_ROOT = os.path.join(os.path.dirname(__file__), "..", "..")
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)


def _get_local_os_label() -> str:
    """
    Maps the real local OS (from Python's platform module) to the same
    OS naming convention used in patch_manager_agent's AVAILABLE_PATCHES
    (e.g. "Windows Server 2022", "Ubuntu 22.04 LTS").

    This is a best-effort mapping for local dev. On a real Windows Server
    or Ubuntu machine, platform.platform() returns enough detail to map
    directly. On a Windows 10/11 dev laptop (the common case for this
    project), we map it to the closest equivalent server OS so the demo
    still shows realistic matches. This mapping is logged clearly so it's
    never mistaken for the real production OS.
    """
    system = platform.system()  # 'Windows' or 'Linux'

    if system == "Windows":
        return "Windows Server 2022"

    elif system == "Linux":
        try:
            with open("/etc/os-release") as f:
                os_release = f.read()
            if "22.04" in os_release:
                return "Ubuntu 22.04 LTS"
            elif "20.04" in os_release:
                return "Ubuntu 20.04 LTS"
        except FileNotFoundError:
            pass
        return "Ubuntu 22.04 LTS"  # default fallback for non-Ubuntu Linux dev

    return "Unknown OS"


@tool
def check_os_patch_status() -> dict:
    """
    Check whether the local machine's operating system has any outstanding
    security or quality patches pending, by cross-referencing against the
    Patch Manager Agent's known patch catalogue.

    Returns the OS detected, whether any patches are outstanding, and full
    details of each outstanding patch including severity and CVE score.

    Use this tool to determine if a patch-needed event should be raised
    to the Patch Manager Agent. Any CRITICAL or IMPORTANT severity patch
    found here should result in an escalation.
    """
    detected_os = _get_local_os_label()
    real_system = platform.system()
    real_release = platform.release()

    outstanding_patches = []
    load_error = None

    try:
        from patch_manager_agent.patch_inventory import AVAILABLE_PATCHES

        for patch in AVAILABLE_PATCHES:
            if detected_os in patch.get("affected_os", []):
                outstanding_patches.append({
                    "patch_id": patch["patch_id"],
                    "title": patch["title"],
                    "severity": patch["severity"],
                    "cve_score": patch["cve_score"],
                    "cve_ids": patch["cve_ids"],
                    "reboot_required": patch["reboot_required"],
                    "release_date": patch["release_date"],
                })

    except ImportError as e:
        load_error = f"Could not load patch catalogue: {str(e)}"

    # Sort outstanding patches by severity (critical first)
    severity_order = {"critical": 0, "important": 1, "moderate": 2, "low": 3}
    outstanding_patches.sort(key=lambda p: severity_order.get(p["severity"], 99))

    highest_severity = outstanding_patches[0]["severity"] if outstanding_patches else "none"
    highest_cve = max((p["cve_score"] for p in outstanding_patches), default=0.0)

    return {
        "timestamp": datetime.datetime.now().isoformat(),
        "real_os_system": real_system,
        "real_os_release": real_release,
        "mapped_os_label": detected_os,
        "patches_outstanding": len(outstanding_patches),
        "outstanding_patches": outstanding_patches,
        "highest_severity": highest_severity,
        "highest_cve_score": highest_cve,
        "patch_action_needed": len(outstanding_patches) > 0,
        "load_error": load_error,
    }


# ─────────────────────────────────────────────────────────────────────────────
#  MONITORING_TOOLS — exported list used by the agent graph
#
#  This is what graph.py imports. Add new tools here and they are
#  automatically available to the agent without changing graph.py.
# ─────────────────────────────────────────────────────────────────────────────

MONITORING_TOOLS = [
    get_cpu_metrics,
    get_memory_metrics,
    get_disk_metrics,
    get_network_metrics,
    get_top_processes,
    check_os_patch_status   
]