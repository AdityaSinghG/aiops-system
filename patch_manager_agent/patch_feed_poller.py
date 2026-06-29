"""
patch_feed_poller.py
=====================
Automated patch feed poller — the real, production-style entry point for
new patches, separate from manual file drops and from Infra Monitoring's
reactive OS check.

WHAT THIS IS:
  Polls Canonical's official Ubuntu Security Notices (USN) data feed for
  new security patches and automatically drops them into patch_inbox/ in
  our standard format — exactly as a human would, but with zero manual
  steps.

DATA SOURCE (real, not simulated):
  Canonical publishes every USN as a JSON file in the OSV (Open Source
  Vulnerability) format, in their public GitHub repository:
      https://github.com/canonical/ubuntu-security-notices
  Raw files are fetched directly from:
      https://raw.githubusercontent.com/canonical/ubuntu-security-notices/main/osv/usn/{USN_ID}.json
  This is Canonical's own recommended, actively maintained format — the
  older usn.ubuntu.com/usn-db/database.json endpoint is legacy and has
  had reliability issues, so we use the current GitHub-based feed instead.

WHY A WATCHLIST INSTEAD OF THE FULL FIREHOSE:
  Canonical publishes USNs for thousands of packages across every Ubuntu
  release. Our simulated server fleet only runs a small number of
  packages (web servers, app servers, etc.), so pulling every USN would
  flood the inbox with patches for software we don't have. In production,
  this watchlist would instead be generated automatically from your real
  asset inventory (Azure Resource Graph / CMDB) — "give me every USN that
  affects a package installed on one of our servers." Locally, we use a
  small watchlist of real, currently-published USN IDs as a stand-in for
  that asset-driven filtering.

  ⭐ UPDATED: We now go one step further than just a static watchlist —
  every fetched patch is checked against patch_inventory.SERVER_REGISTRY
  (our real asset inventory stand-in) BEFORE being dropped into the
  inbox. If a patch's affected_os doesn't match any OS actually running
  in our fleet, it's filtered out here instead of being discovered as
  "not applicable" later during deployment. This is the asset-driven
  filtering behaviour production would have via Azure Resource Graph.

WHAT GETS CONVERTED:
  Each real USN JSON (Canonical's OSV format) is mapped onto our standard
  patch schema (the same one used by patch_inbox/ files and AVAILABLE_PATCHES
  in patch_inventory.py):
    id                              → patch_id
    summary                         → title
    details                         → description
    published                      → release_date
    affected[].package.ecosystem    → affected_os (e.g. "Ubuntu:22.04:LTS" → "Ubuntu 22.04 LTS")
    affected[].database_specific
      .cves_map.cves[].id           → cve_ids
      .cves_map.cves[].severity     → severity + cve_score (Ubuntu priority word → our scale)

HOW TO RUN:
  # Check the feed once, drop any new patches into the inbox, exit
  python patch_feed_poller.py --once

  # Keep polling on an interval (default every 6 hours)
  python patch_feed_poller.py --watch

  # Show which USNs have already been pulled
  python patch_feed_poller.py --history

  # Show which USNs were filtered out as not applicable to our fleet
  python patch_feed_poller.py --not-applicable
"""

import json
import time
import argparse
import urllib.request
import urllib.error
from datetime import datetime
from pathlib import Path


# ─────────────────────────────────────────────
#  CONFIG
# ─────────────────────────────────────────────

INBOX_DIR = Path("patch_inbox")
SEEN_FILE = Path("patch_feed_seen.json")           # Tracks which USN IDs we've already pulled
NOT_APPLICABLE_FILE = Path("patch_feed_not_applicable.json")  # ⭐ NEW — tracks filtered-out USNs

GITHUB_RAW_BASE = (
    "https://raw.githubusercontent.com/canonical/ubuntu-security-notices/main/osv/usn"
)

# ── WATCHLIST ─────────────────────────────────────────────────────────────
# Real, currently-published USN IDs from Canonical's actual feed (confirmed
# live on GitHub at the time this was built). In production this list would
# be generated dynamically from your real asset inventory instead of being
# hardcoded here. Asset-driven filtering (below) now does part of that job
# even with this static starting list.
USN_WATCHLIST = [
    "USN-7486-1",   # libfcgi vulnerability
    "USN-7750-1",   # JSON-XS vulnerability
    "USN-8012-1",   # GitHub CLI vulnerabilities
    "USN-6793-1",   # Git vulnerabilities
    "USN-7934-1",   # Linux kernel vulnerabilities
]

# Ubuntu's own priority scale → our severity scale + a representative CVSS-like score
UBUNTU_PRIORITY_MAP = {
    "critical": ("critical", 9.5),
    "high":     ("critical", 8.5),
    "medium":   ("important", 6.5),
    "low":      ("moderate", 4.0),
    "negligible": ("low", 1.0),
    "untriaged": ("moderate", 5.0),
}


# ─────────────────────────────────────────────
#  SEEN-TRACKING
#  Prevents re-dropping the same USN every poll
# ─────────────────────────────────────────────

def load_seen() -> dict:
    if SEEN_FILE.exists():
        with open(SEEN_FILE, "r") as f:
            return json.load(f)
    return {}


def mark_seen(usn_id: str, outcome: str):
    seen = load_seen()
    seen[usn_id] = {
        "pulled_at": datetime.now().isoformat(),
        "outcome": outcome,
    }
    with open(SEEN_FILE, "w") as f:
        json.dump(seen, f, indent=2)


# ─────────────────────────────────────────────
#  NOT-APPLICABLE TRACKING  ⭐ NEW
#  Separate from "seen" — these were fetched and converted but filtered
#  out because no server in our fleet runs the affected OS. Tracked
#  separately so re-running --reset doesn't immediately re-fetch and
#  re-filter the same irrelevant patches every time, and so you have a
#  clear audit trail of "what we checked but didn't need."
# ─────────────────────────────────────────────

def load_not_applicable() -> dict:
    if NOT_APPLICABLE_FILE.exists():
        with open(NOT_APPLICABLE_FILE, "r") as f:
            return json.load(f)
    return {}


def mark_not_applicable(usn_id: str, affected_os: list, reason: str):
    not_applicable = load_not_applicable()
    not_applicable[usn_id] = {
        "checked_at": datetime.now().isoformat(),
        "affected_os": affected_os,
        "reason": reason,
    }
    with open(NOT_APPLICABLE_FILE, "w") as f:
        json.dump(not_applicable, f, indent=2)


# ─────────────────────────────────────────────
#  ASSET-DRIVEN FILTER  ⭐ NEW
#
#  Checks whether a converted patch's affected_os list matches any OS
#  actually running in our simulated fleet (patch_inventory.SERVER_REGISTRY).
#  This is the local stand-in for what Azure Resource Graph would do in
#  production: "does any of our real infrastructure actually run this?"
# ─────────────────────────────────────────────

def get_fleet_operating_systems() -> set:
    """
    Returns the set of distinct OS strings actually running across our
    simulated server fleet, read live from patch_inventory.SERVER_REGISTRY.
    This makes the filter genuinely asset-driven — if you add a new server
    running a new OS to the registry, the poller automatically starts
    accepting patches for it with no change needed here.
    """
    import sys
    import os as os_module

    project_root = os_module.path.dirname(os_module.path.abspath(__file__))
    if project_root not in sys.path:
        sys.path.insert(0, project_root)

    from patch_inventory import SERVER_REGISTRY

    return {server["os"] for server in SERVER_REGISTRY.values()}


def is_applicable_to_fleet(patch: dict, fleet_os_set: set) -> bool:
    """
    Returns True if at least one OS in the patch's affected_os list
    matches an OS actually running somewhere in our fleet.
    """
    patch_os_set = set(patch.get("affected_os", []))
    return len(patch_os_set & fleet_os_set) > 0


# ─────────────────────────────────────────────
#  FETCH — real network call to Canonical's feed
# ─────────────────────────────────────────────

def fetch_usn(usn_id: str) -> dict | None:
    """
    Fetches the real OSV-format JSON for a given USN ID from Canonical's
    public GitHub repository. Returns the parsed dict, or None on failure.
    """
    url = f"{GITHUB_RAW_BASE}/{usn_id}.json"
    print(f"[FEED] Fetching {usn_id} from {url}")

    try:
        req = urllib.request.Request(url, headers={"User-Agent": "aiops-patch-poller/1.0"})
        with urllib.request.urlopen(req, timeout=15) as response:
            raw = response.read().decode("utf-8")
            return json.loads(raw)
    except urllib.error.HTTPError as e:
        print(f"[FEED] HTTP error fetching {usn_id}: {e.code}")
        return None
    except urllib.error.URLError as e:
        print(f"[FEED] Network error fetching {usn_id}: {e.reason}")
        return None
    except json.JSONDecodeError as e:
        print(f"[FEED] Could not parse JSON for {usn_id}: {e}")
        return None


# ─────────────────────────────────────────────
#  CONVERT — Canonical's OSV format → our patch schema
# ─────────────────────────────────────────────

def convert_osv_to_patch_format(osv_data: dict) -> dict:
    """
    Converts a real Canonical OSV-format USN record into our standard
    patch JSON schema (same shape as files dropped in patch_inbox/ and
    entries in patch_inventory.AVAILABLE_PATCHES).
    """
    usn_id = osv_data.get("id", "UNKNOWN")
    summary = osv_data.get("summary", "No summary provided")
    details = osv_data.get("details", "")
    published = osv_data.get("published", "")
    release_date = published[:10] if published else datetime.now().strftime("%Y-%m-%d")

    affected_os = set()
    all_cve_ids = set()
    severities_found = []

    for affected_entry in osv_data.get("affected", []):
        ecosystem = affected_entry.get("package", {}).get("ecosystem", "")
        # Ecosystem looks like "Ubuntu:22.04:LTS" — convert to "Ubuntu 22.04 LTS"
        if ecosystem.startswith("Ubuntu:"):
            parts = ecosystem.split(":")
            if len(parts) == 3:
                affected_os.add(f"Ubuntu {parts[1]} {parts[2]}")

        cves_map = (
            affected_entry.get("database_specific", {})
            .get("cves_map", {})
            .get("cves", [])
        )
        for cve in cves_map:
            cve_id = cve.get("id")
            if cve_id:
                all_cve_ids.add(cve_id)

            for sev in cve.get("severity", []):
                if sev.get("type") == "Ubuntu":
                    severities_found.append(sev.get("score", "").lower())

    # Determine the highest severity found across all CVEs in this USN
    severity_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "negligible": 4, "untriaged": 5}
    severities_found.sort(key=lambda s: severity_rank.get(s, 99))
    top_priority = severities_found[0] if severities_found else "medium"
    mapped_severity, mapped_score = UBUNTU_PRIORITY_MAP.get(top_priority, ("important", 6.0))

    # Reboot requirement isn't in OSV data — kernel/core packages typically
    # need a reboot, application-level packages usually don't. We use a
    # simple heuristic based on the package name appearing in the summary.
    reboot_keywords = ["kernel", "linux", "systemd", "glibc"]
    reboot_required = any(kw in summary.lower() for kw in reboot_keywords)

    return {
        "patch_id": usn_id,
        "title": summary,
        "severity": mapped_severity,
        "cve_ids": sorted(all_cve_ids),
        "cve_score": mapped_score,
        "affected_os": sorted(affected_os) if affected_os else ["Ubuntu 22.04 LTS"],
        "patch_type": "security",
        "reboot_required": reboot_required,
        "release_date": release_date,
        "description": details.strip()[:500] if details else summary,
        "source": "canonical_usn_feed",
        "source_url": f"https://ubuntu.com/security/notices/{usn_id}",
    }


# ─────────────────────────────────────────────
#  DROP INTO INBOX
# ─────────────────────────────────────────────

def drop_into_inbox(patch: dict) -> Path:
    """Writes the converted patch dict as a JSON file into patch_inbox/."""
    INBOX_DIR.mkdir(exist_ok=True)
    filepath = INBOX_DIR / f"{patch['patch_id']}.json"

    with open(filepath, "w") as f:
        json.dump(patch, f, indent=2)

    return filepath


# ─────────────────────────────────────────────
#  MAIN POLL CYCLE
# ─────────────────────────────────────────────

def poll_feed_once() -> dict:
    """
    Checks the watchlist against what's already been pulled, fetches any
    new USNs from the real Canonical feed, converts them, filters them
    against our real fleet inventory, and drops only applicable patches
    into patch_inbox/.

    Returns a summary dict of what happened this cycle.
    """
    print(f"\n{'='*70}")
    print(f"PATCH FEED POLLER — Checking Canonical USN feed")
    print(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*70}")

    # ⭐ NEW — load our real fleet's OS list once per poll cycle
    fleet_os_set = get_fleet_operating_systems()
    print(f"[FEED] Fleet runs: {', '.join(sorted(fleet_os_set))}")

    seen = load_seen()
    not_applicable = load_not_applicable()
    new_patches = []
    filtered_out = []
    failed_fetches = []
    already_seen = []

    for usn_id in USN_WATCHLIST:
        if usn_id in seen or usn_id in not_applicable:
            already_seen.append(usn_id)
            continue

        osv_data = fetch_usn(usn_id)
        if osv_data is None:
            failed_fetches.append(usn_id)
            continue

        patch = convert_osv_to_patch_format(osv_data)

        # ⭐ NEW — asset-driven filter, before dropping into inbox
        if not is_applicable_to_fleet(patch, fleet_os_set):
            print(f"[FEED] ⏭️  Skipping {usn_id} — affects {patch['affected_os']}, "
                  f"none of which run anywhere in our fleet")
            mark_not_applicable(
                usn_id,
                affected_os=patch["affected_os"],
                reason=f"No server in fleet runs any of: {patch['affected_os']}",
            )
            filtered_out.append(usn_id)
            continue

        filepath = drop_into_inbox(patch)
        mark_seen(usn_id, outcome="dropped")

        print(f"[FEED] ✅ New patch dropped: {filepath}")
        print(f"[FEED]    Severity: {patch['severity']} | CVEs: {', '.join(patch['cve_ids']) or 'none listed'}")
        print(f"[FEED]    Affects: {', '.join(patch['affected_os'])}")

        new_patches.append(patch["patch_id"])

    summary = {
        "checked_at": datetime.now().isoformat(),
        "watchlist_size": len(USN_WATCHLIST),
        "fleet_operating_systems": sorted(fleet_os_set),
        "new_patches_dropped": new_patches,
        "filtered_out_not_applicable": filtered_out,
        "already_seen": already_seen,
        "failed_fetches": failed_fetches,
    }

    print(f"\n[FEED] Poll complete.")
    print(f"[FEED]   New patches dropped into inbox:        {len(new_patches)}")
    print(f"[FEED]   Filtered out (not applicable to fleet): {len(filtered_out)}")
    print(f"[FEED]   Already seen/checked (skipped):         {len(already_seen)}")
    print(f"[FEED]   Failed to fetch:                        {len(failed_fetches)}")
    print(f"{'='*70}\n")

    return summary


def watch_feed(poll_interval_hours: float = 6.0):
    """
    Continuously polls the feed on a fixed interval. Press Ctrl+C to stop.
    In production this would run as a scheduled job (cron / Azure Function
    timer trigger) rather than a long-running loop.
    """
    print(f"[FEED] Starting continuous watch mode — polling every {poll_interval_hours} hour(s)")
    print(f"[FEED] Press Ctrl+C to stop.\n")

    try:
        while True:
            poll_feed_once()
            print(f"[FEED] Sleeping for {poll_interval_hours} hour(s)...")
            time.sleep(poll_interval_hours * 3600)
    except KeyboardInterrupt:
        print("\n[FEED] Stopped watching. Goodbye!")


def show_history():
    """Prints every USN that's been pulled so far, with outcome."""
    seen = load_seen()

    if not seen:
        print("\n[FEED] No patches pulled yet. Run --once first.")
        return

    print(f"\n{'='*70}")
    print(f"  PATCH FEED HISTORY — {len(seen)} USN(s) tracked")
    print(f"{'='*70}")
    print(f"  {'USN ID':<16} {'PULLED AT':<22} {'OUTCOME'}")
    print(f"  {'-'*16} {'-'*22} {'-'*10}")

    for usn_id, record in sorted(seen.items(), key=lambda x: x[1]["pulled_at"], reverse=True):
        print(f"  {usn_id:<16} {record['pulled_at'][:19]:<22} {record['outcome']}")

    print(f"{'='*70}\n")


def show_not_applicable():
    """⭐ NEW — Prints every USN that was filtered out as not applicable to our fleet."""
    not_applicable = load_not_applicable()

    if not not_applicable:
        print("\n[FEED] No patches have been filtered out yet.")
        return

    print(f"\n{'='*70}")
    print(f"  NOT APPLICABLE TO FLEET — {len(not_applicable)} USN(s) filtered")
    print(f"{'='*70}")

    for usn_id, record in sorted(not_applicable.items(), key=lambda x: x[1]["checked_at"], reverse=True):
        print(f"  {usn_id}")
        print(f"    Checked at:  {record['checked_at'][:19]}")
        print(f"    Affects:     {', '.join(record['affected_os'])}")
        print(f"    Reason:      {record['reason']}")
        print()

    print(f"{'='*70}\n")


# ─────────────────────────────────────────────
#  MAIN
# ─────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Ubuntu USN Patch Feed Poller — pulls real patches from Canonical's public feed",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python patch_feed_poller.py --once               # Check feed once, drop applicable patches, exit
  python patch_feed_poller.py --watch               # Poll continuously every 6 hours
  python patch_feed_poller.py --watch --interval 1  # Poll every 1 hour instead
  python patch_feed_poller.py --history             # Show what's been pulled so far
  python patch_feed_poller.py --not-applicable      # Show what was filtered out as irrelevant
  python patch_feed_poller.py --reset               # Clear all history (re-pull and re-filter everything)
        """,
    )
    parser.add_argument("--once", action="store_true", help="Poll the feed once and exit")
    parser.add_argument("--watch", action="store_true", help="Poll continuously on an interval")
    parser.add_argument("--interval", type=float, default=6.0, help="Poll interval in hours (default: 6)")
    parser.add_argument("--history", action="store_true", help="Show pull history")
    parser.add_argument("--not-applicable", action="store_true", help="Show USNs filtered out as not applicable to our fleet")
    parser.add_argument("--reset", action="store_true", help="Clear all history so all USNs are re-pulled and re-filtered")

    args = parser.parse_args()

    if args.reset:
        if SEEN_FILE.exists():
            SEEN_FILE.unlink()
        if NOT_APPLICABLE_FILE.exists():
            NOT_APPLICABLE_FILE.unlink()
        print("[FEED] All history cleared. Next poll will re-pull and re-filter all watchlist USNs.")
    elif args.history:
        show_history()
    elif args.not_applicable:
        show_not_applicable()
    elif args.watch:
        watch_feed(poll_interval_hours=args.interval)
    elif args.once:
        poll_feed_once()
    else:
        # Default: poll once
        poll_feed_once()