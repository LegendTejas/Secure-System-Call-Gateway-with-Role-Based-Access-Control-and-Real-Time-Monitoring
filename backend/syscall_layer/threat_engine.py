"""
syscall/threat_engine.py
Vanshika — Threat Detection Engine + Risk Score System.

This module analyzes syscall logs to detect suspicious behavior patterns.

Detection Rules:
    Rule 1 — Too Many Blocked Calls   : 5+ blocked calls in last 10 minutes → +10 risk
    Rule 2 — Rapid Repeated Requests  : 20+ calls in last 60 seconds         → +5 risk
    Rule 3 — Restricted Path Access   : any /etc, /root, /sys attempt        → +5 risk (immediate)

Risk Score Table:
    Blocked syscall             → +3
    Restricted path attempt     → +5
    Rapid repeated requests     → +5
    5+ blocked calls in window  → +10
    Risk >= 50                  → user auto-flagged
"""

from datetime import datetime, timezone, timedelta
from database.db import get_connection
from syscall.logger import update_user_risk

# ── Risk Delta Constants ──────────────────────────────────────────────────────

RISK_BLOCKED_SYSCALL        = 3.0    # every blocked call
RISK_RESTRICTED_PATH        = 5.0    # trying to access /etc, /root, etc.
RISK_RAPID_REQUESTS         = 5.0    # too many requests in short time
RISK_REPEATED_FAILURES      = 10.0   # 5+ blocked calls in 10 minutes

# Thresholds
RAPID_REQUEST_COUNT         = 20     # more than this many calls...
RAPID_REQUEST_WINDOW_SEC    = 60     # ...within this many seconds = suspicious

REPEATED_FAILURE_COUNT      = 5      # more than this many blocked calls...
REPEATED_FAILURE_WINDOW_MIN = 10     # ...within this many minutes = suspicious

# Paths that trigger immediate risk increase
RESTRICTED_PATHS = ["/etc", "/root", "/sys", "/proc", "/bin", "/usr", "/boot", "/dev"]


# ── Rule 1: Too Many Blocked Calls ───────────────────────────────────────────

def check_repeated_failures(user_id: int) -> dict:
    """
    Rule 1: If a user has 5+ blocked calls in the last 10 minutes,
    add +10 to their risk score.

    Returns:
        { "triggered": True/False, "count": N, "risk_added": X }
    """
    window_start = (
        datetime.now(timezone.utc) - timedelta(minutes=REPEATED_FAILURE_WINDOW_MIN)
    ).isoformat()

    conn = get_connection()
    try:
        row = conn.execute(
            """
            SELECT COUNT(*) as cnt FROM syscall_logs
            WHERE user_id = ?
              AND status = 'blocked'
              AND timestamp >= ?
            """,
            (user_id, window_start)
        ).fetchone()

        count = row["cnt"] if row else 0

        if count >= REPEATED_FAILURE_COUNT:
            update_user_risk(user_id, RISK_REPEATED_FAILURES)
            return {
                "triggered":  True,
                "count":      count,
                "risk_added": RISK_REPEATED_FAILURES,
                "reason":     f"{count} blocked calls in last {REPEATED_FAILURE_WINDOW_MIN} minutes."
            }

        return {"triggered": False, "count": count, "risk_added": 0}
    finally:
        conn.close()


# ── Rule 2: Rapid Repeated Requests ──────────────────────────────────────────

def check_rapid_requests(user_id: int) -> dict:
    """
    Rule 2: If a user makes 20+ calls in the last 60 seconds,
    add +5 to their risk score (possible automation or attack).

    Returns:
        { "triggered": True/False, "count": N, "risk_added": X }
    """
    window_start = (
        datetime.now(timezone.utc) - timedelta(seconds=RAPID_REQUEST_WINDOW_SEC)
    ).isoformat()

    conn = get_connection()
    try:
        row = conn.execute(
            """
            SELECT COUNT(*) as cnt FROM syscall_logs
            WHERE user_id = ?
              AND timestamp >= ?
            """,
            (user_id, window_start)
        ).fetchone()

        count = row["cnt"] if row else 0

        if count >= RAPID_REQUEST_COUNT:
            update_user_risk(user_id, RISK_RAPID_REQUESTS)
            return {
                "triggered":  True,
                "count":      count,
                "risk_added": RISK_RAPID_REQUESTS,
                "reason":     f"{count} requests in last {RAPID_REQUEST_WINDOW_SEC} seconds."
            }

        return {"triggered": False, "count": count, "risk_added": 0}
    finally:
        conn.close()


# ── Rule 3: Restricted Path Access ───────────────────────────────────────────

def check_restricted_path(path: str | None) -> dict:
    """
    Rule 3: If the requested path starts with a restricted system directory,
    this is flagged immediately with +5 risk.

    This is called BEFORE the syscall wrapper executes anything.

    Returns:
        { "triggered": True/False, "risk_added": X }
    """
    if not path:
        return {"triggered": False, "risk_added": 0}

    for restricted in RESTRICTED_PATHS:
        if path.strip().startswith(restricted):
            return {
                "triggered":  True,
                "risk_added": RISK_RESTRICTED_PATH,
                "reason":     f"Attempted access to restricted path: '{path}'."
            }

    return {"triggered": False, "risk_added": 0}


# ── Main Threat Analysis ──────────────────────────────────────────────────────

def analyze_threat(user_id: int, path: str | None, was_blocked: bool) -> dict:
    """
    Run all threat detection rules for a user after a syscall.

    Call this AFTER every syscall (allowed or blocked).

    Args:
        user_id     : the user who made the call
        path        : the target path (if any)
        was_blocked : whether this syscall was blocked

    Returns:
        {
          "risk_added":       total risk added this call,
          "rules_triggered":  list of rule names that fired,
          "is_flagged":       whether user is now flagged
        }
    """
    total_risk     = 0.0
    rules_triggered = []

    # Base risk for every blocked call
    if was_blocked:
        update_user_risk(user_id, RISK_BLOCKED_SYSCALL)
        total_risk += RISK_BLOCKED_SYSCALL
        rules_triggered.append("blocked_syscall")

    # Rule 3: Restricted path check (immediate)
    path_check = check_restricted_path(path)
    if path_check["triggered"]:
        update_user_risk(user_id, path_check["risk_added"])
        total_risk += path_check["risk_added"]
        rules_triggered.append("restricted_path_access")

    # Rule 1: Repeated failures in window
    failure_check = check_repeated_failures(user_id)
    if failure_check["triggered"]:
        total_risk += failure_check["risk_added"]
        rules_triggered.append("repeated_failures")

    # Rule 2: Rapid requests
    rapid_check = check_rapid_requests(user_id)
    if rapid_check["triggered"]:
        total_risk += rapid_check["risk_added"]
        rules_triggered.append("rapid_requests")

    # Check if user is now flagged
    conn = get_connection()
    try:
        row = conn.execute(
            "SELECT is_flagged, risk_score FROM users WHERE id = ?", (user_id,)
        ).fetchone()
        is_flagged = bool(row["is_flagged"]) if row else False
        risk_score = row["risk_score"] if row else 0.0
    finally:
        conn.close()

    return {
        "risk_added":      total_risk,
        "rules_triggered": rules_triggered,
        "is_flagged":      is_flagged,
        "current_risk":    risk_score,
    }


# ── Flagged Users List ────────────────────────────────────────────────────────

def get_flagged_users() -> list[dict]:
    """
    Return all users who are currently flagged (is_flagged = 1).
    Used by the /api/threats endpoint for the dashboard.
    """
    conn = get_connection()
    try:
        rows = conn.execute(
            """
            SELECT id, username, role, risk_score, is_flagged, created_at
            FROM users
            WHERE is_flagged = 1
            ORDER BY risk_score DESC
            """
        ).fetchall()
        return [dict(row) for row in rows]
    finally:
        conn.close()


# ── Dashboard Stats ───────────────────────────────────────────────────────────

def get_dashboard_stats() -> dict:
    """
    Compute summary statistics for the dashboard.
    Used by /api/dashboard/stats endpoint.

    Returns:
        {
          total_calls, allowed_calls, blocked_calls,
          flagged_users, top_users, recent_activity
        }
    """
    conn = get_connection()
    try:
        # Total calls
        total = conn.execute(
            "SELECT COUNT(*) as cnt FROM syscall_logs"
        ).fetchone()["cnt"]

        # Allowed vs blocked
        allowed = conn.execute(
            "SELECT COUNT(*) as cnt FROM syscall_logs WHERE status = 'allowed'"
        ).fetchone()["cnt"]

        blocked = conn.execute(
            "SELECT COUNT(*) as cnt FROM syscall_logs WHERE status = 'blocked'"
        ).fetchone()["cnt"]

        # Number of flagged users
        flagged_count = conn.execute(
            "SELECT COUNT(*) as cnt FROM users WHERE is_flagged = 1"
        ).fetchone()["cnt"]

        # Top 5 most active users
        top_users = conn.execute(
            """
            SELECT u.username, COUNT(l.id) as call_count
            FROM syscall_logs l
            JOIN users u ON l.user_id = u.id
            GROUP BY l.user_id
            ORDER BY call_count DESC
            LIMIT 5
            """
        ).fetchall()

        # Last 10 activity entries
        recent = conn.execute(
            """
            SELECT l.call_type, l.status, l.target_path, l.timestamp, u.username
            FROM syscall_logs l
            JOIN users u ON l.user_id = u.id
            ORDER BY l.id DESC
            LIMIT 10
            """
        ).fetchall()

        return {
            "total_calls":    total,
            "allowed_calls":  allowed,
            "blocked_calls":  blocked,
            "flagged_users":  flagged_count,
            "top_users":      [dict(r) for r in top_users],
            "recent_activity": [dict(r) for r in recent],
        }
    finally:
        conn.close()
