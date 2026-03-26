"""
syscall/logger.py
Vanshika — Secure Audit Logging System with SHA256 Hash Chain.

Every syscall (allowed or blocked) is logged here.
Logs are chained using SHA256 so any tampering is detectable.

Hash Chain Logic:
    Log1: hash = SHA256(log1_data)
    Log2: hash = SHA256(prev_hash + log2_data)
    Log3: hash = SHA256(prev_hash + log3_data)
    ...
    If anyone edits Log2, Log3's hash will no longer match → tamper detected.
"""

import hashlib
import json
from datetime import datetime, timezone

from database.db import get_connection


# ── Internal Helper ───────────────────────────────────────────────────────────

def _get_last_log_hash() -> str | None:
    """
    Fetch the hash of the most recent log entry.
    This becomes prev_hash for the next log entry.
    Returns None if no logs exist yet (first entry).
    """
    conn = get_connection()
    try:
        row = conn.execute(
            "SELECT log_hash FROM syscall_logs ORDER BY id DESC LIMIT 1"
        ).fetchone()
        return row["log_hash"] if row else None
    finally:
        conn.close()


def _compute_hash(prev_hash: str | None, log_data: dict) -> str:
    """
    Compute SHA256 hash for a log entry.

    Formula:
        hash = SHA256( prev_hash + JSON(log_data) )

    If prev_hash is None (first log), we use empty string.
    """
    data_str   = json.dumps(log_data, sort_keys=True, default=str)
    combined   = (prev_hash or "") + data_str
    return hashlib.sha256(combined.encode("utf-8")).hexdigest()


# ── Main Log Function ─────────────────────────────────────────────────────────

def write_log(
    user_id:     int,
    call_type:   str,
    target_path: str | None,
    status:      str,          # "allowed" | "blocked" | "flagged"
    reason:      str | None,
    risk_delta:  float = 0.0,
) -> dict:
    """
    Write a single syscall log entry to the database with hash chaining.

    Args:
        user_id     : ID of the user performing the action
        call_type   : e.g. "file_read", "file_write", "exec_process"
        target_path : the file or command target (can be None)
        status      : "allowed", "blocked", or "flagged"
        reason      : why it was blocked/flagged (None if allowed)
        risk_delta  : how much was added to the user's risk score

    Returns:
        { "success": True, "log_id": <id> }
        { "success": False, "error": <message> }
    """
    timestamp = datetime.now(timezone.utc).isoformat()

    # Build the data dict that will be hashed
    log_data = {
        "user_id":     user_id,
        "call_type":   call_type,
        "target_path": target_path,
        "status":      status,
        "reason":      reason,
        "risk_delta":  risk_delta,
        "timestamp":   timestamp,
    }

    # Get the previous log's hash for chaining
    prev_hash = _get_last_log_hash()

    # Compute this log's hash
    log_hash = _compute_hash(prev_hash, log_data)

    # Insert into database
    conn = get_connection()
    try:
        cursor = conn.execute(
            """
            INSERT INTO syscall_logs
                (user_id, call_type, target_path, status, reason, risk_delta, log_hash, prev_hash, timestamp)
            VALUES
                (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (user_id, call_type, target_path, status, reason, risk_delta, log_hash, prev_hash, timestamp)
        )
        conn.commit()
        return {"success": True, "log_id": cursor.lastrowid}
    except Exception as e:
        return {"success": False, "error": str(e)}
    finally:
        conn.close()


# ── Risk Score Update ─────────────────────────────────────────────────────────

def update_user_risk(user_id: int, delta: float):
    """
    Add delta to a user's risk_score in the users table.
    Caps at 100.0. If risk >= 50, user is auto-flagged.

    Args:
        user_id : the user whose score to update
        delta   : how much to add (e.g. +3, +5, +10)
    """
    conn = get_connection()
    try:
        row = conn.execute(
            "SELECT risk_score FROM users WHERE id = ?", (user_id,)
        ).fetchone()

        if not row:
            return

        new_score  = min(row["risk_score"] + delta, 100.0)
        is_flagged = 1 if new_score >= 50.0 else 0

        conn.execute(
            "UPDATE users SET risk_score = ?, is_flagged = ? WHERE id = ?",
            (new_score, is_flagged, user_id)
        )
        conn.commit()
    finally:
        conn.close()


# ── Log Retrieval ─────────────────────────────────────────────────────────────

def get_logs(limit: int = 100, user_id: int = None) -> list[dict]:
    """
    Fetch recent logs from the database.

    Args:
        limit   : max number of logs to return
        user_id : if given, filter logs for that user only

    Returns:
        List of log dicts ordered by newest first.
    """
    conn = get_connection()
    try:
        if user_id:
            rows = conn.execute(
                """
                SELECT l.*, u.username FROM syscall_logs l
                JOIN users u ON l.user_id = u.id
                WHERE l.user_id = ?
                ORDER BY l.id DESC LIMIT ?
                """,
                (user_id, limit)
            ).fetchall()
        else:
            rows = conn.execute(
                """
                SELECT l.*, u.username FROM syscall_logs l
                JOIN users u ON l.user_id = u.id
                ORDER BY l.id DESC LIMIT ?
                """,
                (limit,)
            ).fetchall()

        return [dict(row) for row in rows]
    finally:
        conn.close()


# ── Log Integrity Verification ────────────────────────────────────────────────

def verify_all_logs() -> dict:
    """
    Verify the entire log chain for tampering.

    Recomputes hash for every log entry and checks:
      1. Each log's hash matches recomputed value
      2. Each log's prev_hash matches the previous log's hash

    Returns:
        { "valid": True,  "checked": N }
        { "valid": False, "broken_at_log_id": X, "reason": <message> }
    """
    conn = get_connection()
    try:
        rows = conn.execute(
            "SELECT * FROM syscall_logs ORDER BY id ASC"
        ).fetchall()

        prev_hash = None

        for row in rows:
            log_data = {
                "user_id":     row["user_id"],
                "call_type":   row["call_type"],
                "target_path": row["target_path"],
                "status":      row["status"],
                "reason":      row["reason"],
                "risk_delta":  row["risk_delta"],
                "timestamp":   row["timestamp"],
            }

            expected_hash = _compute_hash(prev_hash, log_data)

            # Check stored hash matches recomputed hash
            if row["log_hash"] != expected_hash:
                return {
                    "valid":           False,
                    "broken_at_log_id": row["id"],
                    "reason":          f"Hash mismatch at log ID {row['id']}. Log may have been tampered with."
                }

            # Check prev_hash linkage
            if row["prev_hash"] != prev_hash:
                return {
                    "valid":           False,
                    "broken_at_log_id": row["id"],
                    "reason":          f"Chain broken at log ID {row['id']}. prev_hash does not match."
                }

            prev_hash = row["log_hash"]

        return {"valid": True, "checked": len(rows)}
    finally:
        conn.close()


def verify_single_log(log_id: int) -> dict:
    """
    Verify a single log entry's hash integrity.

    Returns:
        { "valid": True,  "log_id": X }
        { "valid": False, "log_id": X, "reason": <message> }
    """
    conn = get_connection()
    try:
        row = conn.execute(
            "SELECT * FROM syscall_logs WHERE id = ?", (log_id,)
        ).fetchone()

        if not row:
            return {"valid": False, "log_id": log_id, "reason": "Log not found."}

        log_data = {
            "user_id":     row["user_id"],
            "call_type":   row["call_type"],
            "target_path": row["target_path"],
            "status":      row["status"],
            "reason":      row["reason"],
            "risk_delta":  row["risk_delta"],
            "timestamp":   row["timestamp"],
        }

        expected_hash = _compute_hash(row["prev_hash"], log_data)

        if row["log_hash"] != expected_hash:
            return {
                "valid":  False,
                "log_id": log_id,
                "reason": "Hash mismatch. This log entry may have been tampered with."
            }

        return {"valid": True, "log_id": log_id}
    finally:
        conn.close()
