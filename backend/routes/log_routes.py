
"""
routes/log_routes.py
Vanshika — Flask routes for logs, integrity verification, and threat data.
"""

from flask import Blueprint, request, jsonify

from auth_rbac.permission_middleware import require_auth, require_role
from logging_detection.audit_logger  import get_logs
from logging_detection.log_integrity import verify_all_logs, verify_single_log
from logging_detection.threat_detection import get_suspicious_users

log_bp = Blueprint("logs", __name__)


@log_bp.route("/api/logs", methods=["GET"])
@require_auth
@require_role("developer")
def api_get_logs():
    """
    GET /api/logs
    Query params: user, status, call_type, date, from, to, page
    """
    result = get_logs(
        user      = request.args.get("user"),
        status    = request.args.get("status"),
        call_type = request.args.get("call_type"),
        date      = request.args.get("date"),
        from_dt   = request.args.get("from"),
        to_dt     = request.args.get("to"),
        page      = int(request.args.get("page", 1)),
        per_page  = int(request.args.get("per_page", 20)),
    )
    return jsonify(result), 200


@log_bp.route("/api/logs/verify", methods=["GET"])
@require_auth
@require_role("admin")
def api_verify_all_logs():
    """GET /api/logs/verify — full chain verification (admin only)"""
    result = verify_all_logs()
    return jsonify({
        "status":  "valid" if result["valid"] else "tampered",
        "message": result["message"],
        "tampered_ids": result.get("tampered_ids", []),
    }), 200


@log_bp.route("/api/logs/verify/<int:log_id>", methods=["GET"])
@require_auth
@require_role("admin")
def api_verify_single_log(log_id: int):
    """GET /api/logs/verify/<id> — single log hash verification"""
    result = verify_single_log(log_id)
    return jsonify(result), 200


@log_bp.route("/api/threats", methods=["GET"])
@require_auth
@require_role("admin")
def api_get_threats():
    """GET /api/threats — flagged users with risk scores"""
    users = get_suspicious_users()
    return jsonify(users), 200


@log_bp.route("/api/dashboard/stats", methods=["GET"])
@require_auth
@require_role("developer")
def api_dashboard_stats():
    """GET /api/dashboard/stats"""
    from database.db import get_connection
    conn = get_connection()
    try:
        total   = conn.execute("SELECT COUNT(*) FROM syscall_logs").fetchone()[0]
        allowed = conn.execute("SELECT COUNT(*) FROM syscall_logs WHERE status='allowed'").fetchone()[0]
        blocked = conn.execute("SELECT COUNT(*) FROM syscall_logs WHERE status='blocked'").fetchone()[0]
        flagged = conn.execute("SELECT COUNT(*) FROM syscall_logs WHERE status='flagged'").fetchone()[0]
        sus_users = conn.execute("SELECT COUNT(*) FROM users WHERE is_flagged=1").fetchone()[0]
        top_users = conn.execute(
            """SELECT u.username, COUNT(*) as call_count
               FROM syscall_logs l JOIN users u ON l.user_id=u.id
               GROUP BY u.username ORDER BY call_count DESC LIMIT 5"""
        ).fetchall()
        return jsonify({
            "total_calls":     total,
            "allowed":         allowed,
            "blocked":         blocked,
            "flagged":         flagged,
            "suspicious_users": sus_users,
            "top_users":       [{"username": r["username"], "call_count": r["call_count"]} for r in top_users],
        }), 200
    finally:
        conn.close()


@log_bp.route("/api/dashboard/activity", methods=["GET"])
@require_auth
@require_role("developer")
def api_dashboard_activity():
    """GET /api/dashboard/activity — hourly timeline"""
    from database.db import get_connection
    conn = get_connection()
    try:
        rows = conn.execute(
            """SELECT strftime('%H:00', timestamp) as hour,
                      SUM(CASE WHEN status='allowed' THEN 1 ELSE 0 END) as allowed,
                      SUM(CASE WHEN status='blocked' THEN 1 ELSE 0 END) as blocked,
                      COUNT(*) as calls
               FROM syscall_logs
               WHERE timestamp >= datetime('now', '-12 hours')
               GROUP BY hour ORDER BY hour ASC"""
        ).fetchall()
        return jsonify([dict(r) for r in rows]), 200
    finally:
        conn.close()
