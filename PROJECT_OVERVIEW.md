# SysCallGuardian: Deep-Dive Technical Manual

**Substantive Architecture · Cryptographic Integrity Chain · Heuristic Threat Governance**

SysCallGuardian is a high-fidelity forensic system call gateway designed to mediate, audit, and secure system-level operations. This manual provides an exhaustive breakdown of the system's logic, security protocols, and forensic infrastructure.

---

## RBAC

| Permission | Admin | Developer | Guest |
|---|---|---|---|
| file_read | ✅ | ✅ | ✅ |
| file_write | ✅ | ✅ | ❌ |
| file_delete | ✅ | ❌ | ❌ |
| dir_list | ✅ | ✅ | ✅ |
| exec_process | ✅ | ✅ | ❌ |
| system_dir_access | ✅ | ❌ | ❌ |
| manage_policies | ✅ | ❌ | ❌ |
| view_logs | ✅ | ✅ | ❌ |


## 🏛️ 1. Architectural Blueprint

SysCallGuardian operates as a mediated interceptor between the User/Application and the Operating System.
Every request passes through **six sequential security checkpoints** before any OS interaction occurs.
Every decision — whether allowed or rejected — is permanently recorded in the forensic chain.

```
╔══════════════════════════════════════════════════════════════════════════════════╗
║                         SYSCALLGUARDIAN — SYSTEM ARCHITECTURE                    ║
╚══════════════════════════════════════════════════════════════════════════════════╝

  ┌──────────────────────────────────────────────────────────┐
  │                   BROWSER / CLIENT                       │
  │                                                          │
  │   index.html + app.js + Chart.js + style.css             │
  │   ┌─────────────┐  ┌──────────────┐  ┌───────────────┐   │
  │   │ Login View  │  │  Dashboard   │  │ Policy Editor │   │
  │   │ Role Select │  │  Overview    │  │ Import/Export │   │
  │   │ OTP Flow    │  │  Live Feed   │  │ User Manager  │   │
  │   └─────────────┘  └──────────────┘  └───────────────┘   │
  │          │                 │                  │          │
  │          └─────────────────┴──────────────────┘          │
  │                            │                             │
  │              HTTP/S  +  Authorization: Bearer <token>    │
  └────────────────────────────┼─────────────────────────────┘
                               │
                               ▼
  ╔════════════════════════════════════════════════════════════╗
  ║  LAYER 1 — AUTH GATEWAY          (auth_routes.py)          ║
  ║                                                            ║
  ║   POST /api/auth/login       → bcrypt password verify      ║
  ║   POST /api/auth/register    → strength check + role guard ║
  ║   POST /api/auth/logout      → token invalidation          ║
  ║   POST /api/auth/forgot-password → OTP generation (SMTP)   ║
  ║   POST /api/auth/reset-password  → OTP verify + rehash     ║
  ║                                                            ║
  ║   • Tokens: SHA-256 UUID stored in `sessions` table        ║
  ║   • Wrong password → risk_score += RISK_INCREMENT_PER_FAIL ║
  ║   • N failed logins → is_flagged = 1 (auto-flag)           ║
  ║   • OTPs stored in `otps` table, expire in 15 minutes      ║
  ╚══════════════════════════╤═════════════════════════════════╝
                             │  token verified ✓
                             │  g.user = { user_id, username, role, risk_score }
                             ▼
  ╔════════════════════════════════════════════════════════════╗
  ║  LAYER 2 — RBAC MIDDLEWARE       (permission_middleware.py)║
  ║                                                            ║
  ║   @require_auth   → validates Bearer token against DB      ║
  ║   @require_role() → enforces minimum role level            ║
  ║                                                            ║
  ║   Role Hierarchy:                                          ║
  ║   ┌────────────┬────────────────────────────────────────┐  ║
  ║   │   guest    │ file_read, system_info                 │  ║
  ║   │ developer  │ + file_write, dir_list                 │  ║
  ║   │   admin    │ + file_delete, exec_process, all mgmt  │  ║
  ║   └────────────┴────────────────────────────────────────┘  ║
  ║                                                            ║
  ║   • No token         → 401 Unauthorized                    ║
  ║   • Insufficient role → 403 Forbidden                      ║
  ╚══════════════════════════╤═════════════════════════════════╝
                             │  role permitted ✓
                             ▼
  ╔════════════════════════════════════════════════════════════╗
  ║  LAYER 3 — POLICY ENGINE         (policy_evaluator.py)     ║
  ║                                                            ║
  ║   Evaluates dynamic JSON rule-sets loaded from DB:         ║
  ║                                                            ║
  ║   Rule Example:                                            ║
  ║     { "call_type": "file_write",                           ║
  ║       "condition": "risk_score >= 80",                     ║
  ║       "action": "block" }                                  ║
  ║                                                            ║
  ║   • Rules are hot-reloadable without server restart        ║
  ║   • GET /api/policies/export → backup rule-set to JSON     ║
  ║   • POST /api/policies/import → restore/deploy rule-set    ║
  ║   • Inactive policies (is_active=0) are skipped            ║
  ║   • Policy breach → 403 + reason logged to audit chain     ║
  ╚══════════════════════════╤═════════════════════════════════╝
                             │  policy allows ✓
                             ▼
  ╔════════════════════════════════════════════════════════════╗
  ║  LAYER 4 — SYSCALL WRAPPER       (syscall_controller.py)   ║
  ║                                 (file_operations.py)       ║
  ║                                 (process_operations.py)    ║
  ║                                 (validation.py)            ║
  ║                                                            ║
  ║  ┌─── Input Sanitization ───────────────────────────────┐  ║
  ║  │ Path Blocklist:                                      │  ║
  ║  │   /etc/passwd  /etc/shadow  /proc  /sys/kernel       │  ║
  ║  │   /dev  /boot  /root  c:/windows/system32            │  ║
  ║  │                                                      │  ║
  ║  │ Path Traversal: rejects ".." after normpath()        │  ║
  ║  │ Null Byte Guard: rejects "\x00" in any path          │  ║
  ║  │ Sandbox Lock: resolved path must start with          │  ║
  ║  │   SANDBOX_ROOT (./sandbox) — no escaping             │  ║
  ║  └──────────────────────────────────────────────────────┘  ║
  ║                                                            ║
  ║  ┌─── Command Whitelist (exec_process only) ────────────┐  ║
  ║  │ ALLOWED: ls, pwd, whoami, echo, cat, head, tail,     │  ║
  ║  │          grep, find, mkdir, touch, cp, mv, wc, sort, │  ║
  ║  │          python3, node, java, hostname, ipconfig,    │  ║
  ║  │          netstat, dir, type, ver, attrib             │  ║
  ║  │                                                      │  ║
  ║  │ BLOCKED (denylist): rm, rmdir, dd, sudo, chmod,      │  ║
  ║  │   chown, kill, wget, curl, bash, sh, passwd          │  ║
  ║  │                                                      │  ║
  ║  │ Injection Patterns (regex):                          │  ║
  ║  │   ;\s*rm\s   |  \|\s*sh  |  &&\s*curl                │  ║
  ║  │   >\s*/etc   |  `.*`     |  \$\(  |  \.\.\/          │  ║
  ║  └──────────────────────────────────────────────────────┘  ║
  ║                                                            ║
  ║  ┌─── Write Mode Control (file_write) ──────────────────┐  ║
  ║  │  truncate  → open(f, 'w')          full overwrite    │  ║
  ║  │  append    → open(f, 'a')          add to end        │  ║
  ║  │  overwrite → open(f, 'r+'), seek(0) from position 0  │  ║
  ║  │  offset    → open(f, 'r+'), seek(n) at byte n        │  ║
  ║  │  max payload: 10 MB                                  │  ║
  ║  └──────────────────────────────────────────────────────┘  ║
  ║                                                            ║
  ║  ┌─── Timeout Guard (exec_process) ─────────────────────┐  ║
  ║  │  subprocess.run(..., timeout=5, cwd=SAFE_BASE_DIR)   │  ║
  ║  │  Hangs → killed + "Command timed out" in log         │  ║
  ║  └──────────────────────────────────────────────────────┘  ║
  ╚═══════════════╤══════════════════════╤═════════════════════╝
                  │                      │
        validation passes ✓        validation fails ✗
                  │                      │
                  ▼                      ▼
  ┌───────────────────────┐   ┌──────────────────────────────┐
  │    OS / KERNEL        │   │     BLOCKED — NO OS ACCESS   │
  │                       │   │                              │
  │  file_read  → read()  │   │  reason written to audit     │
  │  file_write → write() │   │  log with risk_delta         │
  │  file_delete→ remove()│   │  user.risk_score updated     │
  │  dir_list  → listdir()│   │  403 returned to client      │
  │  exec_process→        │   └──────────────────────────────┘
  │    subprocess.run()   │
  │  system_info → static │
  └──────────┬────────────┘
             │  OS result (content / output / entries)
             │
             ▼
  ╔════════════════════════════════════════════════════════════╗
  ║  LAYER 5 — AUDIT LOGGER          (audit_logger.py)         ║
  ║                                                            ║
  ║  Every syscall decision (allowed OR blocked) is logged:    ║
  ║                                                            ║
  ║  Log Entry Fields:                                         ║
  ║  ┌──────────────┬────────────────────────────────────┐     ║
  ║  │ user_id      │ FK → users.id                      │     ║
  ║  │ call_type    │ file_read / exec_process / etc.    │     ║
  ║  │ target_path  │ sanitized path or command string   │     ║
  ║  │ status       │ "allowed" | "blocked" | "flagged"  │     ║
  ║  │ reason       │ NULL if allowed; block reason text │     ║
  ║  │ risk_delta   │ risk score increment for this event│     ║
  ║  │ timestamp    │ UTC ISO-8601                       │     ║
  ║  │ log_hash     │ SHA-256 of entry fields            │     ║
  ║  │ prev_hash    │ log_hash of previous entry (chain) │     ║
  ║  └──────────────┴────────────────────────────────────┘     ║
  ║                                                            ║
  ║  SHA-256 Chain Formula:                                    ║
  ║  ┌─────────────────────────────────────────────────────┐   ║
  ║  │  hash_n = SHA256(JSON({                             │   ║
  ║  │    user_id, call_type, target_path,                 │   ║
  ║  │    status, reason, risk_delta,                      │   ║
  ║  │    timestamp, prev_hash=hash_(n-1)                  │   ║
  ║  │  }, sort_keys=True))                                │   ║
  ║  │                                                     │   ║
  ║  │  First entry: prev_hash = "GENESIS"                 │   ║
  ║  └─────────────────────────────────────────────────────┘   ║
  ║                                                            ║
  ║  Any post-write modification to a log row                  ║
  ║  breaks the chain — detectable via:                        ║
  ║    GET /api/logs/verify      (full chain scan)             ║
  ║    GET /api/logs/verify/:id  (single entry check)          ║
  ╚══════════════════════════╤═════════════════════════════════╝
                             │  log committed
                             ▼
  ╔════════════════════════════════════════════════════════════╗
  ║  LAYER 6 — THREAT ENGINE         (threat_detection.py)     ║
  ║                                  (risk_scoring.py)         ║
  ║                                                            ║
  ║  Runs analyze_event() after EVERY syscall (allowed+blocked)║
  ║                                                            ║
  ║  In-Memory Sliding Window (5 min, resets on restart):      ║
  ║  ┌──────┬────────────────────┬───────────┬─────────────┐   ║
  ║  │ Rule │ Name               │ Threshold │ Severity    │   ║
  ║  ├──────┼────────────────────┼───────────┼─────────────┤   ║
  ║  │  R2  │ Syscall Flood      │ ≥5 same   │ High        │   ║
  ║  │      │                    │ type/60s  │             │   ║
  ║  │  R3  │ Exec Violation     │ ≥1 blocked│ Critical    │   ║
  ║  │      │                    │ exec/5min │             │   ║
  ║  │  R4  │ System Path Probe  │ any access│ High        │   ║
  ║  │      │                    │ to /sys   │             │   ║
  ║  │      │                    │ /proc etc.│             │   ║
  ║  │  R5  │ Risk Threshold     │ score ≥70 │ Critical    │   ║
  ║  └──────┴────────────────────┴───────────┴─────────────┘   ║
  ║                                                            ║
  ║  Risk Score Accumulation:                                  ║
  ║    risk_score += risk_delta per blocked call               ║
  ║    risk_score capped at 100.0 (MAX_RISK_SCORE)             ║
  ║                                                            ║
  ║  Risk Levels:                                              ║
  ║    0–19   → low       (normal usage)                       ║
  ║    20–39  → medium    (watch list)                         ║
  ║    40–69  → high      (dashboard flagged)                  ║
  ║    70–100 → critical  (forensic isolation recommended)     ║
  ║                                                            ║
  ║  On rule fire:                                             ║
  ║    UPDATE users SET is_flagged = 1 WHERE id = ?            ║
  ║    event appended to _threat_log (in-memory)               ║
  ╚══════════════════════════╤═════════════════════════════════╝
                             │  threat state updated
                             ▼
  ╔════════════════════════════════════════════════════════════╗
  ║  DASHBOARD UI                    (app.js + Chart.js)       ║
  ║                                                            ║
  ║  Reads from these API endpoints:                           ║
  ║                                                            ║
  ║  ┌──────────────────────────────────────────────────────┐  ║
  ║  │  /api/dashboard/stats     → KPI cards (total,        │  ║
  ║  │                             allowed, blocked)        │  ║
  ║  │  /api/dashboard/activity  → 24h hourly timeline      │  ║
  ║  │  /api/dashboard/extended  → heatmap, role dist,      │  ║
  ║  │                             risk scores, scatter     │  ║
  ║  │  /api/logs                → forensic audit table     │  ║
  ║  │  /api/threats             → flagged users + scores   │  ║
  ║  │  /api/threats/events      → live threat event feed   │  ║
  ║  │  /api/policies            → policy rule-set editor   │  ║
  ║  │  /api/users               → user cards + mgmt        │  ║
  ║  └──────────────────────────────────────────────────────┘  ║
  ║                                                            ║
  ║  Visualizations:                                           ║
  ║    • Forensic Scatter Stream   (chronological events)      ║
  ║    • User × Syscall Heatmap    (call volume matrix)        ║
  ║    • 24h Activity Timeline     (allowed vs blocked)        ║
  ║    • Risk Score Leaderboard    (user risk ranking)         ║
  ║    • Role Distribution Chart   (call share by role)        ║
  ║    • Security Intel Snapshot   (live threat counters)      ║
  ╚════════════════════════════════════════════════════════════╝

  ┌─────────────────────────────────────────────────────────────┐
  │                  DATA FLOW SUMMARY                          │
  │                                                             │
  │  REQUEST PATH (happy path):                                 │
  │  Client → Auth → RBAC → Policy → Wrapper → OS               │
  │                                         ↓                   │
  │                                    Audit Logger             │
  │                                         ↓                   │
  │                                    Threat Engine            │
  │                                         ↓                   │
  │                                    Dashboard APIs           │
  │                                                             │
  │  BLOCK PATH (any layer can reject):                         │
  │  Client → [Layer N rejects] → Audit Logger → Threat Engine  │
  │                            ↓                                │
  │                       403 + reason returned to client       │
  └─────────────────────────────────────────────────────────────┘
```

---

## 🛡️ 2. Security Mediation Layer

The Mediation Layer (`validation.py`) enforces strict isolation through three primary protection mechanisms:

### A. Path Sanitization & Blocklist

System-critical paths are strictly unreachable regardless of user role:

- **Restricted Directories**: `/etc/passwd`, `/etc/shadow`, `/proc`, `/sys/kernel`, `/dev`, `/boot`, `/root`.
- **Normalization**: Every path is normalized (`os.path.normpath`) to prevent bypasses via `./` or `//`.

### B. Command Whitelist (exec_process)

Only a curated list of non-destructive diagnostic tools is permitted:

- **Utilities**: `ls`, `pwd`, `whoami`, `echo`, `cat`, `head`, `tail`, `grep`, `find`, `wc`, `sort`, `uniq`.
- **Sandbox**: `python3`, `node`, `java`.
- **Diagnostic**: `hostname`, `ipconfig`, `netstat`.

### C. Injection Protection (Regex)

All command strings and paths are scanned for high-risk shell patterns:

- `; \s*rm \s` (Chained deletions)
- `\|\s*sh` (Piping to shell)
- `>\s*/etc` (Unauthorized redirects)
- `\.\.\/` (Advanced path traversal)
- `$( ... )` and `` `...` `` (Command substitution)

---

## 🔍 3. Forensic Chain-of-Trust (HMAC)

To protect the audit log from post-compromise tampering, SysCallGuardian implements a cryptographic **Chain-of-Trust**.

### The Hashing Flow

Each log entry is hashed using SHA-256 by combining its own metadata with the hash of the _previous_ entry (`prev_hash`).

```python
# audit_logger.py Logic Pattern
def _hash_entry(data, prev_hash):
    payload = json.dumps({
        **data,
        "prev_hash": prev_hash
    }, sort_keys=True)
    return hashlib.sha256(payload.encode()).hexdigest()
```

### Forensic Integrity Verification

Administrators can run a **Full Chain Audit**. The verification engine reconstructs every hash in the chain. If any bit of a 1,000-entry log was modified, the chain breaks at that ID, flagging the entry as **TAMPERED**.

---

## 🧠 4. Heuristic Threat Intelligence

The Threat Intel Engine monitors real-time forensic streams to assign dynamic **Risk Scores (0-100)** to users.

| Rule ID | Name           | Trigger Condition                           | Severity     |
| :------ | :------------- | :------------------------------------------ | :----------- |
| **R2**  | Syscall Flood  | 5+ calls of same type in 60s                | **High**     |
| **R3**  | Exec Violation | 1+ blocked `exec_process` attempts          | **Critical** |
| **R4**  | Path Probe     | Access attempts to `/sys`, `/proc`, `/root` | **High**     |
| **R5**  | Threshold      | Cumulative risk score ≥ 70                  | **Critical** |

### Risk Categorization

- **0-20 (Low)**: Normal operational usage.
- **20-40 (Medium)**: Occasional errors or unusual path queries.
- **40-70 (High)**: Repeated violations; automatic dashboard flagging.
- **70-100 (Critical)**: Active threat suspected; forensic isolation recommended.

---

## 💾 5. Data Infrastructure (SQL Schema)

### Table: `users`

| Column       | Type          | Description                         |
| :----------- | :------------ | :---------------------------------- |
| `id`         | INTEGER (PK)  | Unique User Identifier              |
| `username`   | TEXT (Unique) | Identity Handle                     |
| `role`       | TEXT          | RBAC Role (guest, developer, admin) |
| `risk_score` | REAL          | Heuristic risk (0-100)              |
| `is_flagged` | INTEGER (0/1) | Alert status for SOC                |

### Table: `syscall_logs`

| Column        | Type         | Description                      |
| :------------ | :----------- | :------------------------------- |
| `id`          | INTEGER (PK) | Log Sequence ID                  |
| `user_id`     | INTEGER (FK) | Reference to `users.id`          |
| `call_type`   | TEXT         | e.g. `file_read`, `exec_process` |
| `target_path` | TEXT         | Sanitized path or command        |
| `status`      | TEXT         | `allowed`, `blocked`, `flagged`  |
| `log_hash`    | TEXT         | Cryptographic entry signature    |
| `prev_hash`   | TEXT         | Chain link to previous entry     |

---

## 🛰️ 6. API Manifest v1.0

### Authentication & Management

- `POST /api/auth/login`: Issue session tokens.
- `PUT /api/users/:id/role`: (Admin) Update RBAC status.
- `DELETE /api/users/:id`: (Admin) Forensic account removal (cascades to logs).

### Forensic Operations

- `GET /api/logs`: Query the forensic stream (sanitized for non-Admins).
- `GET /api/logs/verify`: (Admin) Full cryptographic chain audit.
- `GET /api/threats/events`: Live feed of heuristic detection events.

### Syscall Gateway

- `POST /api/syscall/read`: Mediated file retrieval.
- `POST /api/syscall/write`: Multi-mode write (Append/Truncate/Offset).
- `POST /api/syscall/execute`: Restricted subprocess execution.

---

**SysCallGuardian — System Call Security, Reimagined.** 
_Watch every bit. Control every byte. Rule every call._
