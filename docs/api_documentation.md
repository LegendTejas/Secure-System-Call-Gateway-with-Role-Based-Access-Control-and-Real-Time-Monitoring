# 📡 SysCallGuardian: API Technical Reference v4.0

**Secure System Call Mediation · Multi-Role Audit Infrastructure · Integrity Monitoring**

SysCallGuardian provides a robust, RESTful API surface for mediating system-level operations, enforcing granular security policies, and maintaining a cryptographically linked audit trail.

---

## 🏛️ General Information

### Base URL
```text
http://127.0.0.1:5000
```

### Security Tokens
All protected routes require a JWT-equivalent session token issued upon login.
- **Header**: `Authorization: Bearer <session_token>`

### Response Standards
The API communicates exclusively in **JSON**. Standardized response codes:
- `200 OK`: Request successful.
- `201 Created`: Resource (User/Policy) successfully generated.
- `400 Bad Request`: Validation failure or missing parameters.
- `401 Unauthorized`: Invalid, expired, or missing session token.
- `403 Forbidden`: Role-Based Access Control (RBAC) or Policy violation.
- `404 Not Found`: Resource (User/Policy/Log) does not exist.
- `409 Conflict`: Resource (Username/Policy Name) already exists.

---

## 🔐 1. Identity & Access Management (IAM)

### **Authenticate Session**
Exchange credentials for a secure session token.
- **Endpoint**: `POST /api/auth/login`
- **Auth**: Public
- **Request Body**: `{ "username": "...", "password": "..." }`
- **Response `200`**:
  ```json
  {
    "message": "Login successful",
    "token": "sess_82f1...",
    "role": "admin",
    "username": "Tejax"
  }
  ```

---

### **Managed Registration**
Register a new user account with strict hierarchy enforcement.
- **Endpoint**: `POST /api/auth/register`
- **Auth**: `developer`+
- **Rule**: **Admins** can register any role; **Developers** can ONLY register `guest` accounts.
- **Request Body**: `{ "username": "...", "email": "...", "password": "...", "role": "..." }`

---

### **Revise Password (OTP Flow)**
Initiate a secure password recovery sequence.
- **Endpoint**: `POST /api/auth/forgot-password`
- **Auth**: Public
- **Scenarios**:
  - **Admins**: Triggers urgent security alert to system owners.
  - **Developers**: Generates a single-use secure link for identity verification.
  - **Guests**: Issues a 6-digit verification code (OTP) via email.
- **Request Body**: `{ "identity": "..." }`

---

### **Reset Password**
Commit a new password using a valid verification OTP.
- **Endpoint**: `POST /api/auth/reset-password`
- **Auth**: Public
- **Request Body**: `{ "identity": "...", "otp": "...", "new_password": "..." }`

---

### **Identify Role**
Retrieve the role associated with an identity without exposing sensitive data.
- **Endpoint**: `POST /api/auth/recover-info`
- **Auth**: Public
- **Request Body**: `{ "identity": "..." }`
- **Response**: `{ "role": "guest/developer/admin" }`

---

### **Active Session Termination**
Invalidate the current session token.
- **Endpoint**: `POST /api/auth/logout`
- **Auth**: Required

---

## 👤 2. User & Administrative Control

### **Personal Profile Telemetry**
Retrieve the current user's security standing and risk metrics.
- **Endpoint**: `GET /api/user/me`
- **Auth**: `guest`+
- **Response**: Returns `username`, `role`, `risk_score`, and `is_flagged` status.

---

### **Global User Audit**
List all registered users with real-time system call statistics.
- **Endpoint**: `GET /api/users`
- **Auth**: `developer`+
- **Metrics returned**: `total_calls`, `blocked_calls`, `risk_score`, `is_flagged`.

---

### **Managed Account Remediation**
| Endpoint | Method | Role | Logic |
| :--- | :--- | :--- | :--- |
| `/api/users/:id/role` | `PUT` | `dev`+ | Developers can only demote/promote to `guest`. |
| `/api/users/:id/revoke`| `POST` | `dev`+ | Forcefully kills all active sessions for the user. |
| `/api/users/:id/unflag`| `POST` | `dev`+ | Resets risk score and clears suspicious flags. |
| `/api/users/:id` | `DELETE` | `admin` | Hard deletion of account and all associated logs. |

---

### **Permission Matrix Discovery**
Describe the system call capabilities for every role in the system.
- **Endpoint**: `GET /api/user/roles`
- **Auth**: `developer`+
- **Response**: Key/Value list of roles and their permitted system calls.

---

## 🛡️ 3. Security Policy Governance

### **Active Rule Management**
- **Endpoint**: `GET /api/policies`
- **Auth**: `developer`+
- **Logic**: Admins see full JSON rules; Developers see a sanitized list of rules.
- **GET `/api/policies/preview`**: Provides a lightweight, read-only view of active policies for developers.

---

### **Policy Lifecycle Operations**
- **POST `/api/policies`**: Add a new mediation rule (`admin` only).
- **PUT `/api/policies/:id`**: Update rule logic or toggle `is_active` (`admin` only).
- **DELETE `/api/policies/:id`**: Permanently remove a mediation rule (`admin` only).

---

### **Bulk Synchronization**
- **Export Rule-set**: `GET /api/policies/export` — Backup all policies as a JSON list (`admin` only).
- **Import Rule-set**: `POST /api/policies/import` — Restore policies from a JSON list (`admin` only).

---

## ⚙️ 4. Mediated System Call Gateway

> 🔒 **Pre-execution Logic**: Every syscall endpoint enforces path sanitization, command whitelisting, and role-based policy evaluation before interacting with the host OS.

### **File Operations**
Execute filtered file-level requests.
- **Endpoints**: `POST /api/syscall/read`, `POST /api/syscall/write`, `POST /api/syscall/delete`.
- **Directory List**: `POST /api/syscall/dir_list`
- **Payload**: `{ "file_path": "scripts/audit.log" }`
- **Response**: `200` (success) OR `403` (Blocked by policy).

---

### **Resource Explorer**
Enumerate the current sandbox root directory.
- **Endpoint**: `GET /api/syscall/explorer`
- **Auth**: `guest`+
- **Logic**: Defaults to the secure project root directory for safe exploration.

---

### **Restricted Process Execution**
Spawn whitelisted diagnostic processes on the host.
- **Endpoint**: `POST /api/syscall/execute`
- **Auth**: `guest`+
- **Body**: `{ "command": "...", "args": [...] }`
- **Whitelist includes**: `ls`, `pwd`, `whoami`, `echo`, `cat`, `python3`, `node`, `grep`, `find`, `mkdir`, `touch`, `cp`, `mv`, `wc`, `sort`, `uniq`.

---

### **System Diagnostic Metadata**
Retrieve host-level information (OS version, CPU architecture, memory availability).
- **Endpoint**: `GET /api/syscall/system_info`
- **Auth**: `guest`+

---

## 📜 5. Audit logs & Security Monitoring

### **Centralized Audit Query**
Access the global system activity log.
- **Endpoint**: `GET /api/logs`
- **Auth**: `guest`+
- **Data Isolation**: 
  - **Guests**: See only their own logs.
  - **Developers**: See all logs with sensitive paths (e.g., `/etc/shadow`) masked.
  - **Admins**: Full global visibility.
- **Parameters**: `user`, `status` (allowed/blocked/flagged), `call_type`, `from`, `to`, `page`, `per_page`.

---

### **Audit Trail Integrity**
Verify the cryptographic SHA-256 hash chains.
- **Verify All**: `GET /api/logs/verify` (`admin` only)
- **Verify Item**: `GET /api/logs/verify/:id` (`admin` only)
- **Logic**: Re-computes hashes from row data and checks against the `prev_hash` chain link.

---

### **Threat Landscape**
- **Aggregated Threats**: `GET /api/threats` — List users with critical risk standings (`admin` only).
- **Detection Stream**: `GET /api/threats/events` — Chronological feed of every security violation event (`admin` only).

---

## 📊 6. Dashboard Telemetry Analytics

### **Operational Stats**
Return high-level volume metrics for the dashboard summary cards.
- **Endpoint**: `GET /api/dashboard/stats`
- **Auth**: `guest`+ (Scope filtered)
- **Includes**: Total calls, Success/Block ratio, High-risk user count.

---

### **Activity Timelines**
Retrieve syscall volume data binned by hour (last 24 hours).
- **Endpoint**: `GET /api/dashboard/activity`
- **Auth**: `guest`+

---

### **Extended Analytics Package**
Advanced telemetry for complex visualizations.
- **Endpoint**: `GET /api/dashboard/extended`
- **Components**:
  - **Heatmap**: syscall density across user/operation dimensions.
  - **Risk Ranking**: Comparative list of user risk scores.
  - **Role Distribution**: Syscall volume share by role.
  - **Recent Activity**: The last 100 system events (RBAC sanitized).

---
**SysCallGuardian — Stability through Observation.**
*Engine v4.0.0 Stable Build.*
