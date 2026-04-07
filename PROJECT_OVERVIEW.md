# PROJECT_OVERVIEW.md: SysCallGuardian Forensic Gateway

**Technical Depth · Multi-Layered Security Architecture · Forensic Governance**

SysCallGuardian is a sophisticated, mediated system call gateway designed for high-security environments. It acts as an isolation layer between administrative/operation users and critical host operations, ensuring every syscall is validated against granular role-based policies and forensic integrity chains.

---

## 🏛️ System Architecture

The SysCallGuardian architecture is built on a **Triple-Layer Lockdown** model:

1. **Authentication & RBAC Layer**: Enforces identity-based access control. No operation is permitted without a valid session token (SHA-256 backed).
2. **Mediation Layer (Policy Engine)**: Every syscall (`file_read`, `file_write`, `file_delete`, `dir_list`, `exec_process`, `system_info`) is intercepted and evaluated against the **Security Policy JSON**.
3. **Forensic Audit Layer**: Every transaction—both allowed and blocked—is committed to a forensic log protected by a **Chain-of-Trust HMAC signature**.

---

## 🛡️ Security Protocols & RBAC

### Role-Based Access Control (RBAC)
SysCallGuardian enforces three distinct security personas:
- **Administrator**: Full system lifecycle management (User Admin, Policy Import/Export, Forensic Verification).
- **Developer**: Mediated system access (File read/write/list) with path sanitization and forensic logging.
- **Guest**: Restricted, read-only observer status with access to personal logs only.

### Custom Security Policies
Mediation is governed by a persistent rule-set (`policies.json`) that defines:
- **Call Targets**: Specific file paths or restricted system commands.
- **Role Permissions**: Which roles are permitted to target which resources.
- **Exception Rules**: Granular overrides for critical security scenarios.

---

## 🔍 Forensic Integrity & HMAC

To prevent attackers from erasing their traces after a compromise, SysCallGuardian implements a **Chain-of-Trust Forensic Audit**:
1. **Transaction Hashing**: Each log entry is hashed with its predecessor's signature using a secret HMAC key.
2. **Integrity Verification**: Admins can run a **Full Chain Audit** to detect any manual log tampering or missing entries.
3. **Immutability Principle**: The forensic log is treated as an append-only source of truth, isolation from standard user modify operations.

---

## 🧠 Heuristic Threat Intelligence

SysCallGuardian's **Threat Intel Engine** provides real-time security observability:
- **Heuristic Risk Scoring**: Users are assigned a dynamic risk score (0-100) based on their interaction patterns and block rates.
- **Threshold Alerts**: If a user's risk exceeds a critical threshold (e.g., 80+), their account is flagged for forensic review.
- **Threat Event Distribution**: Real-time categorization of security events into `Audit`, `Warning`, and `Critical` indicators.

---

## 📊 Analytics & Forensic Visualization

The **Security Operations Center (SOC)** dashboard features:
- **Forensic Scatter Stream**: A chronological visualization of system calls, mapped by decision (Allowed vs. Blocked).
- **Metric Micro-Distributions**: Real-time charts showing system call volume, role distribution, and block rates.
- **Live Intelligence Snapshot**: Categorized counters for active threats, flagged users, and forensic node status.

---

## 🛰️ API Reference (High-Level)

### 1. Authentication
- `POST /api/auth/login`: Identity verification and session issuance.
- `POST /api/auth/register`: (Admin Only) Forensic user provisioning.

### 2. Syscall Mediation
- `POST /api/syscall/read`: Mediated file read with path validation.
- `POST /api/syscall/write`: Multi-mode file write (Append, Overwrite, Offset).
- `POST /api/syscall/execute`: Restricted process execution via allowlist.

### 3. Forensic & Threat Data
- `GET /api/logs`: Query-driven forensic audit stream.
- `GET /api/logs/verify`: (Admin Only) Full cryptographic chain-of-trust audit.
- `GET /api/threats/events`: Chronological list of heuristic threat indicators.

---
**SysCallGuardian — Forensic Stability, Cinematic Security.**
JSON Security Policy Engine · HMAC-Protected Logs · Heuristic Intel Snapshot
