# SysCallGuardian 🛡️

**Cinematic Forensic System Call Gateway · Multi-Layered Security Mediation · RBAC Enforced**

SysCallGuardian is a next-generation security infrastructure that serves as a mediated gateway for system operations. It provides a hardened interface between users and the underlying operating system, enforcing strict **Role-Based Access Control (RBAC)**, real-time **Heuristic Threat Intelligence**, and a **Chain-of-Trust Forensic Audit** system.

---

## 🚀 Key Capabilities

- **SysCall Mediation Engine**: Granular control over file operations (Read, Write, Delete, Offset), directory listing, and process execution.
- **Forensic Chain-of-Audit**: Every operation is logged with a unique **SHA-256 HMAC** integrity signature, protecting the audit log from post-compromise tampering.
- **Heuristic Threat Intel**: Real-time risk scoring (0-100) and block rate analysis to identify and isolation rogue operators.
- **Cinematic Security Dashboard**: A high-fidelity, glassmorphism-inspired interface featuring forensic scatter charts and live security intelligence snapshots.
- **Rule-Set Governance**: Advanced policy engine supporting live export/import of custom security mediation rules.

## 🛠️ Project Stack

- **Backend**: Python 3.10+ · Flask · SQLite3 (Forensic Integrity Layers)
- **Frontend**: Vanilla JavaScript · HTML5 (Semantic) · CSS3 (Glassmorphism & CRT Shaders)
- **Analytics**: Chart.js (Scatter Forensics & Metric Distros)
- **Security**: SHA-256 HMAC Forensics · RBAC Middleware · System Mediation Layer

## 🏁 Getting Started

### 1. Requirements
Ensure you have Python 3.10 or higher installed on your system.

### 2. Installation
Clone the repository and install the standard library dependencies (no complex external packages required beyond Flask):
```bash
# Backend Dependencies
pip install flask requests
```

### 3. Execution
Launch the forensic gateway and access the dashboard at `http://localhost:5000`.
```bash
# In the project root
python app.py
```

### 4. Admin Credentials
Use the following credentials for initial system management:
- **Username**: `Tejax`
- **Password**: `U@itej99x`

---

## 🏛️ Forensic Architecture

SysCallGuardian operates on a "Zero-Trust Mediation" principle. No system call reaches the OS without passing through the triple-lock verification:
1. **RBAC Verification**: Checks if the user's role allows the operation.
2. **Policy Negotiation**: Evaluates the specific target (e.g., path or command) against the active security rule-set.
3. **Integrity Validation**: Cross-references the current transaction with the forensic chain-of-trust.

---
**Developed for Security Engineers & Forensic Analysts.**  
*SysCallGuardian — Secure Operations, Cinematically Audited.*
