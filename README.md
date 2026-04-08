# SysCallGuardian

![Version](https://img.shields.io/badge/version-4.0.0--stable-blue.svg)
![Python](https://img.shields.io/badge/python-3.8%2B-blue.svg)
![Security](https://img.shields.io/badge/security-SHA--256-success.svg)

**SysCallGuardian** is a high-fidelity, high-performance system call gateway engineered to mediate, audit, and secure operating system-level operations in real-time. Designed as a protective layer between user actions and the underlying host system, it provides centralized enforcement of granular security policies, advanced forensic auditing, and heuristic threat detection across a multi-user environment.

---

## 🔥 Core Capabilities

- **Strict Access Mediation**: Intercepts, sanitizes, and evaluates all file and process operations against a robust whitelist and regex-based threat signatures.
- **Cryptographic Log Integrity**: Every user operation is logged and cryptographically signed using SHA-256 HMAC cascading chains, ensuring forensic audibility and tamper evidence.
- **Heuristic Threat Engine**: Implements dynamic risk-scoring assigned per user, triggering real-time alerts and blocking automated attacks or lateral movement attempts.
- **Role-Based Access Control (RBAC)**: Centralized authorization model with strict boundary management, separating Administrative oversight, Developer access, and Guest isolation.
- **Cinematic Forensic Interface**: A dynamic, fully responsive, and visually immersive frontend dashboard for security operations center (SOC) monitoring.

---

## 🏗️ Technical Stack

- **Backend core**: Python, Flask, SQLite3, Cryptography (HMAC/SHA-256).
- **Frontend interface**: Vanilla HTML5, CSS3 (Glassmorphism + CRT Aesthetics), JavaScript (ES6+), Chart.js.
- **Security Protocols**: JWT-equivalent sessioning, Bcrypt hashing, strict API rate-limiting.

---

## 🚀 Quick Start Guide

### 1. Prerequisites

- **Python 3.8+** installed on your host system.
- Standard Unix/Linux or Windows environment.

### 2. Installation Setup

```bash
# Clone the repository
git clone https://github.com/your-org/secure-syscall-gateway.git
cd secure-syscall-gateway

# Initialize and activate the virtual environment
python -m venv venv
source venv/Scripts/activate  # Or `source venv/bin/activate` on Unix systems

# Install required dependencies
pip install -r requirements.txt
```

### 3. Database Initialization

```bash
# Seed the initial users, roles, and populate the database with mock logs
python reseed_users.py
```

### 4. Running the Gateway

```bash
# Navigate to the backend service location
cd backend

# Launch the secure gateway
python app.py
```

The unified dashboard and gateway will be accessible at: `http://127.0.0.1:5000`.

---

## 🗂️ Folder Structure

```text
secure-syscall-gateway/
├── backend/                # Flask Core & Security Engines
│   ├── auth_rbac/          # Identity & Access Management
│   ├── database/           # SQLite Schemas & Operations
│   ├── logging_detection/  # HMAC Forensic Chain & Heuristics
│   ├── routes/             # REST API Endpoints
│   └── syscall_layer/      # OS Execution & Validation Layer
├── frontend/               # SPA Dashboard & Terminal Interface
│   ├── css/                # Glassmorphism & UI Themes
│   ├── js/                 # Client-side API Controllers
│   └── src/                # Core frontend source files
├── tests/                  # Pytest Validation Suites
├── PROJECT_OVERVIEW.md     # In-Depth Technical Manual
└── README.md               # Project Quick Start Guide
```

---

## 🔐 Default Environment Roles

SysCallGuardian ships with core pre-configured accounts designed for testing the RBAC boundaries:

| Role Level              | Username    | Password      | Operational Purpose                                             |
| :---------------------- | :---------- | :------------ | :-------------------------------------------------------------- |
| **Administrator** | `Tejax`   | `U@itej99x` | Security oversight, full policy control, full audit capability. |
| **Administrator** | `Akael`   | `Akhil9890` | System administration, forensic review, security enforcement.   |
| **Developer**     | `Vancika` | `Van112358` | Environment debugging, restricted execution access.             |
| **Guest Tier A**  | `GuestA`  | `Guest@123` | Read-only constrained access. High-risk actions denied.         |
| **Guest Tier B**  | `GuestB`  | `Guest@456` | Read-only constrained access. High-risk actions denied.         |

> **Note**: For production environments, it is strictly required to change these default passwords and remove unneeded guest accounts.

### Allowed Syscalls Mapping

| Role | File Read / List | File Write | File Delete | Process Execution | System Actions |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **Administrator** | ✅ | ✅ | ✅ | ✅ (Whitelisted) | ✅ |
| **Developer** | ✅ | ✅ | ❌ | ✅ (Limited) | ❌ |
| **Guest** | ✅ (Safe Paths) | ❌ | ❌ | ❌ | ❌ |

---

## 📚 Comprehensive Documentation

For engineers, SOC analysts, and forensic auditors, detailed system documentation is available in the **[PROJECT_OVERVIEW.md](PROJECT_OVERVIEW.md)** manual. It covers:

- Exhaustive folder structures and internal mechanisms.
- Cryptographic hash chaining strategies.
- API route guidelines and permission matrices.
- The underlying heuristics engine design.

---

*SysCallGuardian is developed to bring enterprise-grade forensic stability to complex system call architectures.*
