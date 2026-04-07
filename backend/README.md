# ⚙️ SysCallGuardian — Secure Backend

**High-Performance System Call Mediation & Security Audit Server**

The SysCallGuardian backend is a modular, Flask-based security gateway designed to intercept, validate, and audit system-level operations in real-time. It enforces strict Role-Based Access Control (RBAC) and maintains a secure, cryptographically linked audit trail.

---

## 🏛️ Core Architecture

The system is organized into four main security pillars:

- **Identity & IAM (`auth_rbac/`)**: Comprehensive session management and multi-tier role enforcement.
- **Syscall Mediation (`syscall_layer/`)**: Low-level validation for file IO, process execution, and directory traversal.
- **Security Policy Engine (`policy_engine/`)**: Dynamic, JSON-based rule evaluators that can be updated without server restart.
- **Audit & Monitoring (`logging_detection/`)**: Real-time logging with SHA-256 HMAC integrity monitoring and heuristic risk scoring.

---

## 🚀 Quick Start

To run the backend independently:

```bash
# Install dependencies
pip install -r requirements.txt

# Start the Flask security gateway
python app.py
```

*Default environment: `http://127.0.0.1:5000`*

---
*For full API documentation, refer to the [Root API Docs](../docs/api_documentation.md).*
