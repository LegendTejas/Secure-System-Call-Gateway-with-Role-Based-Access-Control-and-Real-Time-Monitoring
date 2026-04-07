# 🎨 SysCallGuardian — Frontend & Dashboard

**Modern, Zero-Dependency Administrative Gateway**

The SysCallGuardian frontend is a high-performance, CRT-styled single-page application (SPA) designed for real-time system monitoring, security policy governance, and detailed audit log exploration. It provides a professional, role-based dashboard for administrators, developers, and guests to interact with the security gateway.

---

## ✨ Key Features

- **Real-Time Telemetry**: Live stream of system call activity with pause/resume control.
- **Audit Log Explorer**: Fast, multi-filtered query engine for investigating system-level operations.
- **Policy Control Plane**: Interactive toggles for enabling/disabling security mediation rules.
- **Dynamic Risk Engine**: Heuristic scoring of suspicious users and automated threat highlighting.
- **Integrated Chart Analytics**: Time-series activity visualization and role-based syscall distribution charts.

---

## 🧰 Tech Stack

- **Core**: Vanilla HTML5, CSS3, and JavaScript (ES6+).
- **Visualization**: Chart.js for high-fidelity interactive telemetry.
- **Architecture**: Single-file SPA (no frameworks, no build tools, zero-dependency).

---

## 🚀 Quick Start

To view the dashboard and interact with the gateway:

```bash
cd backend

# Start the Flask security gateway
python app.py
```

*Access the gateway at: `http://localhost:5000`*

---

*Frontend built for SysCallGuardian Engine v4.0.0 Stable.*
