# SysCallGuardian — API Documentation

A security layer that sits between users and the operating system. Every system call — read file, write file, execute process — passes through authentication, role-based access control, and dynamic policy evaluation before being executed. Every action is logged with SHA-256 hash chaining for tamper detection. 

This doc contains detailed walkthrough of 26+ API endpoints and all the functionalities of the Project

---

## API Overview

| Method | Endpoint | Description |
|---|---|---|
| POST | /api/auth/login | Login + get JWT |
| POST | /api/auth/logout | Invalidate session |
| GET | /api/user/me | Current user info |
| GET | /api/users | All users with stats (admin) |
| PUT | /api/users/:id/role | Change user role (admin) |
| POST | /api/users/:id/revoke | Revoke session (admin) |
| POST | /api/users/:id/unflag | Clear flag + risk (admin) |
| GET | /api/policies | All policies |
| POST | /api/policies | Create policy (admin) |
| PUT | /api/policies/:id | Update/disable policy (admin) |
| POST | /api/syscall/read | Read file |
| POST | /api/syscall/write | Write file |
| POST | /api/syscall/delete | Delete file |
| POST | /api/syscall/execute | Execute process |
| GET | /api/logs | Paginated audit logs |
| GET | /api/logs/verify | Full chain verification |
| GET | /api/logs/verify/:id | Single entry verification |
| GET | /api/threats | Flagged users (aggregated) |
| GET | /api/threats/events | Detailed threat event log (admin) |
| GET | /api/dashboard/stats | Syscall statistics |
| GET | /api/dashboard/activity | Hourly timeline |
| GET | /api/policies/export | Download full rule-set (admin) |
| POST | /api/policies/import | Bulk rule-set update (admin) |
| POST | /api/syscall/system_info| Fetch system metadata |

Full documentation: `docs/api_documentation.md`

---

## OS Concepts Demonstrated

This project demonstrates the following OS concepts:

- **System Call Interface** — mediation layer between user space and kernel
- **Access Control** — RBAC implemented as a middleware security layer
- **Process Management** — safe subprocess execution with timeout and resource limits
- **File System Security** — path sanitization, sandbox isolation
- **Audit Logging** — tamper-evident log chain using cryptographic hashing
- **Scheduling & Performance** — overhead measurement of mediation vs direct calls
- **Inter-Process Communication** — REST API as the IPC mechanism between frontend and backend

---

*SysCallGuardian · Akhil · Tejas · Vanshika*
