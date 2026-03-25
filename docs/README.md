# 📡 API Documentation
**Project:** Secure System Call Gateway with RBAC & Real-Time Monitoring

---

## 🔐 Authentication APIs

### 1. Login
**POST** `/api/auth/login`

**Request Body:**
```json
{
  "username": "tejas",
  "password": "password123"
}
```

**Response:**
```json
{
  "message": "Login successful",
  "token": "jwt_token_here",
  "role": "admin"
}
```

---

### 2. Logout
**POST** `/api/auth/logout`

**Headers:**
```
Authorization: Bearer <token>
```

**Response:**
```json
{
  "message": "Logged out successfully"
}
```

---

## 👤 User & Role APIs

### 3. Get Current User
**GET** `/api/user/me`

**Headers:**
```
Authorization: Bearer <token>
```

**Response:**
```json
{
  "username": "tejas",
  "role": "admin",
  "is_flagged": false,
  "risk_score": 0.0
}
```

---

## 🛡️ Policy APIs

### 4. Get All Policies
**GET** `/api/policies`

**Headers:**
```
Authorization: Bearer <token>
```

> 🔒 Requires `admin` role.

**Response:**
```json
[
  {
    "id": 1,
    "name": "block_guest_exec",
    "rule_json": {
      "action": "exec_process",
      "allow_roles": ["admin", "developer"]
    },
    "is_active": true
  }
]
```

---

### 5. Create Policy
**POST** `/api/policies`

**Headers:**
```
Authorization: Bearer <token>
```

> 🔒 Requires `admin` role.

**Request Body:**
```json
{
  "name": "block_guest_write",
  "rule_json": {
    "action": "file_write",
    "allow_roles": ["admin", "developer"]
  },
  "is_active": true
}
```

**Response:**
```json
{
  "message": "Policy created successfully",
  "id": 2
}
```

---

### 6. Update Policy
**PUT** `/api/policies/:id`

**Headers:**
```
Authorization: Bearer <token>
```

> 🔒 Requires `admin` role.

**Request Body:**
```json
{
  "rule_json": {
    "action": "file_write",
    "allow_roles": ["admin"]
  },
  "is_active": true
}
```

**Response:**
```json
{
  "message": "Policy updated successfully"
}
```

---

## ⚙️ System Call APIs

> 🔒 All syscall routes require `Authorization: Bearer <token>` header.
> Permissions enforced by RBAC middleware based on role.

### 7. Read File
**POST** `/api/syscall/read`

**Headers:**
```
Authorization: Bearer <token>
```

**Request Body:**
```json
{
  "file_path": "test.txt"
}
```

**Response:**
```json
{
  "status": "allowed",
  "content": "File content here"
}
```

---

### 8. Write File
**POST** `/api/syscall/write`

**Headers:**
```
Authorization: Bearer <token>
```

**Request Body:**
```json
{
  "file_path": "test.txt",
  "data": "Hello World"
}
```

**Response:**
```json
{
  "status": "allowed",
  "message": "Write successful"
}
```

---

### 9. Delete File
**POST** `/api/syscall/delete`

**Headers:**
```
Authorization: Bearer <token>
```

**Request Body:**
```json
{
  "file_path": "test.txt"
}
```

**Response:**
```json
{
  "status": "blocked",
  "reason": "Permission denied"
}
```

---

### 10. Execute Process
**POST** `/api/syscall/execute`

**Headers:**
```
Authorization: Bearer <token>
```

**Request Body:**
```json
{
  "command": "ls"
}
```

**Response:**
```json
{
  "status": "allowed",
  "output": "file1.txt file2.txt"
}
```

---

## 📜 Logging APIs

### 11. Get Logs
**GET** `/api/logs`

**Headers:**
```
Authorization: Bearer <token>
```

**Query Params (Optional):**

| Param | Type | Description |
|---|---|---|
| `user` | string | Filter by username |
| `status` | string | `allowed` / `blocked` / `flagged` |
| `call_type` | string | `file_read` / `file_write` / `exec_process` / `file_delete` |
| `date` | string | Date filter e.g. `2026-03-25` |
| `from` | string | Start datetime e.g. `2026-03-25T00:00:00` |
| `to` | string | End datetime e.g. `2026-03-25T23:59:59` |
| `page` | integer | Page number for pagination (default: 1) |

**Response:**
```json
{
  "page": 1,
  "total": 120,
  "logs": [
    {
      "id": 42,
      "user": "tejas",
      "call_type": "file_read",
      "target_path": "test.txt",
      "status": "allowed",
      "reason": null,
      "risk_delta": 0.0,
      "timestamp": "2026-03-25T10:00:00"
    }
  ]
}
```

---

### 12. Verify All Log Integrity
**GET** `/api/logs/verify`

**Headers:**
```
Authorization: Bearer <token>
```

> 🔒 Requires `admin` role. Verifies the full SHA256 hash chain across all logs.

**Response:**
```json
{
  "status": "valid",
  "message": "Logs are not tampered"
}
```

---

### 13. Verify Single Log Entry
**GET** `/api/logs/verify/:id`

**Headers:**
```
Authorization: Bearer <token>
```

> Verifies the SHA256 hash of a single log entry and checks it against the chain.

**Response:**
```json
{
  "log_id": 42,
  "valid": true,
  "tampered": false
}
```

---

## 🚨 Threat Detection APIs

### 14. Get Suspicious Activities
**GET** `/api/threats`

**Headers:**
```
Authorization: Bearer <token>
```

> 🔒 Requires `admin` role.

**Response:**
```json
[
  {
    "user": "guest",
    "risk_score": 85,
    "reason": "Multiple failed attempts"
  }
]
```

---

## 📊 Dashboard APIs

### 15. System Statistics
**GET** `/api/dashboard/stats`

**Headers:**
```
Authorization: Bearer <token>
```

**Response:**
```json
{
  "total_calls": 120,
  "allowed": 90,
  "blocked": 30,
  "flagged": 5,
  "suspicious_users": 3,
  "top_users": [
    { "username": "tejas", "call_count": 55 },
    { "username": "vanshika", "call_count": 40 }
  ]
}
```

---

### 16. Activity Over Time
**GET** `/api/dashboard/activity`

**Headers:**
```
Authorization: Bearer <token>
```

**Response:**
```json
[
  {
    "time": "10:00",
    "allowed": 12,
    "blocked": 3,
    "calls": 15
  },
  {
    "time": "11:00",
    "allowed": 18,
    "blocked": 2,
    "calls": 20
  }
]
```

---

## 🔒 Security Notes

- All protected routes require JWT Authentication
- Role-Based Access Control (RBAC) enforced at middleware level
- Policies dynamically loaded from `access_policy.json` and synced to DB
- All system calls are:
  - Logged with SHA256 hash chaining
  - Validated and path-sanitized
  - Checked against RBAC permissions and active policies
- Risk score updated on every flagged or blocked syscall attempt

---

## 📌 Status Codes

| Code | Meaning               |
| ---- | --------------------- |
| 200  | Success               |
| 401  | Unauthorized          |
| 403  | Forbidden             |
| 404  | Not Found             |
| 500  | Internal Server Error |

---

## 🧠 Summary

This API layer acts as a secure mediation interface between users and OS system calls by integrating:
- Authentication (JWT + bcrypt)
- RBAC (role-based permission enforcement)
- Policy Enforcement (dynamic JSON rules)
- Secure Logging (SHA256 hash chain, paginated, filterable)
- Threat Detection (risk scoring, suspicious user tracking)
