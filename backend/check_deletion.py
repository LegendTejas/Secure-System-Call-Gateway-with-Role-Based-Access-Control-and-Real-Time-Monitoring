import sqlite3
import os

path = "syscall_gateway.db"
if not os.path.exists(path):
    print(f"DB not found at {path}")
    exit(1)

conn = sqlite3.connect(path)
conn.row_factory = sqlite3.Row
user = conn.execute("SELECT * FROM users WHERE username = 'NewUser'").fetchone()
conn.close()

if user:
    print("User 'NewUser' still exists.")
else:
    print("User 'NewUser' NOT found (Successfully deleted).")
