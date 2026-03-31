"""
syscall_layer/process_operations.py
Vanshika — Secure subprocess execution wrapper.
Uses subprocess with strict timeout, no shell=True, whitelist-only.
"""

import subprocess
import shlex
import os
from syscall_layer.validation import validate_command

EXEC_TIMEOUT_S = 10    # max seconds a subprocess is allowed to run
MAX_OUTPUT_LEN = 8192  # truncate output beyond this


def safe_exec_process(command: str) -> dict:
    """
    Execute a whitelisted command safely.
    - Never uses shell=True (prevents injection)
    - Hard timeout of 10 seconds
    - Output truncated at 8KB

    Returns: { success, output, return_code } or { success: False, error }
    """
    validation = validate_command(command)
    if not validation["valid"]:
        return {"success": False, "error": validation["reason"]}

    try:
        tokens = shlex.split(command)

        result = subprocess.run(
            tokens,
            capture_output=True,
            text=True,
            timeout=EXEC_TIMEOUT_S,
            shell=False,          # CRITICAL: never shell=True
            cwd="/tmp",           # run in /tmp, not project root
            env={                 # minimal environment — no secrets leaked
                "PATH": "/usr/bin:/bin",
                "HOME": "/tmp",
            }
        )

        output = result.stdout + result.stderr
        if len(output) > MAX_OUTPUT_LEN:
            output = output[:MAX_OUTPUT_LEN] + f"\n[Output truncated at {MAX_OUTPUT_LEN} chars]"

        return {
            "success":     True,
            "output":      output.strip(),
            "return_code": result.returncode,
        }

    except subprocess.TimeoutExpired:
        return {"success": False, "error": f"Command timed out after {EXEC_TIMEOUT_S} seconds."}
    except FileNotFoundError:
        return {"success": False, "error": f"Command not found: '{validation['base_command']}'."}
    except PermissionError:
        return {"success": False, "error": "Execution permission denied."}
    except Exception as e:
        return {"success": False, "error": str(e)}
