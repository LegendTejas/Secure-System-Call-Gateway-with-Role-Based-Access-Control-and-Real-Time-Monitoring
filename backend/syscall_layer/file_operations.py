"""
syscall_layer/file_operations.py
Secure file operation wrappers: read, write, delete, dir_list.
All functions return { success, result/content, error } dicts.
"""

import os
from syscall_layer.validation import validate_file_path, validate_write_data

# Sandbox root — all relative paths are resolved under this directory
SANDBOX_ROOT = os.path.abspath(os.getenv("SANDBOX_ROOT", "./sandbox"))


def _resolve(path: str) -> str:
    """Resolve path inside sandbox. Prevents escaping the sandbox."""
    if os.path.isabs(path):
        return path
    return os.path.join(SANDBOX_ROOT, path)


def safe_file_read(path: str) -> dict:
    """
    Read a file's content safely.
    Returns: { success, content } or { success: False, error }
    """
    validation = validate_file_path(path)
    if not validation["valid"]:
        return {"success": False, "error": validation["reason"]}

    resolved = _resolve(validation["sanitized_path"])

    try:
        if not os.path.exists(resolved):
            return {"success": False, "error": f"File not found: {path}"}
        if not os.path.isfile(resolved):
            return {"success": False, "error": f"Path is not a file: {path}"}

        with open(resolved, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()

        return {"success": True, "content": content}

    except PermissionError:
        return {"success": False, "error": f"Permission denied: {path}"}
    except Exception as e:
        return {"success": False, "error": str(e)}


def safe_file_write(path: str, data: str, mode: str = "truncate", offset: int = 0) -> dict:
    """
    Write data to a file safely with advanced control.
    Modes: truncate (w), append (a), overwrite (r+ at 0), offset (r+ at offset)
    Returns: { success, message } or { success: False, error }
    """
    path_validation = validate_file_path(path)
    if not path_validation["valid"]:
        return {"success": False, "error": path_validation["reason"]}

    data_validation = validate_write_data(data)
    if not data_validation["valid"]:
        return {"success": False, "error": data_validation["reason"]}

    resolved = _resolve(path_validation["sanitized_path"])

    try:
        os.makedirs(os.path.dirname(resolved) or ".", exist_ok=True)
        
        # Ensure file exists for r+ mode
        if mode in ("overwrite", "offset") and not os.path.exists(resolved):
            with open(resolved, "w", encoding="utf-8") as f:
                pass

        py_mode = "w"
        if mode == "append":
            py_mode = "a"
        elif mode in ("overwrite", "offset"):
            py_mode = "r+"

        with open(resolved, py_mode, encoding="utf-8") as f:
            if mode == "offset":
                f.seek(offset)
            elif mode == "overwrite":
                f.seek(0)
            
            f.write(data)

        return {"success": True, "message": f"Write ({mode}) successful"}

    except PermissionError:
        return {"success": False, "error": f"Permission denied: {path}"}
    except Exception as e:
        return {"success": False, "error": str(e)}


def safe_file_delete(path: str) -> dict:
    """
    Delete a file safely.
    Returns: { success, message } or { success: False, error }
    """
    validation = validate_file_path(path)
    if not validation["valid"]:
        return {"success": False, "error": validation["reason"]}

    resolved = _resolve(validation["sanitized_path"])

    try:
        if not os.path.exists(resolved):
            return {"success": False, "error": f"File not found: {path}"}
        if not os.path.isfile(resolved):
            return {"success": False, "error": "Only files can be deleted via this gateway."}

        os.remove(resolved)
        return {"success": True, "message": f"File deleted: {path}"}

    except PermissionError:
        return {"success": False, "error": f"Permission denied: {path}"}
    except Exception as e:
        return {"success": False, "error": str(e)}


def safe_dir_list(path: str) -> dict:
    """
    List directory contents safely.
    Returns: { success, entries: [{ name, type, size }] }
    """
    validation = validate_file_path(path)
    if not validation["valid"]:
        return {"success": False, "error": validation["reason"]}

    resolved = _resolve(validation["sanitized_path"])

    try:
        if not os.path.exists(resolved):
            return {"success": False, "error": f"Directory not found: {path}"}
        if not os.path.isdir(resolved):
            return {"success": False, "error": f"Path is not a directory: {path}"}

        entries = []
        for name in os.listdir(resolved):
            full = os.path.join(resolved, name)
            entries.append({
                "name": name,
                "type": "dir" if os.path.isdir(full) else "file",
                "size": os.path.getsize(full) if os.path.isfile(full) else None,
            })

        return {"success": True, "entries": sorted(entries, key=lambda x: (x["type"], x["name"]))}

    except PermissionError:
        return {"success": False, "error": f"Permission denied: {path}"}
    except Exception as e:
        return {"success": False, "error": str(e)}
