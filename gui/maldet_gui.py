#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
##
# Linux Malware Detect v2.0.1 - Web GUI
#             (C) 2002-2026, R-fx Networks <proj@rfxn.com>
#             (C) 2026, Ryan MacDonald <ryan@rfxn.com>
#
# A self-contained web-based GUI for Linux Malware Detect (maldet).
# Built with Python 3 standard library only - no external dependencies.
# Licensed under GNU GPL v2.
##
#
import os
import sys
import json
import subprocess
import threading
import time
import re
import signal
import shutil
import platform
import pwd
import hashlib
import secrets
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

VERSION = "1.0.0"
MALDET_BIN = os.environ.get("MALDET_BIN", "maldet")
DEFAULT_BASE_DIR = "/usr/local/maldetect"
CONF_FILE = "conf.maldet"
LOG_DIR = "/var/log/maldet"
EVENT_LOG = "event_log"
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 32501

MIME_TYPES = {
    ".html": "text/html", ".css": "text/css", ".js": "application/javascript",
    ".png": "image/png", ".jpg": "image/jpeg", ".gif": "image/gif",
    ".svg": "image/svg+xml", ".ico": "image/x-icon",
    ".json": "application/json", ".txt": "text/plain",
}

BASE_DIR = DEFAULT_BASE_DIR
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
STATIC_DIR = os.path.join(SCRIPT_DIR, "static")
TEMPLATE_DIR = os.path.join(SCRIPT_DIR, "templates")
AUTH_FILE = "gui.auth"
AUTH_SESSIONS = {}
AUTH_LOCK = threading.Lock()
SCAN_START_LOCK = threading.Lock()
SCAN_START_RESERVATIONS = {}
SCAN_START_RESERVATION_TTL = 30.0


# ---------------------------------------------------------------------------
# Path resolution helpers
# ---------------------------------------------------------------------------

def get_maldet_path():
    """Resolve the maldet binary: PATH first, then known install locations."""
    found = shutil.which(MALDET_BIN)
    if found:
        return found
    for candidate in [
        "/usr/local/sbin/maldet",
        "/usr/local/maldetect/maldet",
        "/usr/sbin/maldet",
        "/usr/bin/maldet",
    ]:
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    return MALDET_BIN

def get_base_dir():
    base = BASE_DIR
    if not os.path.isfile(os.path.join(base, CONF_FILE)):
        for c in ["/usr/local/maldetect", "/usr/lib/maldet", "/usr/share/maldet"]:
            if os.path.isfile(os.path.join(c, CONF_FILE)):
                return c
    return base

def get_log_dir():
    base = get_base_dir()
    link = os.path.join(base, "logs")
    if os.path.islink(link) and os.path.isdir(link):
        return os.readlink(link)
    return LOG_DIR

def get_conf_path():
    return os.path.join(get_base_dir(), CONF_FILE)

def get_quarantine_dir():
    return os.path.join(get_base_dir(), "quarantine")

def get_session_dir():
    return os.path.join(get_base_dir(), "sess")

def get_sig_dir():
    return os.path.join(get_base_dir(), "sigs")

def get_auth_path():
    return os.path.join(get_base_dir(), AUTH_FILE)

def _auth_record():
    try:
        with open(get_auth_path(), encoding="utf-8") as fh:
            salt, digest = fh.read().strip().split(":", 1)
            return salt, digest
    except (OSError, ValueError):
        return None

def _password_hash(password, salt):
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 200000).hex()

def auth_required():
    return _auth_record() is not None

def set_auth_password(password):
    if not isinstance(password, str) or len(password) < 8:
        return False, "Password must contain at least 8 characters"
    salt = secrets.token_hex(16)
    path = get_auth_path()
    tmp = path + ".tmp." + str(os.getpid())
    try:
        with open(tmp, "w", encoding="utf-8") as fh:
            fh.write(salt + ":" + _password_hash(password, salt) + "\n")
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
        return True, ""
    except OSError as exc:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        return False, str(exc)

def authenticate_password(password):
    record = _auth_record()
    if not record or not isinstance(password, str):
        return False
    salt, expected = record
    return secrets.compare_digest(_password_hash(password, salt), expected)


# ---------------------------------------------------------------------------
# Utility: run maldet
# ---------------------------------------------------------------------------

def run_maldet(args, timeout=30, capture=True):
    """Execute a maldet command and return (stdout, stderr, returncode)."""
    cmd = [get_maldet_path()] + args
    try:
        proc = subprocess.run(
            cmd, capture_output=capture, text=True, timeout=timeout,
            start_new_session=True,
        )
        return proc.stdout, proc.stderr, proc.returncode
    except FileNotFoundError:
        return "", "maldet binary not found: " + str(MALDET_BIN), 127
    except subprocess.TimeoutExpired:
        return "", "Command timed out after " + str(timeout), 124
    except Exception as e:
        return "", str(e), 1


# ---------------------------------------------------------------------------
# Utility: system info
# ---------------------------------------------------------------------------

def get_system_info():
    """Gather system information for the dashboard."""
    installer_candidates = [
        os.path.join(os.path.dirname(SCRIPT_DIR), "install.sh"),
        os.path.join(get_base_dir(), "install.sh"),
    ]
    installer_path = next(
        (path for path in installer_candidates if os.path.isfile(path)), "")
    info = {
        "hostname": platform.node(),
        "system": platform.system(),
        "release": platform.release(),
        "machine": platform.machine(),
        "processor": platform.processor() or "unknown",
        "python_version": platform.python_version(),
        "maldet_path": get_maldet_path(),
        "base_dir": get_base_dir(),
        "installer_directory": os.path.dirname(installer_path) if installer_path else "",
        "installer_path": installer_path,
        "log_dir": get_log_dir(),
        "euid": os.geteuid(),
        "is_root": os.geteuid() == 0,
    }

    # CPU info
    try:
        with open("/proc/cpuinfo", "r") as f:
            cpudata = f.read()
        for line in cpudata.split("\n"):
            if line.startswith("model name"):
                info["cpu"] = line.split(":", 1)[1].strip()
                break
        info["cpu_cores"] = cpudata.count("processor\t:") or cpudata.count("processor :")
    except Exception:
        info["cpu"] = "unknown"
        info["cpu_cores"] = 0

    # Memory info
    try:
        mem = {}
        with open("/proc/meminfo", "r") as f:
            for line in f:
                parts = line.split(":")
                if len(parts) == 2:
                    mem[parts[0].strip()] = int(parts[1].strip().split()[0])
        info["mem_total_mb"] = mem.get("MemTotal", 0) // 1024
        info["mem_available_mb"] = mem.get("MemAvailable", 0) // 1024
    except Exception:
        pass

    # Disk usage
    try:
        usage = os.statvfs(get_base_dir())
        info["disk_total_gb"] = round((usage.f_blocks * usage.f_frsize) / (1024**3), 1)
        info["disk_free_gb"] = round((usage.f_bavail * usage.f_frsize) / (1024**3), 1)
    except Exception:
        pass

    # Check binaries
    info["binaries"] = {}
    for name in ["clamscan", "clamdscan", "yara", "cpulimit",
                 "inotifywait", "mail", "sendmail", "curl", "wget"]:
        info["binaries"][name] = shutil.which(name) or ""

    # Monitor status
    info["monitor_running"] = False
    try:
        result = subprocess.run(["pgrep", "-f", "inotify.paths"],
                                capture_output=True, text=True, timeout=5)
        if result.stdout.strip():
            info["monitor_running"] = True
            info["monitor_pids"] = result.stdout.strip().split("\n")
    except Exception:
        pass

    # Active scans from meta files. A meta file is retained after completion,
    # so only explicitly running/paused states belong in this dashboard count.
    sess = get_session_dir()
    active = []
    try:
        if os.path.isdir(sess):
            for f in os.listdir(sess):
                if f.startswith("scan.meta.") and not f.endswith(".tmp"):
                    scan_id = f.replace("scan.meta.", "")
                    try:
                        meta_state = ""
                        for line in open(os.path.join(sess, f)):
                            if line.startswith("state="):
                                meta_state = line.split("=", 1)[1].strip()
                            if line.startswith("pid="):
                                pid = int(line.split("=", 1)[1].strip())
                        if meta_state not in ("running", "paused"):
                            continue
                        try:
                            os.kill(pid, 0)
                            state = meta_state
                        except (OSError, ProcessLookupError):
                            continue
                        active.append({"scan_id": scan_id, "pid": pid, "state": state})
                    except Exception:
                        pass
    except Exception:
        pass
    info["active_scans"] = active

    # Signature version
    sig_ver_file = os.path.join(get_sig_dir(), "maldet.sigs.ver")
    try:
        info["signature_version"] = open(sig_ver_file).read().strip()
    except Exception:
        info["signature_version"] = "unknown"

    # maldet version
    out, _, _ = run_maldet(["-v"], timeout=5)
    info["version"] = out.strip().split("\n")[0] if out else "unknown"

    return info


def format_elapsed(seconds):
    """Format seconds into human-readable duration."""
    if not seconds or seconds == 0:
        return "n/a"
    seconds = int(seconds)
    days, seconds = divmod(seconds, 86400)
    hours, seconds = divmod(seconds, 3600)
    minutes, seconds = divmod(seconds, 60)
    if days > 0:
        return "%dd %dh %dm" % (days, hours, minutes)
    elif hours > 0:
        return "%dh %dm %ds" % (hours, minutes, seconds)
    elif minutes > 0:
        return "%dm %ds" % (minutes, seconds)
    return "%ds" % seconds


def quarantine_details(filename):
    """Return infection metadata for one quarantined file."""
    quar_dir = os.path.realpath(get_quarantine_dir())
    name = os.path.basename(str(filename or ""))
    if not name or name != str(filename) or name in (".", ".."):
        raise ValueError("Invalid quarantine file")
    path = os.path.realpath(os.path.join(quar_dir, name))
    if os.path.dirname(path) != quar_dir or not os.path.isfile(path):
        raise FileNotFoundError("Quarantined file not found")

    details = {
        "name": name,
        "path": path,
        "size": os.path.getsize(path),
    }
    info_path = path + ".info"
    if os.path.isfile(info_path):
        with open(info_path, "r", errors="replace") as info_file:
            for line in info_file:
                parts = line.strip().split(":", 8)
                if len(parts) < 9 or line.lstrip().startswith("#"):
                    continue
                details.update({
                    "owner": parts[0],
                    "group": parts[1],
                    "mode": parts[2],
                    "original_size": int(parts[3]) if parts[3].isdigit() else parts[3],
                    "hash": parts[4],
                    "atime": int(parts[5]) if parts[5].isdigit() else parts[5],
                    "mtime": int(parts[6]) if parts[6].isdigit() else parts[6],
                    "ctime": int(parts[7]) if parts[7].isdigit() else parts[7],
                    "original_path": parts[8],
                })
                break

    history_path = os.path.join(get_session_dir(), "quarantine.hist")
    if os.path.isfile(history_path):
        with open(history_path, "r", errors="replace") as history:
            for line in reversed(history.readlines()):
                parts = line.rstrip("\n").split(":", 7)
                if len(parts) == 8 and os.path.realpath(parts[7]) == path:
                    details.update({
                        "detected_at": int(parts[0]) if parts[0].isdigit() else parts[0],
                        "signature": parts[1],
                        "detected_path": parts[2],
                        "detected_user": parts[3],
                        "detected_group": parts[4],
                        "md5": parts[5],
                    })
                    break
    return details


# ---------------------------------------------------------------------------
# Utility: configuration management
# ---------------------------------------------------------------------------

def parse_config(path=None):
    """Parse a maldet configuration file into a dict."""
    if path is None:
        path = get_conf_path()
    config = {}
    if not os.path.isfile(path):
        return config
    current_section = "General"
    current_comment = ""
    try:
        for line in open(path, "r", errors="replace"):
            stripped = line.strip()
            m = re.match(r"^##\s*#\s*\[ (.+?) \]\s*##", stripped)
            if m:
                current_section = m.group(1)
                current_comment = ""
                continue
            if stripped.startswith("#"):
                current_comment = stripped
                continue
            m = re.match(r'^(\w+)="([^"]*)"', stripped)
            if m:
                config[m.group(1)] = {
                    "value": m.group(2),
                    "comment": current_comment,
                    "section": current_section,
                }
                current_comment = ""
    except Exception as e:
        config["__error__"] = {"error": str(e)}
    return config


def write_config_change(path, key, value):
    """Update a single key=value in the config file."""
    try:
        lines = open(path, "r", errors="replace").readlines()
        changed = False
        new_lines = []
        for line in lines:
            stripped = line.strip()
            m = re.match(r'^(%s)="([^"]*)"' % re.escape(key), stripped)
            if m and not changed:
                new_lines.append('%s="%s"\n' % (m.group(1), value))
                changed = True
            else:
                new_lines.append(line)
        if not changed:
            return False, "Config key '%s' not found" % key
        open(path, "w").writelines(new_lines)
        return True, "Config updated successfully"
    except Exception as e:
        return False, str(e)


# ---------------------------------------------------------------------------
# Utility: quarantine management
# ---------------------------------------------------------------------------

def parse_quarantine_list():
    """Parse the quarantine directory to list all quarantined files."""
    quar_dir = get_quarantine_dir()
    files = []
    try:
        if not os.path.isdir(quar_dir):
            return files
        for entry in sorted(os.listdir(quar_dir)):
            full_path = os.path.join(quar_dir, entry)
            info_path = full_path + ".info"
            if not os.path.isfile(full_path) or entry.endswith(".info"):
                continue
            info = {"name": entry, "path": full_path, "size": os.path.getsize(full_path)}
            if os.path.isfile(info_path):
                try:
                    for line in open(info_path, "r", errors="replace"):
                        parts = line.strip().split(":", 8)
                        if len(parts) >= 9:
                            info["signature"] = parts[0]
                            info["original_path"] = parts[8]
                            try:
                                info["mtime"] = int(parts[5])
                            except (ValueError, IndexError):
                                pass
                            try:
                                info["size_orig"] = int(parts[4])
                            except (ValueError, IndexError):
                                pass
                except Exception:
                    pass
            files.append(info)
    except Exception:
        pass
    return files


# ---------------------------------------------------------------------------
# Utility: log and ignore file management
# ---------------------------------------------------------------------------

def read_event_log(lines=200):
    """Read the last N lines of the event log."""
    log_file = os.path.join(get_log_dir(), EVENT_LOG)
    if not os.path.isfile(log_file):
        return []
    try:
        result = subprocess.run(
            ["tail", "-n", str(lines), log_file],
            capture_output=True, text=True, timeout=10
        )
        return [l for l in result.stdout.strip().split("\n") if l]
    except Exception:
        return []


def read_ignore_file(filepath):
    """Read an ignore file and return its lines."""
    if not os.path.isfile(filepath):
        return []
    try:
        return [line.rstrip("\n") for line in open(filepath, "r", errors="replace")]
    except Exception:
        return []


def write_ignore_file(filepath, lines):
    """Write lines to an ignore file."""
    try:
        with open(filepath, "w") as f:
            for line in lines:
                f.write(line + "\n")
        return True, "File updated successfully"
    except Exception as e:
        return False, str(e)


def get_ignore_files():
    """Get all ignore file paths and their contents."""
    base = get_base_dir()
    ignore_files = {}
    definitions = {
        "ignore_paths": "Line-separated paths to exclude from scans",
        "ignore_file_ext": "Line-separated file extensions to exclude from scans",
        "ignore_sigs": "Line-separated signature patterns to ignore (regex)",
        "ignore_inotify": "Paths/regex to exclude from monitoring (literal: prefix for literal)",
    }
    for filename, desc in definitions.items():
        filepath = os.path.join(base, filename)
        ignore_files[filename] = {
            "path": filepath,
            "lines": read_ignore_file(filepath),
            "description": desc,
        }
    return ignore_files


# ---------------------------------------------------------------------------
# Utility: JSON helpers for maldet output
# ---------------------------------------------------------------------------

def safe_json_report(scan_id):
    """Run maldet --json-report SCANID and parse the JSON output."""
    cmd = [get_maldet_path(), "--json-report", scan_id]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    if result.returncode not in (0, 2):
        raise RuntimeError(result.stderr.strip() or "Failed to get report")
    return json.loads(result.stdout)


def safe_json_list():
    """Run maldet --json-report list and parse the JSON output."""
    cmd = [get_maldet_path(), "--json-report", "list"]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    return json.loads(result.stdout)


def safe_json_active():
    """Run maldet --format json -L and parse active scans."""
    cmd = [get_maldet_path(), "--format", "json", "-L"]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    stripped = result.stdout.strip()
    if not stripped or stripped.startswith("No active"):
        return {"active_scans": []}
    if result.returncode not in (0, 2):
        raise RuntimeError(result.stderr.strip() or "Failed to read active scans")
    return json.loads(stripped)


# ---------------------------------------------------------------------------
# API Handler
# ---------------------------------------------------------------------------

class MaldetAPI:
    """Dispatches API requests to maldet CLI commands."""

    @staticmethod
    def handle(method, path, body=None):
        """Route an API request. Returns (status_code, response_dict)."""
        parsed = urlparse(path)
        route = parsed.path.rstrip("/")
        query = parse_qs(parsed.query)

        try:
            return MaldetAPI._dispatch(method, route, query, body)
        except json.JSONDecodeError as e:
            return 500, {"error": "JSON decode error: " + str(e)}
        except Exception as e:
            return 500, {"error": str(e)}

    @staticmethod
    def _dispatch(method, route, query, body):
        # ---- System / version ----
        if route == "/api/system":
            return 200, {"system": get_system_info()}

        if route == "/api/version":
            info = get_system_info()
            return 200, {
                "version": info.get("version", "unknown"),
                "signature_version": info.get("signature_version", "unknown"),
                "gui_version": VERSION,
            }

        if route == "/api/config":
            if method == "GET":
                config = parse_config()
                return 200, {"config": config, "path": get_conf_path()}
            elif method == "PUT":
                data = body or {}
                key = data.get("key", "")
                value = data.get("value", "")
                if not key:
                    return 400, {"error": "Missing 'key' parameter"}
                ok, msg = write_config_change(get_conf_path(), key, value)
                return (200 if ok else 400), {"message": msg} if ok else {"error": msg}

        if route == "/api/config/reload" and method == "POST":
            # Config is auto-loaded on each invocation; no explicit reload needed
            return 200, {"message": "Configuration will be reloaded on next command"}

        if route == "/api/config/defaults" and method == "GET":
            defaults_path = os.path.join(get_base_dir(), CONF_FILE)
            defaults = parse_config(defaults_path)
            return 200, {"defaults": defaults, "path": defaults_path}

        if route == "/api/directories" and method == "GET":
            requested = query.get("path", ["/"])[0] or "/"
            current = os.path.abspath(os.path.expanduser(requested))
            if not os.path.isdir(current):
                return 400, {"error": "Directory does not exist: " + current}
            directories = []
            try:
                for name in sorted(os.listdir(current), key=str.lower):
                    full_path = os.path.join(current, name)
                    if os.path.isdir(full_path) and not os.path.islink(full_path):
                        directories.append({"name": name, "path": full_path})
            except OSError as exc:
                return 403, {"error": "Cannot read directory: " + str(exc)}
            parent = os.path.dirname(current) if current != "/" else None
            return 200, {"path": current, "parent": parent, "directories": directories}

        # ---- Scans ----
        if route == "/api/scans" and method == "GET":
            try:
                data = safe_json_list()
                return 200, data
            except Exception as exc:
                return 503, {"error": "Unable to load scan reports: " + str(exc)}

        if route == "/api/scans/active" and method == "GET":
            try:
                return 200, safe_json_active()
            except Exception as exc:
                return 503, {"error": "Unable to load active scans: " + str(exc)}

        if route.startswith("/api/scan/") and method == "GET":
            scan_id = route.split("/")[3]
            try:
                return 200, safe_json_report(scan_id)
            except Exception as e:
                return 404, {"error": str(e)}

        if route == "/api/scan" and method == "POST":
            return MaldetAPI._handle_scan_start(body or {})

        if route.startswith("/api/scan/") and method == "POST":
            parts = route.split("/")
            scan_id = parts[3]
            action = parts[4] if len(parts) > 4 else ""
            return MaldetAPI._handle_scan_action(scan_id, action, body or {})

        # ---- Quarantine ----
        if route == "/api/quarantine" and method == "GET":
            files = parse_quarantine_list()
            return 200, {"files": files, "dir": get_quarantine_dir(),
                         "count": len(files)}

        if route == "/api/quarantine/stats" and method == "GET":
            return MaldetAPI._quarantine_stats()

        if route == "/api/quarantine/details" and method == "GET":
            filename = query.get("file", [""])[0]
            try:
                return 200, quarantine_details(filename)
            except (FileNotFoundError, ValueError) as exc:
                return 404, {"error": str(exc)}
            except OSError as exc:
                return 500, {"error": "Cannot read quarantine details: " + str(exc)}

        if route.startswith("/api/quarantine/") and method == "POST":
            return MaldetAPI._handle_quarantine_action(
                route.split("/")[3], body or {})

        # ---- Logs ----
        if route == "/api/logs" and method == "GET":
            lines = int(query.get("lines", ["200"])[0])
            return 200, {"logs": read_event_log(lines), "total": 0}

        # ---- Monitor ----
        if route == "/api/monitor" and method == "POST":
            return MaldetAPI._handle_monitor(body or {})

        if route == "/api/monitor/users":
            return MaldetAPI._monitor_users(method, body or {})

        # ---- Updates ----
        if route == "/api/update/sigs" and method == "POST":
            data = body or {}
            before = get_system_info()
            args = ["-u"]
            if data.get("force"):
                args.append("--force")
            out, err, rc = run_maldet(args, timeout=120)
            after = get_system_info()
            return (200 if rc == 0 else 400), {
                "operation": "signature update",
                "status": "completed" if rc == 0 else "failed",
                "returncode": rc,
                "stdout": out,
                "stderr": err,
                "before": {"signature_version": before.get("signature_version")},
                "after": {"signature_version": after.get("signature_version")},
                "changed": before.get("signature_version") != after.get("signature_version"),
            }

        if route == "/api/update/version" and method == "POST":
            data = body or {}
            before = get_system_info()
            args = ["-d"]
            if data.get("force"):
                args.append("--force")
            if data.get("beta"):
                args.append("--beta")
            out, err, rc = run_maldet(args, timeout=120)
            after = get_system_info()
            return (200 if rc == 0 else 400), {
                "operation": "beta version update" if data.get("beta") else "version update",
                "status": "completed" if rc == 0 else "failed",
                "returncode": rc,
                "stdout": out,
                "stderr": err,
                "before": {"version": before.get("version")},
                "after": {"version": after.get("version")},
                "changed": before.get("version") != after.get("version"),
            }

        # ---- Test alerts ----
        if route == "/api/test-alert" and method == "POST":
            data = body or {}
            return MaldetAPI._test_alert(
                data.get("type", "scan"), data.get("channel", "email"))

        # ---- Purge & maintenance ----
        if route == "/api/purge" and method == "POST":
            out, err, rc = run_maldet(["-p"], timeout=60)
            return 200, {"returncode": rc, "stdout": out, "stderr": err}

        if route == "/api/maintenance" and method == "POST":
            out, err, rc = run_maldet(["--maintenance"], timeout=120)
            return 200, {"returncode": rc, "stdout": out, "stderr": err}

        # ---- Alerts ----
        if route == "/api/digest" and method == "POST":
            out, err, rc = run_maldet(["--digest"], timeout=30)
            return 200, {"returncode": rc, "stdout": out, "stderr": err}

        if route == "/api/alert-daily" and method == "POST":
            out, err, rc = run_maldet(["--alert-daily"], timeout=30)
            return 200, {"returncode": rc, "stdout": out, "stderr": err}

        # ---- Ignore files ----
        if route == "/api/ignore" and method == "GET":
            return 200, {"files": get_ignore_files()}

        if route == "/api/ignore" and method == "PUT":
            data = body or {}
            filename = data.get("filename", "")
            lines = data.get("lines", [])
            ignore_files = get_ignore_files()
            if filename not in ignore_files:
                return 400, {"error": "Unknown ignore file: " + filename}
            ok, msg = write_ignore_file(ignore_files[filename]["path"], lines)
            return (200 if ok else 400), {"message": msg} if ok else {"error": msg}

                        # ---- Health check ----
        if route == "/api/check" and method == "GET":
            info = get_system_info()
            return 200, {
                "available": os.path.isfile(info.get("maldet_path", "")),
                "version": info.get("version", "unknown"),
                "signature_version": info.get("signature_version", "unknown"),
                "base_dir": info.get("base_dir", ""),
            }

        # ---- Hook scan reports ----
        if route == "/api/reports/hooks" and method == "GET":
            hook_log = os.path.join(get_session_dir(), "hook.hits.log")
            hits = []
            if os.path.isfile(hook_log):
                try:
                    for line in open(hook_log, "r", errors="replace"):
                        if not line.strip():
                            continue
                        parts = line.strip().split("\t")
                        if len(parts) >= 4:
                            hits.append({
                                "timestamp": parts[0] if len(parts) > 0 else "",
                                "mode": parts[1] if len(parts) > 1 else "",
                                "signature": parts[2] if len(parts) > 2 else "",
                                "file": parts[3] if len(parts) > 3 else "",
                            })
                except Exception:
                    pass
            # Return most recent 100 entries
            return 200, {"hits": hits[-100:], "count": len(hits)}

        return 404, {"error": "Not found: " + method + " " + route}

    @staticmethod
    def _handle_scan_start(data):
        """Start a scan: scan-all, scan-recent, or file-list.

        Scans always run detached in the background (-b) so the HTTP
        request returns immediately instead of hanging for the whole
        scan duration. Progress can be followed via /api/scans/active
        (Scan Management page) and /api/scans (Reports page).
        """
        scan_type = data.get("type", "all")
        if scan_type == "filelist":
            return 400, {"error": "File list scans are disabled in the GUI"}
        if scan_type not in ("all", "recent"):
            return 400, {"error": "Unsupported scan type: " + str(scan_type)}
        path = data.get("path", "/home")
        days = data.get("days", "7")
        if scan_type == "recent":
            try:
                days = str(int(days))
                if int(days) < 1:
                    raise ValueError
            except (TypeError, ValueError):
                return 400, {"error": "Recent scans require a positive number of days"}
        config_overrides = data.get("config_overrides", "")
        # GUI scans always use Maldet's native engine, regardless of any
        # stale or forged ClamAV override supplied by a client.
        override_parts = [
            part for part in str(config_overrides).split(",")
            if part.strip().split("=", 1)[0].strip() != "scan_clamscan"
        ]
        config_overrides = ",".join(override_parts + ["scan_clamscan=0"])
        include_regex = data.get("include_regex", "")
        exclude_regex = data.get("exclude_regex", "")
        user = data.get("user", "")

        path = os.path.abspath(os.path.expanduser(str(path).strip()))
        if not os.path.isdir(path):
            return 400, {"error": "Scan directory does not exist: " + path}
        path = os.path.realpath(path)

        args = ["-b"]
        if config_overrides:
            args.extend(["-co", config_overrides])
        if include_regex:
            args.extend(["-i", include_regex])
        if exclude_regex:
            args.extend(["-x", exclude_regex])
        if user:
            args.extend(["-U", user])

        if scan_type == "recent":
            args.extend(["-r", path, days])
        else:
            args.extend(["-a", path])

        with SCAN_START_LOCK:
            now = time.monotonic()
            expired = [
                reserved_path for reserved_path, reserved_at in SCAN_START_RESERVATIONS.items()
                if now - reserved_at >= SCAN_START_RESERVATION_TTL
            ]
            for reserved_path in expired:
                del SCAN_START_RESERVATIONS[reserved_path]
            if path in SCAN_START_RESERVATIONS:
                return 409, {
                    "error": "A scan for this directory is already being processed; wait for its status to appear"
                }
            try:
                active_data = safe_json_active()
                active_scans = [
                    item for item in active_data.get("active_scans", [])
                    if isinstance(item, dict)
                ]
                same_path = [
                    item for item in active_scans
                    if os.path.realpath(str(item.get("path", ""))) == path
                ]
                if same_path:
                    ids = ", ".join(str(item.get("scan_id", "unknown")) for item in same_path)
                    return 409, {
                        "error": "A scan for this directory is already active" + (": " + ids if ids else "")
                    }
            except Exception as exc:
                return 503, {"error": "Unable to verify active scans: " + str(exc)}
            SCAN_START_RESERVATIONS[path] = now
            out, err, rc = run_maldet(args, timeout=60)
            if rc not in (0, 2) and "scan in progress" not in (out + err).lower():
                SCAN_START_RESERVATIONS.pop(path, None)
        ok = (rc == 0) or ("scan in progress" in (out + err).lower())
        if ok:
            return 200, {"message": "Scan started in background",
                         "scan_started": True,
                         "args": " ".join(args),
                         "stdout": out, "stderr": err}
        return 500, {"error": (err or out or "failed to start scan").strip(),
                     "args": " ".join(args)}

    @staticmethod
    def _handle_scan_action(scan_id, action, data):
        """Perform an action on a scan (kill, pause, etc.)."""
        actions = {
            "kill": lambda: run_maldet(["--kill", scan_id], timeout=30),
            "pause": lambda: run_maldet(
                ["--pause", scan_id] + ([data["duration"]] if data.get("duration") else []),
                timeout=30),
            "unpause": lambda: run_maldet(["--unpause", scan_id], timeout=30),
            "stop": lambda: MaldetAPI._stop_scan(scan_id),
            "continue": lambda: run_maldet(["--continue", scan_id], timeout=600),
            "quarantine": lambda: run_maldet(["-q", scan_id], timeout=300),
            "clean": lambda: run_maldet(["-n", scan_id], timeout=300),
            "restore": lambda: run_maldet(["-s", scan_id], timeout=300),
        }
        if action == "report_json":
            try:
                return 200, safe_json_report(scan_id)
            except Exception as e:
                return 404, {"error": str(e)}
        if action == "report":
            fmt = data.get("format", "text")
            mailto = data.get("mailto", "")
            args = ["-e", scan_id, "--format", fmt]
            if mailto:
                args.extend(["--mailto", mailto])
            out, err, rc = run_maldet(args, timeout=30)
            return 200, {"returncode": rc, "stdout": out, "stderr": err}
        if action in ("quarantine", "restore"):
            try:
                report = safe_json_report(scan_id)
                if not report.get("reports"):
                    return 404, {"error": "Scan report not found: " + scan_id}
            except Exception as exc:
                return 404, {"error": "Scan report not found: " + str(exc)}
        if action not in actions:
            return 400, {"error": "Unknown action: " + action}
        out, err, rc = actions[action]()
        status = 200 if rc in (0, 2) else 400
        return status, {
            "returncode": rc, "stdout": out, "stderr": err,
            "clean": rc == 0 or rc == 2, "hits_found": rc == 2,
        }

    @staticmethod
    def _stop_scan(scan_id):
        """Stop a scan, terminating engines that cannot checkpoint."""
        out, err, rc = run_maldet(["--stop", scan_id], timeout=30)
        if rc == 0:
            return out, err, rc
        kill_out, kill_err, kill_rc = run_maldet(
            ["--kill", scan_id], timeout=30)
        combined_out = "\n".join(part for part in (out, kill_out) if part)
        combined_err = "\n".join(part for part in (err, kill_err) if part)
        return combined_out, combined_err, kill_rc

    @staticmethod
    def _handle_quarantine_action(action, data):
        """Handle quarantine actions (restore, view info)."""
        if action == "restore-all":
            files = parse_quarantine_list()
            results = []
            for item in files:
                filename = item.get("name", "")
                if not filename or os.path.basename(filename) != filename:
                    results.append({"file": filename, "ok": False, "error": "Invalid quarantine filename"})
                    continue
                try:
                    quarantine_details(filename)
                except (FileNotFoundError, ValueError):
                    results.append({"file": filename, "ok": False, "error": "Quarantined file not found"})
                    continue
                out, err, rc = run_maldet(["-s", filename], timeout=30)
                results.append({
                    "file": filename,
                    "ok": rc in (0, 2),
                    "returncode": rc,
                    "stdout": out,
                    "stderr": err,
                })
            failed = [item for item in results if not item["ok"]]
            return (200 if not failed else 207), {
                "restored": len(results) - len(failed),
                "failed": len(failed),
                "results": results,
            }
        if action == "restore":
            file_path = data.get("file", "")
            if not file_path or os.path.basename(file_path) != file_path:
                return 400, {"error": "Missing 'file' parameter"}
            try:
                quarantine_details(file_path)
            except (FileNotFoundError, ValueError):
                return 404, {"error": "Quarantined file not found"}
            out, err, rc = run_maldet(["-s", file_path], timeout=30)
            return (200 if rc in (0, 2) else 400), {
                "returncode": rc, "stdout": out, "stderr": err}
        return 400, {"error": "Unknown action: " + action}

    @staticmethod
    def _quarantine_stats():
        """Get quarantine statistics."""
        quar_dir = get_quarantine_dir()
        count = 0
        total_size = 0
        try:
            if os.path.isdir(quar_dir):
                for entry in os.listdir(quar_dir):
                    if entry.endswith(".info"):
                        continue
                    full = os.path.join(quar_dir, entry)
                    if os.path.isfile(full):
                        count += 1
                        total_size += os.path.getsize(full)
        except Exception:
            pass
        return 200, {
            "count": count,
            "total_size_mb": round(total_size / (1024 * 1024), 2),
            "dir": quar_dir,
        }

    @staticmethod
    def _monitor_running():
        """Return True if an inotify monitor supervisor process is alive."""
        try:
            result = subprocess.run(["pgrep", "-f", "inotify.paths"],
                                    capture_output=True, text=True, timeout=5)
            return bool(result.stdout.strip())
        except Exception:
            return False

    @staticmethod
    def _systemd_unit():
        """Return True if systemd has an available maldet.service unit."""
        try:
            if not shutil.which("systemctl"):
                return False
            result = subprocess.run(
                ["systemctl", "list-unit-files", "maldet.service"],
                capture_output=True, text=True, timeout=10)
            return "maldet.service" in result.stdout
        except Exception:
            return False

    @staticmethod
    def _systemd_active():
        """Return True if the maldet systemd unit is active."""
        try:
            result = subprocess.run(
                ["systemctl", "is-active", "maldet.service"],
                capture_output=True, text=True, timeout=10)
            return result.stdout.strip() == "active"
        except Exception:
            return False

    @staticmethod
    def _systemd_cmd(action):
        """Run systemctl against the maldet service: start|stop|restart."""
        try:
            result = subprocess.run(
                ["systemctl", action, "maldet.service"],
                capture_output=True, text=True, timeout=30)
            return result.stdout, result.stderr, result.returncode
        except Exception as e:
            return "", str(e), 1

    @staticmethod
    def _handle_monitor(data):
        """Start, stop, or reload the inotify monitor.

        Prefers the systemd unit (works for non-root users when policykit
        permits service control); falls back to the maldet CLI.
        """
        act = data.get("action", "start")
        mode = data.get("mode", "users")
        use_systemd = MaldetAPI._systemd_unit()

        if act == "start":
            if MaldetAPI._monitor_running():
                return 200, {"message": "Monitor is already running",
                             "mode": mode}
            if use_systemd:
                # systemctl start can take ~7-10s (supervisor + inotify
                # witness).  Run it in a background thread so the HTTP
                # request returns immediately and the frontend polls the
                # real status, instead of risking a client timeout.
                def _start_worker():
                    try:
                        r = subprocess.run(
                            ["systemctl", "start", "maldet.service"],
                            capture_output=True, text=True, timeout=150)
                        # If systemctl failed without bringing the supervisor
                        # up, fall back to the maldet CLI directly.
                        if r.returncode != 0 and not MaldetAPI._monitor_running():
                            run_maldet(["-b", "-m", mode], timeout=30)
                    except Exception:
                        pass

                threading.Thread(target=_start_worker, daemon=True).start()
                return 200, {"message": "Monitor start in progress",
                             "status": "starting",
                             "mode": mode,
                             "note": "Starting the monitor supervisor, "
                                     "this can take several seconds."}
            # Fallback: direct CLI as the current user.
            out, err, rc = run_maldet(["-b", "-m", mode], timeout=10)
            if rc != 0:
                return 500, {"error": err or out or "Monitor failed to start (rc=%d)" % rc,
                             "stdout": out, "stderr": err}
            # Supervisor daemonizes and returns 0 even if the monitor then
            # fails (e.g. root-only config, scan_user_access=0).  Verify the
            # process actually came up before claiming success.
            time.sleep(1)
            if not MaldetAPI._monitor_running():
                reason = (err or out or "").strip()
                message = "Monitor did not start."
                if reason:
                    message += " " + reason
                else:
                    message += (" Check that maldet has read access to the "
                                "config and that the GUI runs with sufficient "
                                "privileges.")
                return 500, {"error": message, "stdout": out, "stderr": err}
            return 200, {"message": "Monitor started", "mode": mode,
                         "stdout": out, "stderr": err}
        elif act == "stop":
            if use_systemd and MaldetAPI._systemd_active():
                # The maldet supervisor only handles SIGTERM between monitor
                # cycles (it can be sleeping up to inotify_sleep seconds), so
                # systemctl stop can take 20-120s.  Run it in a background
                # thread so the HTTP request returns immediately and the
                # frontend polls the real status.
                def _stop_worker():
                    try:
                        r = subprocess.run(
                            ["systemctl", "stop", "maldet.service"],
                            capture_output=True, text=True, timeout=150)
                        if r.returncode != 0:
                            # systemctl may time out waiting for the
                            # supervisor to finish its current cycle.
                            # Force-stop the supervisor and its inotifywait.
                            subprocess.run(
                                ["pkill", "-TERM", "-f",
                                 "maldet --monitor"],
                                capture_output=True, text=True, timeout=10)
                            subprocess.run(
                                ["pkill", "-TERM", "-f", "inotify.paths"],
                                capture_output=True, text=True, timeout=10)
                            # Give the trap handler time to finalize.
                            for _ in range(20):
                                if not MaldetAPI._monitor_running():
                                    break
                                time.sleep(1)
                            if MaldetAPI._monitor_running():
                                subprocess.run(
                                    ["pkill", "-KILL", "-f",
                                     "inotify.paths"],
                                    capture_output=True, text=True,
                                    timeout=10)
                    except Exception:
                        pass

                t = threading.Thread(target=_stop_worker, daemon=True)
                t.start()
                return 200, {"message": "Monitor stop in progress",
                             "status": "stopping",
                             "note": "The monitor supervisor can take up to "
                                     "2 minutes to shut down between cycles."}
            out, err, rc = run_maldet(["-k"], timeout=30)
            if rc != 0:
                return 500, {"error": err or out or "Monitor stop failed (rc=%d)" % rc,
                             "stdout": out, "stderr": err}
            return 200, {"message": "Monitor stop signal sent",
                         "stdout": out, "stderr": err}
        elif act == "reload":
            if use_systemd and MaldetAPI._systemd_active():
                out, err, rc = MaldetAPI._systemd_cmd("restart")
                if rc != 0:
                    return 500, {"error": err or out or "systemctl restart failed (rc=%d)" % rc,
                                 "stdout": out, "stderr": err}
                return 200, {"message": "Monitor reloaded via systemd",
                             "stdout": out, "stderr": err}
            out, err, rc = run_maldet(["-m", "reload"], timeout=10)
            if rc != 0:
                return 500, {"error": err or out or "Monitor reload failed (rc=%d)" % rc,
                             "stdout": out, "stderr": err}
            return 200, {"message": "Monitor reload signal sent",
                         "stdout": out, "stderr": err}
        return 400, {"error": "Unknown monitor action: " + act}

    @staticmethod
    def _monitor_users(method, data):
        """List and persist per-user exclusions for `maldet -m users`."""
        config = parse_config()
        disabled_setting = config.get("monitor_disabled_users", {})
        disabled_path = disabled_setting.get("value") if isinstance(disabled_setting, dict) else disabled_setting
        disabled_path = disabled_path or os.path.join(get_base_dir(), "monitor_disabled_users")
        disabled = set()
        if os.path.isfile(disabled_path):
            with open(disabled_path, encoding="utf-8", errors="replace") as fh:
                disabled = {line.strip() for line in fh if line.strip() and not line.startswith("#")}
        users = []
        minuid_setting = config.get("inotify_minuid", {})
        minuid_value = minuid_setting.get("value") if isinstance(minuid_setting, dict) else minuid_setting
        try:
            minuid = int(minuid_value or 500)
        except (TypeError, ValueError):
            minuid = 500
        for entry in pwd.getpwall():
            home = os.path.abspath(entry.pw_dir or "")
            if entry.pw_uid >= minuid and home.startswith("/home/") and os.path.isdir(home):
                users.append({"name": entry.pw_name, "uid": entry.pw_uid,
                              "home": home, "enabled": entry.pw_name not in disabled})
        users.sort(key=lambda item: item["name"])
        if method == "GET":
            return 200, {"users": users, "path": disabled_path}
        if method != "PUT":
            return 405, {"error": "Method not allowed"}
        requested = data.get("users")
        if not isinstance(requested, list) or any(not isinstance(v, str) for v in requested):
            return 400, {"error": "users must be a list of usernames"}
        valid = {item["name"] for item in users}
        invalid = sorted(set(requested) - valid)
        if invalid:
            return 400, {"error": "Unknown or ineligible users: " + ", ".join(invalid)}
        os.makedirs(os.path.dirname(disabled_path) or ".", exist_ok=True)
        tmp = disabled_path + ".tmp.%d" % os.getpid()
        with open(tmp, "w", encoding="utf-8") as fh:
            fh.write("\n".join(sorted(set(requested))) + ("\n" if requested else ""))
        os.replace(tmp, disabled_path)
        return 200, {"message": "Monitor user exclusions saved",
                     "disabled": sorted(set(requested)), "restart_required": True}

    @staticmethod
    def _test_alert(alert_type, channel):
        """Send a test alert via the specified channel."""
        if alert_type not in ("scan", "digest"):
            return 400, {"error": "Invalid alert type. Use 'scan' or 'digest'"}
        if channel not in ("email", "telegram"):
            return 400, {"error": "Invalid channel. Use email or telegram"}
        out, err, rc = run_maldet(["--test-alert", alert_type, channel], timeout=30)
        message = (err or out or "").strip()
        failed = rc not in (0, 2) or "not enabled" in message.lower() or "failed" in message.lower()
        if failed:
            return 400, {"error": message or "Test alert failed",
                         "returncode": rc, "stdout": out, "stderr": err}
        return 200, {"returncode": rc, "stdout": out, "stderr": err}


# ---------------------------------------------------------------------------
# HTTP Request Handler
# ---------------------------------------------------------------------------

class Handler(BaseHTTPRequestHandler):
    """HTTP handler: serves static files and API endpoints."""

    server_version = "MaldetGUI/" + VERSION
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        if os.environ.get("MALDET_GUI_DEBUG"):
            sys.stderr.write("%s - %s\n" % (self.address_string(), fmt % args))

    def _set_headers(self, status=200, content_type="application/json",
                     content_length=None):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        # HTTP/1.1 keep-alive requires an explicit Content-Length (or
        # Connection: close); otherwise clients wait forever for the body.
        if content_length is not None:
            self.send_header("Content-Length", str(content_length))
        self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
        self.send_header("Pragma", "no-cache")
        self.send_header("Expires", "0")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS, HEAD")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        if getattr(self, "_pending_cookie", ""):
            self.send_header("Set-Cookie", self._pending_cookie)
        self.end_headers()

    def _send_json(self, data, status=200):
        body = json.dumps(data, indent=2, default=str).encode("utf-8")
        self._set_headers(status, "application/json", len(body))
        self.wfile.write(body)

    def _session_id(self):
        cookie = self.headers.get("Cookie", "")
        for part in cookie.split(";"):
            name, _, value = part.strip().partition("=")
            if name == "maldet_session":
                return value
        return ""

    def _authenticated(self):
        sid = self._session_id()
        with AUTH_LOCK:
            return bool(sid and sid in AUTH_SESSIONS)

    def _set_session(self):
        sid = secrets.token_urlsafe(32)
        with AUTH_LOCK:
            AUTH_SESSIONS[sid] = time.time()
        self._pending_cookie = "maldet_session=%s; Path=/; HttpOnly; SameSite=Strict" % sid

    def _auth_response(self):
        if not auth_required():
            return self._send_json({"authenticated": False, "setup_required": True}, 401)
        return self._send_json({"authenticated": False, "setup_required": False}, 401)

    def _send_static(self, filepath, content_type=None):
        if not os.path.isfile(filepath):
            self._set_headers(404, "text/plain", len(b"404 Not Found"))
            self.wfile.write(b"404 Not Found")
            return
        if content_type is None:
            content_type = MIME_TYPES.get(
                os.path.splitext(filepath)[1], "application/octet-stream")
        with open(filepath, "rb") as f:
            content = f.read()
        self._set_headers(200, content_type, len(content))
        self.wfile.write(content)

    def _read_body(self):
        length = int(self.headers.get("Content-Length", 0))
        if length == 0:
            return None
        raw = self.rfile.read(length)
        try:
            return json.loads(raw)
        except (json.JSONDecodeError, UnicodeDecodeError):
            return {"raw": raw.decode("utf-8", errors="replace")}

    def do_OPTIONS(self):
        self._set_headers(200)

    def do_HEAD(self):
        """Handle HEAD requests - used by browsers to check if resources exist."""
        route = urlparse(self.path).path
        if route.startswith("/static/"):
            filepath = os.path.join(SCRIPT_DIR, route.lstrip("/"))
            if os.path.isfile(filepath):
                mime = MIME_TYPES.get(os.path.splitext(filepath)[1], "application/octet-stream")
                self._set_headers(200, mime, os.path.getsize(filepath))
            else:
                self._set_headers(404, "text/plain", len(b"404 Not Found"))
            return
        if route == "/" or not route.startswith("/api"):
            idx = os.path.join(TEMPLATE_DIR, "index.html")
            if os.path.isfile(idx):
                self._set_headers(200, "text/html", os.path.getsize(idx))
            else:
                self._set_headers(404, "text/html", len(b"404 Not Found"))
            return
        self._set_headers(200)

    def do_GET(self):
        route = urlparse(self.path).path
        if route == "/api/auth/status":
            if self._authenticated():
                return self._send_json({"authenticated": True, "setup_required": False})
            return self._send_json({"authenticated": False, "setup_required": not auth_required()})
        if route == "/api/systray/status":
            try:
                data = safe_json_active()
                scans = data.get("active_scans", data.get("active", []))
                states = {}
                for scan in scans if isinstance(scans, list) else []:
                    state = str(scan.get("state", "running"))
                    states[state] = states.get(state, 0) + 1
                return self._send_json({
                    "available": True,
                    "active_count": len(scans) if isinstance(scans, list) else 0,
                    "states": states,
                })
            except Exception as exc:
                return self._send_json({"available": False, "error": str(exc)}, 503)
        if route.startswith("/api/") and not self._authenticated():
            return self._auth_response()
        # Serve static files
        if route.startswith("/static/"):
            filepath = os.path.join(SCRIPT_DIR, route.lstrip("/"))
            self._send_static(filepath)
            return
        # SPA routing: serve index.html for non-API routes
        if route == "/" or not route.startswith("/api"):
            idx = os.path.join(TEMPLATE_DIR, "index.html")
            self._send_static(idx, "text/html")
            return
        # API routes
        status, data = MaldetAPI.handle("GET", self.path)
        self._send_json(data, status)

    def do_POST(self):
        route = urlparse(self.path).path
        body = self._read_body()
        if route == "/api/auth/setup":
            if auth_required():
                return self._send_json({"error": "Password is already configured"}, 409)
            ok, error = set_auth_password((body or {}).get("password"))
            if not ok:
                return self._send_json({"error": error}, 400)
            self._set_session()
            return self._send_json({"authenticated": True})
        if route == "/api/auth/login":
            if not auth_required():
                return self._send_json({"error": "Initial password setup is required"}, 409)
            if not authenticate_password((body or {}).get("password")):
                return self._send_json({"error": "Invalid password"}, 401)
            self._set_session()
            return self._send_json({"authenticated": True})
        if route == "/api/auth/change":
            if not self._authenticated():
                return self._auth_response()
            payload = body or {}
            current = payload.get("current_password")
            new_password = payload.get("new_password")
            confirmation = payload.get("confirm_password")
            if not authenticate_password(current):
                return self._send_json({"error": "Current password is invalid"}, 400)
            if new_password != confirmation:
                return self._send_json({"error": "New passwords do not match"}, 400)
            ok, error = set_auth_password(new_password)
            if not ok:
                return self._send_json({"error": error}, 400)
            return self._send_json({"changed": True})
        if route == "/api/auth/logout":
            sid = self._session_id()
            with AUTH_LOCK:
                AUTH_SESSIONS.pop(sid, None)
            return self._send_json({"authenticated": False})
        if route.startswith("/api/") and not self._authenticated():
            return self._auth_response()
        if route.startswith("/api/"):
            status, data = MaldetAPI.handle("POST", route, body)
            self._send_json(data, status)
            return
        self._send_json({"error": "Not found"}, 404)

    def do_PUT(self):
        route = urlparse(self.path).path
        body = self._read_body()
        if route.startswith("/api/") and not self._authenticated():
            return self._auth_response()
        if route.startswith("/api/"):
            status, data = MaldetAPI.handle("PUT", route, body)
            self._send_json(data, status)
            return
        self._send_json({"error": "Not found"}, 404)

    def do_DELETE(self):
        route = urlparse(self.path).path
        body = self._read_body()
        if route.startswith("/api/") and not self._authenticated():
            return self._auth_response()
        if route.startswith("/api/"):
            status, data = MaldetAPI.handle("DELETE", route, body)
            self._send_json(data, status)
            return
        self._send_json({"error": "Not found"}, 404)


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def parse_args():
    import argparse
    parser = argparse.ArgumentParser(
        description="Maldet GUI v%s - Web interface for Linux Malware Detect" % VERSION)
    parser.add_argument("--host", default=DEFAULT_HOST,
                        help="Bind address (default: %s)" % DEFAULT_HOST)
    parser.add_argument("--port", type=int, default=DEFAULT_PORT,
                        help="Port number (default: %d)" % DEFAULT_PORT)
    parser.add_argument("--base-dir", default=DEFAULT_BASE_DIR,
                        help="Maldet installation directory")
    parser.add_argument("--maldet-bin", default=MALDET_BIN,
                        help="Path to maldet binary")
    return parser.parse_args()


def main():
    global BASE_DIR, MALDET_BIN
    args = parse_args()
    BASE_DIR = args.base_dir
    MALDET_BIN = args.maldet_bin

    print("Maldet GUI v%s" % VERSION)
    print("  Server:        http://%s:%d" % (args.host, args.port))
    print("  Maldet binary: %s" % get_maldet_path())
    print("  Install dir:   %s" % get_base_dir())
    print("  License:       GPLv2+")
    print()

    server = ThreadingHTTPServer((args.host, args.port), Handler)
    server.daemon_threads = True

    def shutdown(signum, frame):
        print("\nShutting down...")
        # server.shutdown() must run from a different thread than the
        # serve_forever() loop, otherwise it deadlocks and the process
        # never exits (leaving zombie servers behind).
        threading.Thread(target=server.shutdown, daemon=True).start()
        sys.exit(0)

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        shutdown(None, None)


if __name__ == "__main__":
    main()
