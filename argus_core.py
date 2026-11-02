#!/usr/bin/env python3
"""
Argus core - a strictly READ-ONLY view of what a Hermes Agent is doing.

Reads Hermes' state.db (SQLite) and runtime/active_sessions.json. Never writes
to Hermes' files, never reads .env / auth.json, redacts secrets in all output.

Commands:
  python argus_core.py doctor            verify assumptions against YOUR database (run this first)
  python argus_core.py status            1. what is the agent doing right now
  python argus_core.py commands [-n 10]  2. recent commands + plain-language explanation + risk tag
  python argus_core.py files             3. what it can access / touched / changed
  python argus_core.py watch             live feed of new tool calls (polls every second)
Options: --base PATH (Hermes home), --profile NAME, --json
"""
import argparse
import json
import os
import re
import sqlite3
import subprocess
import sys
import time
from pathlib import Path

RISK_ORDER = ["safe", "runs-code", "modifies", "network", "install", "delete", "danger"]


def worse(a, b):
    return a if RISK_ORDER.index(a) >= RISK_ORDER.index(b) else b


# --------------------------------------------------------------------------
# Redaction (applied to EVERYTHING that leaves this module)
# --------------------------------------------------------------------------
_REDACTIONS = [
    (re.compile(r"\b(?:sk-[A-Za-z0-9_\-]{12,}|gsk_[A-Za-z0-9]{12,}|ghp_[A-Za-z0-9]{20,}|"
                r"github_pat_[A-Za-z0-9_]{20,}|xox[abprs]-[A-Za-z0-9-]{10,}|AIza[0-9A-Za-z_\-]{20,}|"
                r"hf_[A-Za-z0-9]{20,})"), "[REDACTED-KEY]"),
    (re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{5,}"), "[REDACTED-JWT]"),
    (re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._\-]{12,}"), "Bearer [REDACTED]"),
    (re.compile(r"(?i)((?:api[_-]?key|token|secret|password|passwd|pwd|authorization)[\"']?\s*[:=]\s*[\"']?)"
                r"([^\s\"',;&]{4,})"), r"\1[REDACTED]"),
    (re.compile(r"(://)[^/\s:@]+:[^/\s@]+@"), r"\1[REDACTED]@"),
    (re.compile(r"[\w-]+\.ngrok[\w.-]*"), "[ngrok-host]"),
]


def redact(text):
    if text is None:
        return ""
    text = str(text)
    for rx, rep in _REDACTIONS:
        text = rx.sub(rep, text)
    return text


# --------------------------------------------------------------------------
# Locating Hermes data
# --------------------------------------------------------------------------
def find_base(arg=None):
    cands = []
    if arg:
        cands.append(Path(arg))
    if os.environ.get("HERMES_HOME"):
        cands.append(Path(os.environ["HERMES_HOME"]))
    if os.environ.get("LOCALAPPDATA"):
        cands.append(Path(os.environ["LOCALAPPDATA"]) / "hermes")
    cands.append(Path.home() / ".hermes")
    for c in cands:
        if c.exists():
            return c
    raise SystemExit("Could not find the Hermes folder. Pass --base PATH "
                     r"(e.g. C:\Users\you\AppData\Local\hermes).")


class Hermes:
    def __init__(self, base=None, profile=None):
        self.base = find_base(base)
        if not profile:
            ap = self.base / "active_profile"
            if ap.exists():
                profile = ap.read_text(encoding="utf-8", errors="ignore").strip()
        pdir = self.base / "profiles" / profile if profile else None
        self.profile = profile if pdir and pdir.exists() else None
        self.dir = pdir if self.profile else self.base
        self.db_path = self.dir / "state.db"
        if not self.db_path.exists():
            raise SystemExit(f"No state.db in {self.dir}")
        # read-only: URI mode=ro plus query_only pragma. Never touches the WAL writer.
        self.con = sqlite3.connect(self.db_path.as_uri() + "?mode=ro", uri=True, timeout=5)
        self.con.row_factory = sqlite3.Row
        self.con.execute("PRAGMA query_only=ON")
        self.con.execute("PRAGMA busy_timeout=3000")
        self._cols = {}

    # ---- schema helpers
    def cols(self, table):
        if table not in self._cols:
            self._cols[table] = [r[1] for r in self.con.execute(f"PRAGMA table_info('{table}')")]
        return self._cols[table]

    def select(self, table, wanted):
        have = set(self.cols(table))
        return ", ".join(c for c in wanted if c in have) or "*"

    # ---- sessions
    def active_session_id(self):
        f = self.dir / "runtime" / "active_sessions.json"
        try:
            entries = json.loads(f.read_text(encoding="utf-8")).get("entries", [])
            if entries:
                entries.sort(key=lambda e: e.get("updated_at", 0), reverse=True)
                return entries[0].get("session_id"), entries[0]
        except Exception:
            pass
        order = "last_activity_at" if "last_activity_at" in self.cols("sessions") else "started_at"
        r = self.con.execute(f"SELECT id FROM sessions ORDER BY {order} DESC LIMIT 1").fetchone()
        return (r["id"] if r else None), {}

    def session(self, sid):
        sel = self.select("sessions", ["id", "started_at", "ended_at", "cwd", "git_branch", "git_repo_root",
                                       "message_count", "tool_call_count", "tool_names", "title", "model",
                                       "last_activity_at", "last_activity_description"])
        r = self.con.execute(f"SELECT {sel} FROM sessions WHERE id=?", (sid,)).fetchone()
        return dict(r) if r else {}

    # ---- tool calls
    def tool_calls(self, sid, limit=15, after_id=0):
        """Newest-last list of tool calls for a session."""
        have = set(self.cols("messages"))
        sel = self.select("messages", ["id", "role", "tool_calls", "tool_name", "tool_call_id",
                                       "effect_disposition", "timestamp"])
        rows = self.con.execute(
            f"SELECT {sel} FROM messages WHERE session_id=? AND id>? ORDER BY id DESC LIMIT ?",
            (sid, after_id, max(limit * 6, 60))).fetchall()
        disp_by_call = {}
        for r in rows:
            if r["role"] == "tool" and r["tool_call_id"] and "effect_disposition" in have:
                disp_by_call[r["tool_call_id"]] = r["effect_disposition"]
        calls = []
        for r in rows:
            if r["role"] != "assistant":
                continue
            for c in parse_tool_calls(r["tool_calls"]):
                c["msg_id"] = r["id"]
                c["time"] = r["timestamp"] if "timestamp" in have else None
                c["disposition"] = (disp_by_call.get(c["id"]) or
                                    (r["effect_disposition"] if "effect_disposition" in have else None))
                calls.append(c)
        calls.sort(key=lambda c: c["msg_id"])
        return calls[-limit:]

    def all_tool_calls(self, sid):
        """Every tool call of a session, oldest first (used once, to build the file ledger)."""
        have = set(self.cols("messages"))
        sel = self.select("messages", ["id", "tool_calls", "timestamp"])
        out = []
        for r in self.con.execute(f"SELECT {sel} FROM messages WHERE session_id=? AND role='assistant' "
                                  "AND tool_calls IS NOT NULL AND tool_calls NOT IN ('','[]') ORDER BY id", (sid,)):
            for c in parse_tool_calls(r["tool_calls"]):
                c["msg_id"] = r["id"]
                c["time"] = r["timestamp"] if "timestamp" in have else None
                c["disposition"] = None
                out.append(c)
        return out

    def max_message_id(self, sid):
        r = self.con.execute("SELECT MAX(id) m FROM messages WHERE session_id=?", (sid,)).fetchone()
        return (r["m"] or 0) if r else 0

    def last_message_time(self, sid):
        if "timestamp" not in self.cols("messages"):
            return None
        r = self.con.execute("SELECT MAX(timestamp) t FROM messages WHERE session_id=?", (sid,)).fetchone()
        return r["t"] if r else None


def parse_tool_calls(raw):
    """Tolerant parser: OpenAI-style [{id, function:{name, arguments:'{json}'}}] or flat variants."""
    if not raw:
        return []
    try:
        data = json.loads(raw) if isinstance(raw, (str, bytes)) else raw
    except Exception:
        return []
    if isinstance(data, dict):
        data = data.get("tool_calls", [data])
    out = []
    for item in data if isinstance(data, list) else []:
        if not isinstance(item, dict):
            continue
        fn = item.get("function") if isinstance(item.get("function"), dict) else item
        name = fn.get("name") or item.get("name") or item.get("tool_name") or "?"
        args = fn.get("arguments", fn.get("args", item.get("input", {})))
        if isinstance(args, str):
            try:
                args = json.loads(args)
            except Exception:
                args = {"_raw": args}
        if not isinstance(args, dict):
            args = {"_raw": str(args)}
        out.append({"id": item.get("id") or item.get("call_id"), "name": str(name), "args": args})
    return out


# --------------------------------------------------------------------------
# Command explainer (dictionary first, so explanations are instant and not guessed)
# --------------------------------------------------------------------------
SAFE_READ = {
    "ls": "Lists files in a folder", "dir": "Lists files in a folder", "cat": "Prints a file's contents",
    "type": "Prints a file's contents", "head": "Shows the start of a file", "tail": "Shows the end of a file",
    "echo": "Prints text", "pwd": "Shows the current folder", "cd": "Changes the working folder",
    "grep": "Searches text for a pattern", "findstr": "Searches text for a pattern", "find": "Searches for files",
    "where": "Locates a program", "which": "Locates a program", "whoami": "Shows the current user",
    "ver": "Shows the OS version", "tree": "Shows folder structure", "get-childitem": "Lists files in a folder",
    "get-content": "Prints a file's contents", "select-string": "Searches text for a pattern",
    "wc": "Counts lines/words", "sort": "Sorts lines", "date": "Shows the date", "env": "Shows environment variables",
    "set": "Shows or sets environment variables", "tasklist": "Lists running programs", "ps": "Lists running processes",
    "ping": "Tests network reachability", "nslookup": "Looks up a domain name", "sleep": "Waits",
    "start-sleep": "Waits", "timeout": "Waits", "pytest": "Runs the project's tests", "mypy": "Type-checks code",
    # PowerShell / shell helpers that only read or reformat output
    "get-item": "Checks details of a file or folder", "get-location": "Shows the current folder",
    "get-process": "Lists running programs", "get-service": "Lists services", "get-date": "Shows the date",
    "get-command": "Looks up a program", "get-help": "Shows help", "test-path": "Checks if a path exists",
    "resolve-path": "Resolves a path", "format-list": "Formats output", "format-table": "Formats output",
    "select-object": "Picks columns from output", "where-object": "Filters output", "sort-object": "Sorts output",
    "foreach-object": "Processes each result", "out-string": "Formats output", "measure-object": "Counts results",
    "write-output": "Prints text", "write-host": "Prints text", "convertto-json": "Formats output",
    "convertfrom-json": "Reads JSON", "get-filehash": "Computes a file checksum", "uname": "Shows system info",
    "hostname": "Shows the computer name", "systeminfo": "Shows system info", "uniq": "Removes duplicate lines",
    "cut": "Picks columns", "tr": "Replaces characters", "awk": "Processes text", "sed": "Edits streamed text",
    "xargs": "Passes results to another command", "stat": "Shows file details", "file": "Shows a file's type",
    "du": "Shows disk usage", "df": "Shows free disk space", "more": "Pages through text", "less": "Pages through text",
}
CMDS = {
    "mkdir": ("Creates a folder", "modifies"), "md": ("Creates a folder", "modifies"),
    "touch": ("Creates an empty file / updates its timestamp", "modifies"),
    "cp": ("Copies files", "modifies"), "copy": ("Copies files", "modifies"), "xcopy": ("Copies files", "modifies"),
    "robocopy": ("Copies/mirrors folders (can delete with /mir)", "modifies"),
    "mv": ("Moves or renames files", "modifies"), "move": ("Moves or renames files", "modifies"),
    "ren": ("Renames a file", "modifies"), "rename": ("Renames a file", "modifies"),
    "rm": ("Deletes files/folders", "delete"), "del": ("Deletes files", "delete"), "erase": ("Deletes files", "delete"),
    "rmdir": ("Deletes a folder", "delete"), "rd": ("Deletes a folder", "delete"),
    "remove-item": ("Deletes files/folders", "delete"),
    "chmod": ("Changes file permissions", "modifies"), "chown": ("Changes file owner", "modifies"),
    "icacls": ("Changes file permissions", "modifies"), "attrib": ("Changes file attributes", "modifies"),
    "kill": ("Stops a running process", "modifies"), "taskkill": ("Stops a running process", "modifies"),
    "stop-process": ("Stops a running process", "modifies"), "pkill": ("Stops processes by name", "modifies"),
    "curl": ("Makes a web request / downloads data", "network"), "wget": ("Downloads a file", "network"),
    "invoke-webrequest": ("Makes a web request / downloads", "network"), "iwr": ("Makes a web request / downloads", "network"),
    "invoke-restmethod": ("Calls a web API", "network"), "irm": ("Calls a web API", "network"),
    "ssh": ("Connects to a remote machine", "network"), "scp": ("Copies files to/from a remote machine", "network"),
    "python": ("Runs a Python program", "runs-code"), "python3": ("Runs a Python program", "runs-code"),
    "py": ("Runs a Python program", "runs-code"), "node": ("Runs a Node.js program", "runs-code"),
    "npx": ("Runs a Node package", "runs-code"), "uvicorn": ("Starts a Python web server", "runs-code"),
    "flask": ("Runs a Flask app", "runs-code"), "java": ("Runs a Java program", "runs-code"),
    "powershell": ("Starts PowerShell", "runs-code"), "pwsh": ("Starts PowerShell", "runs-code"),
    "cmd": ("Starts the Windows shell", "runs-code"), "bash": ("Starts a shell", "runs-code"),
    "sh": ("Starts a shell", "runs-code"), "start": ("Opens a program/file", "runs-code"),
    "sqlite3": ("Opens a SQLite database (can change data)", "modifies"),
    "psql": ("Connects to a PostgreSQL database (can change data)", "modifies"),
    "mysql": ("Connects to a MySQL database (can change data)", "modifies"),
    "reg": ("Reads/edits the Windows registry", "danger"), "regedit": ("Edits the Windows registry", "danger"),
    "netsh": ("Changes network/firewall settings", "danger"), "schtasks": ("Manages scheduled tasks", "danger"),
    "crontab": ("Manages scheduled jobs", "danger"), "shutdown": ("Shuts down / restarts the computer", "danger"),
    "format": ("Formats a disk", "danger"), "diskpart": ("Manages disks/partitions", "danger"),
    "sc": ("Manages Windows services", "danger"), "setx": ("Permanently sets an environment variable", "modifies"),
}
TWO = {
    "pip install": ("Installs Python packages", "install"), "pip3 install": ("Installs Python packages", "install"),
    "pip uninstall": ("Removes Python packages", "delete"), "uv pip": ("Manages Python packages", "install"),
    "uv add": ("Installs Python packages", "install"), "npm install": ("Installs Node packages", "install"),
    "npm i": ("Installs Node packages", "install"), "npm uninstall": ("Removes Node packages", "delete"),
    "yarn add": ("Installs Node packages", "install"), "pnpm add": ("Installs Node packages", "install"),
    "npm run": ("Runs a project script (build/dev server/tests)", "runs-code"),
    "npm start": ("Starts the project", "runs-code"), "npm test": ("Runs the project's tests", "runs-code"),
    "winget install": ("Installs a Windows program", "install"), "choco install": ("Installs a Windows program", "install"),
    "apt install": ("Installs system packages", "install"), "apt-get install": ("Installs system packages", "install"),
    "brew install": ("Installs a program", "install"), "cargo install": ("Installs a Rust program", "install"),
    "git status": ("Shows changed files in the repo", "safe"), "git diff": ("Shows code changes", "safe"),
    "git log": ("Shows commit history", "safe"), "git show": ("Shows a commit", "safe"),
    "git branch": ("Lists/creates branches", "safe"), "git add": ("Stages changes for commit", "modifies"),
    "git commit": ("Saves a commit in the repo", "modifies"), "git checkout": ("Switches branch / restores files", "modifies"),
    "git switch": ("Switches branch", "modifies"), "git pull": ("Downloads and merges remote changes", "network"),
    "git fetch": ("Downloads remote changes", "network"), "git clone": ("Downloads a repository", "network"),
    "git push": ("Uploads commits to a remote", "network"), "git merge": ("Merges branches", "modifies"),
    "git stash": ("Shelves local changes", "modifies"), "git reset": ("Moves HEAD / discards changes", "modifies"),
    "git clean": ("Deletes untracked files", "delete"),
    "docker ps": ("Lists containers", "safe"), "docker images": ("Lists images", "safe"),
    "docker run": ("Starts a container", "modifies"), "docker build": ("Builds an image", "modifies"),
    "docker compose": ("Runs a multi-container app", "modifies"), "docker rm": ("Deletes containers", "delete"),
    "docker rmi": ("Deletes images", "delete"), "docker exec": ("Runs a command inside a container", "modifies"),
}
SHELL_WRAPPERS = {"powershell", "pwsh", "cmd", "bash", "sh", "zsh"}
_SPLIT = re.compile(r"\s*(?:&&|\|\||;|\||\r?\n)\s*")
_ROOTISH = re.compile(r"(^|\s)(/|/\*|~|~/|[A-Za-z]:\\?|\\|%userprofile%|\$home)(\s|$)", re.I)


def _first_tokens(seg):
    toks = seg.strip().split()
    while toks and (re.match(r"^[A-Za-z_]\w*=", toks[0]) or toks[0].lower() in ("sudo", "call", "nohup", "time")):
        toks = toks[1:]
    if not toks:
        return "", ""
    t0 = os.path.basename(toks[0].strip("\"'").replace("\\", "/")).lower()
    t0 = re.sub(r"\.(exe|cmd|bat|ps1)$", "", t0)
    t1 = toks[1].lower() if len(toks) > 1 else ""
    return t0, t1


_REDIR = re.compile(r"(?<![\d&<])>{1,2}\s*(?!&|nul\b|/dev/null|\$null)([^\s|&;<>]+)", re.I)


def redirect_targets(cmd):
    return [m.group(1).strip("\"'") for m in _REDIR.finditer(cmd or "")]


def command_file_targets(cmd):
    """Best-effort list of files/folders a state-changing command points at."""
    out = []
    for seg in [s for s in _SPLIT.split(cmd or "") if s.strip()]:
        t0, t1 = _first_tokens(seg)
        two = f"{t0} {t1}".strip()
        r = TWO[two][1] if two in TWO else (CMDS[t0][1] if t0 in CMDS else "safe")
        if r not in ("modifies", "delete", "danger") or t0 in ("git", "docker", "psql", "mysql", "sqlite3"):
            continue
        toks = seg.strip().split()[1:]
        for tok in toks:
            tok = tok.strip("\"'")
            if not tok or tok.startswith(("-", "/")) and len(tok) <= 3 or "://" in tok:
                continue
            if tok.startswith("-") or tok.startswith(">"):
                continue
            out.append(tok)
    out += redirect_targets(cmd)
    return list(dict.fromkeys(out))


def explain_command(cmd, depth=0):
    """Returns (explanation, risk)."""
    cmd = (cmd or "").strip()
    if not cmd:
        return "Empty command", "safe"
    risk, notes = "safe", []
    low = cmd.lower()

    if re.search(r"(curl|wget|iwr|irm|invoke-webrequest|invoke-restmethod)\b.*\|\s*(bash|sh|iex|invoke-expression|python\w*)", low) \
            or re.search(r"\biex\b.*\b(iwr|irm|downloadstring|invoke-webrequest)", low):
        return "Downloads code from the internet and runs it immediately without review", "danger"

    for seg in [s for s in _SPLIT.split(cmd) if s.strip()]:
        t0, t1 = _first_tokens(seg)
        two = f"{t0} {t1}".strip()
        seg_low = seg.lower()
        if t0 in SHELL_WRAPPERS and depth < 2:
            m = re.search(r"(?:-command|-c|/c)\s+(.*)$", seg, re.I | re.S)
            if m:
                inner = m.group(1).strip().strip("\"'")
                e, r = explain_command(inner, depth + 1)
                notes.append(f"Runs a nested shell: {e}")
                risk = worse(risk, r)
                continue
        if t0 == "git" and "push" in seg_low and re.search(r"--force|\s-f(\s|$)", seg_low):
            notes.append("Force-pushes commits, can overwrite remote history"); risk = worse(risk, "danger"); continue
        if t0 == "git" and "reset" in seg_low and "--hard" in seg_low:
            notes.append("Hard-resets the repo, discarding uncommitted changes"); risk = worse(risk, "danger"); continue
        if t0 == "git" and "clean" in seg_low and re.search(r"-\w*f", seg_low):
            notes.append("Deletes untracked files from the repo"); risk = worse(risk, "danger"); continue
        if t0 in ("psql", "mysql", "sqlite3", "mongosh") and re.search(r"\bselect\b", seg_low) \
                and not re.search(r"\b(insert|update|delete|drop|alter|create|truncate)\b", seg_low):
            e, r = "Reads data from a database", "safe"
        elif two in TWO:
            e, r = TWO[two]
        elif t0 in ("python", "python3", "py") and t1 in ("-m",):
            mod = seg.split()[2] if len(seg.split()) > 2 else "?"
            e, r = f"Runs the Python module '{mod}'", ("install" if mod == "pip" and "install" in seg_low else "runs-code")
        elif t0 in ("python", "python3", "py") and t1 and not t1.startswith("-"):
            e, r = f"Runs the Python script {t1.strip(chr(34)+chr(39))}", "runs-code"
        elif t0 in ("python", "python3", "py") and t1 in ("--version", "-v"):
            e, r = "Checks the Python version", "safe"
        elif t0 in CMDS:
            e, r = CMDS[t0]
        elif t0 in SAFE_READ:
            e, r = SAFE_READ[t0], "safe"
        else:
            e, r = f"Runs '{t0}' (not in the built-in dictionary, check manually)", "runs-code"
        if r == "delete" and (re.search(r"\s-[a-z]*r[a-z]*", seg_low) or re.search(r"/s\b|-recurse", seg_low)):
            e = "Deletes a folder and everything inside it"
            if _ROOTISH.search(seg[len(seg.split()[0]):] + " "):
                e += " (target looks like a root/home folder!)"; r = "danger"
        notes.append(e)
        risk = worse(risk, r)

    if redirect_targets(cmd):
        notes.append("Writes output into a file")
        risk = worse(risk, "modifies")
    return "; ".join(dict.fromkeys(notes)) or "Runs a command", risk


# --------------------------------------------------------------------------
# Classification: what area is the agent working on
# --------------------------------------------------------------------------
PATH_KEYS = ("path", "file_path", "filepath", "file", "filename", "target", "dest", "destination",
             "old_path", "new_path", "paths")
CMD_KEYS = ("command", "cmd", "script")


def get_command(args):
    for k in CMD_KEYS:
        if isinstance(args.get(k), str):
            return args[k]
    return None


def get_paths(args):
    out = []
    for k in PATH_KEYS:
        v = args.get(k)
        if isinstance(v, str):
            out.append(v)
        elif isinstance(v, list):
            out += [x for x in v if isinstance(x, str)]
    return out


def tool_kind(name):
    n = name.lower()
    if re.search(r"terminal|shell|bash|exec|run_command|powershell", n):
        return "command"
    if re.search(r"write|patch|edit|create_file|apply|replace|append|save", n):
        return "write"
    if re.search(r"read|view|open_file|cat", n):
        return "read"
    if re.search(r"search_files|list|glob|grep|find", n):
        return "search"
    if n.startswith("mcp"):
        return "mcp"
    if re.search(r"web|browser|fetch|http|url", n):
        return "web"
    return "other"


AREA_RULES = [
    ("database", r"\b(psql|sqlite3?|mysql|mongosh|redis-cli|alembic|prisma|supabase|airtable)\b|\.sql\b|\.db\b|\bselect\b.+\bfrom\b"),
    ("frontend", r"\b(vite|webpack|next|nuxt|react|vue|svelte|tailwind|eslint)\b|\.(tsx|jsx|vue|svelte|css|scss|html)\b|\b(npm|yarn|pnpm)\s+(run\s+)?(dev|build|start)\b"),
    ("downloading", r"\b(curl|wget|iwr|irm|invoke-webrequest|git\s+clone|yt-dlp)\b"),
    ("installing", r"\b(pip3?|uv|npm|yarn|pnpm|winget|choco|apt(-get)?|brew|cargo)\s+(install|add|i)\b"),
    ("moving/copying files", r"\b(mv|move|cp|copy|xcopy|robocopy|ren|rename)\b"),
    ("deleting files", r"\b(rm|del|rmdir|rd|erase|remove-item)\b"),
    ("backend", r"\b(flask|fastapi|uvicorn|django|express|gunicorn|server)\b|\.(py|go|rs|java|php)\b"),
    ("git", r"\bgit\b"),
    ("docker", r"\bdocker\b"),
    ("automation (n8n)", r"\bn8n\b"),
]


def classify(call):
    name, args = call["name"], call["args"]
    kind = tool_kind(name)
    cmd = get_command(args)
    paths = get_paths(args)
    blob = " ".join([cmd or "", " ".join(paths)]).lower().strip()
    if kind == "mcp":
        return "external tool (MCP)", f"calling {name}"
    if kind == "read":
        return "reading files", ", ".join(paths)
    if kind == "search":
        return "searching files", ", ".join(paths)
    if re.search(r"vault|credential|secret|password|login", name.lower()):
        return "CREDENTIAL VAULT access", name
    for area, rx in AREA_RULES:
        if area == "backend" and kind == "command":
            rx = r"\b(flask|fastapi|uvicorn|django|express|gunicorn)\b"  # a .py in a command is just "a script"
        if re.search(rx, blob):
            if kind == "write" and area == "backend" and any(p.endswith((".py", ".js", ".sh", ".ps1", ".ts")) for p in paths):
                return "writing a script", ", ".join(paths)
            return area, blob[:80]
    if kind == "write":
        return ("writing a script" if any(p.lower().endswith((".py", ".js", ".sh", ".ps1", ".ts", ".bat")) for p in paths)
                else "writing/editing files"), ", ".join(paths)
    if kind == "read":
        return "reading files", ", ".join(paths)
    if kind == "search":
        return "searching files", ""
    if kind == "web":
        return "browsing the web", ""
    if kind == "command":
        t0, _ = _first_tokens(_SPLIT.split(cmd or "")[0] if cmd else "")
        if t0 in ("python", "python3", "py", "node"):
            return "running a script", cmd or ""
        if t0 in ("mkdir", "md", "touch"):
            return "creating files/folders", cmd or ""
        if t0 in SAFE_READ:
            return "inspecting files/system", cmd or ""
        return "running a command", cmd or ""
    return f"using tool '{name}'", ""


def fmt_time(ts):
    if not ts:
        return "--:--:--"
    try:
        return time.strftime("%H:%M:%S", time.localtime(float(ts)))
    except Exception:
        return str(ts)[:8]


def ago(ts):
    if not ts:
        return "unknown"
    try:
        s = int(time.time() - float(ts))
    except Exception:
        return "unknown"
    if s < 0:
        s = 0
    return f"{s}s ago" if s < 120 else f"{s // 60}m ago" if s < 7200 else f"{s // 3600}h ago"


# --------------------------------------------------------------------------
# The three functions
# --------------------------------------------------------------------------
def fn_status(h):
    sid, entry = h.active_session_id()
    if not sid:
        return {"summary": "No session found."}
    s = h.session(sid)
    calls = h.tool_calls(sid, limit=5)
    last_t = h.last_message_time(sid) or s.get("last_activity_at")
    idle = (time.time() - float(last_t)) if last_t else None
    out = {
        "session": sid, "surface": entry.get("surface"), "folder": redact(s.get("cwd")),
        "git_branch": s.get("git_branch"), "tool_calls_total": s.get("tool_call_count"),
        "last_activity": ago(last_t), "hermes_own_description": redact(s.get("last_activity_description")),
    }
    out["idle_seconds"] = int(idle) if idle is not None else None
    if not calls:
        out["summary"] = "No tool calls yet in this session (thinking or chatting)."
        out["area"] = "no tool calls yet"
        return out
    last = calls[-1]
    area, detail = classify(last)
    out["area"] = area
    parts = [f"Now: {area}" + (f" ({redact(detail)[:70]})" if detail else "")]
    recent = []
    for c in calls[:-1]:
        a, _ = classify(c)
        if a not in recent:
            recent.append(a)
    if recent:
        parts.append("earlier: " + ", ".join(recent[-3:]))
    if idle is not None and idle > 90:
        parts.append(f"[no activity for {int(idle)}s, may be idle or waiting for you]")
    out["summary"] = " | ".join(parts)
    out["recent"] = [{"time": fmt_time(c["time"]), "area": classify(c)[0], "tool": c["name"]} for c in calls]
    return out


def fn_commands(h, n=10):
    sid, _ = h.active_session_id()
    rows = []
    for c in h.tool_calls(sid, limit=n * 4):
        cmd = get_command(c["args"])
        if not cmd:
            continue
        expl, risk = explain_command(cmd)
        rows.append({"time": fmt_time(c["time"]), "ts": c["time"], "tool": c["name"], "risk": risk,
                     "command": redact(cmd), "does": expl, "hermes_effect_tag": c.get("disposition"),
                     "workdir": redact(c["args"].get("workdir") or c["args"].get("cwd") or "")})
    return rows[-n:]


def _git(cwd, *args):
    env = dict(os.environ, GIT_OPTIONAL_LOCKS="0")  # do not even refresh the index
    try:
        r = subprocess.run(["git", "-C", cwd, *args], capture_output=True, text=True, timeout=10, env=env)
        return r.stdout if r.returncode == 0 else None
    except Exception:
        return None


_ABS = re.compile(r"^([A-Za-z]:[\\/]|[\\/]|~)")


def abspath(p, base):
    if not p or _ABS.match(p) or not base:
        return p
    return str(Path(base) / p)


def fn_files(h):
    sid, _ = h.active_session_id()
    s = h.session(sid)
    cwd = s.get("cwd")
    calls = h.tool_calls(sid, limit=200)
    written, read, via_cmd = {}, {}, {}
    for c in calls:
        kind = tool_kind(c["name"])
        base = c["args"].get("workdir") or c["args"].get("cwd") or cwd
        for p in get_paths(c["args"]):
            if kind == "write":
                written[abspath(p, base)] = fmt_time(c["time"])
            elif kind in ("read", "search"):
                read[abspath(p, base)] = fmt_time(c["time"])
        cmd = get_command(c["args"])
        if cmd:
            _, risk = explain_command(cmd)
            if risk in ("modifies", "delete", "danger"):
                for tok in command_file_targets(cmd):
                    via_cmd[abspath(tok, base)] = f"{fmt_time(c['time'])} [{risk}]"
    access = {"session_folder": redact(cwd), "git_repo_root": redact(s.get("git_repo_root"))}
    cfg = h.dir / "config.yaml"
    if not cfg.exists():
        cfg = h.base / "config.yaml"
    if cfg.exists():
        keep = re.compile(r"^\s*(backend|env_type|terminal|cwd|docker_\w+|volumes?|mounts?|sandbox\w*|allowed_\w+|workdir)\s*:", re.I)
        lines = [redact(l.rstrip()) for l in cfg.read_text(encoding="utf-8", errors="ignore").splitlines() if keep.match(l)]
        access["config_yaml_terminal_lines"] = lines[:20]
    git = {}
    root = s.get("git_repo_root") or cwd
    if root and Path(root).exists():
        top = (_git(root, "rev-parse", "--show-toplevel") or "").strip()
        if top:
            tp = Path(top).resolve()
            if tp == Path.home().resolve() or len(tp.parts) <= 1:
                git["skipped"] = (f"{tp} is a very broad git repo (your home/drive folder), so git status "
                                  "would list unrelated personal files. Work inside a project folder for git diffs.")
            else:
                st = _git(root, "status", "--porcelain")
                if st is not None:
                    lines = st.splitlines()
                    git["changed_files"] = [redact(l) for l in lines[:50]] + \
                        ([f"... and {len(lines) - 50} more"] if len(lines) > 50 else [])
                    git["diff_stat"] = redact((_git(root, "diff", "--stat") or "").strip()[-1500:])
    return {"can_access": access, "written_by_file_tools": {redact(k): v for k, v in written.items()},
            "read_or_searched": {redact(k): v for k, v in read.items()},
            "touched_via_commands_approx": {redact(k): v for k, v in list(via_cmd.items())[:40]},
            "git_changes": git,
            "note": "'Read' only covers what appears in tool calls. Reads done inside scripts/commands are invisible here."}


# ---------------------------------------------------------------------------
# Plain-English translation of commands (what a non-technical person would understand)
# ---------------------------------------------------------------------------
RISK_TEXT = {
    "safe": "Safe: it only looks, nothing is changed",
    "runs-code": "Runs a program on your computer",
    "modifies": "Changes something on your computer",
    "network": "Uses the internet",
    "install": "Installs software",
    "delete": "Deletes things, this can't be undone",
    "danger": "Dangerous: could harm your computer",
}
_TOK = re.compile(r'"(?:[^"\\]|\\.)*"|\'[^\']*\'|\S+')
_HOME = re.compile(r"^(?:[A-Za-z]:|/[a-z])?[\\/]+(?:Users|home)[\\/]+[^\\/]+", re.I)
_PIPE = re.compile(r"(?<!\|)\|(?!\|)")
_HELPERS = {"select-object", "format-list", "format-table", "format-custom", "sort-object", "where-object",
            "foreach-object", "out-string", "measure-object", "select", "sort", "uniq", "wc", "cut", "tr", "awk",
            "sed", "head", "tail", "tee", "xargs", "convertto-json", "convertfrom-json", "out-null", "more", "less"}


def _unq(t):
    t = (t or "").strip()
    return t[1:-1] if len(t) >= 2 and t[0] == t[-1] and t[0] in "\"'" else t


def nice_path(p):
    p = re.sub(r"\\{2,}", r"\\", _unq(p))
    if re.fullmatch(r"[A-Za-z]:[\\/]*", p):
        return f"the whole {p[0].upper()}: drive"
    m = _HOME.match(p)
    if m:
        rest = p[m.end():].lstrip("\\/")
        p = "your home folder" + (" / " + rest.replace("\\", "/") if rest else "")
    if len(p) > 46:
        parts = [x for x in re.split(r"[\\/]", p) if x]
        p = "…/" + "/".join(parts[-2:])
    return p or "the current folder"


def _param(toks, *names):
    for i, t in enumerate(toks):
        if t.startswith("-") and t.lstrip("-").lower() in names and i + 1 < len(toks):
            return _unq(toks[i + 1])
    return None


def _flag(toks, *names):
    return any((t.startswith("-") or (t.startswith("/") and len(t) <= 3)) and t.lstrip("-/").lower() in names
               for t in toks)


def _unwrap(cmd):
    for _ in range(2):
        m = re.match(r"^\s*(?:[\w:\\/.\-]*[\\/])?(?:powershell|pwsh)(?:\.exe)?\s+(.*)$", cmd, re.I | re.S)
        if m:
            m2 = re.search(r"(?:^|\s)-(?:command|c)\s+(.*)$", m.group(1), re.I | re.S)
            cmd = _unq((m2.group(1) if m2 else m.group(1)).strip())
            continue
        m = re.match(r"^\s*(?:cmd(?:\.exe)?\s+/[cks]|(?:ba|z)?sh\s+-l?c)\s+(.*)$", cmd, re.I | re.S)
        if m:
            cmd = _unq(m.group(1).strip())
            continue
        break
    return cmd


def _host(url):
    m = re.search(r"https?://([^/\s\"']+)", url or "")
    return m.group(1).split("@")[-1] if m else None


def _describe(seg):
    seg = re.sub(r"\s\d*>{1,2}&?\s*\S+", "", " " + seg).strip()  # ignore "> file" / "2>&1" when describing
    toks = _TOK.findall(seg.strip())
    while toks and (re.match(r"^[A-Za-z_]\w*=", toks[0]) or toks[0].lower() in ("sudo", "call", "nohup", "time")):
        toks = toks[1:]
    if not toks:
        return ""
    t0 = os.path.basename(_unq(toks[0]).replace("\\", "/")).lower()
    t0 = re.sub(r"\.(exe|cmd|bat|ps1)$", "", t0)
    args = toks[1:]
    pos = [_unq(a) for a in args if not (a.startswith("-") or (a.startswith("/") and len(a) <= 3))]
    first = nice_path(pos[0]) if pos else None
    rec = _flag(args, "r", "rf", "fr", "recurse", "s", "force", "recursive")
    sub = pos[0].lower() if pos else ""

    if t0 in ("ls", "dir", "get-childitem", "gci", "tree"):
        pat = _param(args, "filter", "include", "name")
        where = nice_path(_param(args, "path", "literalpath") or (pos[0] if pos else ""))
        if rec and pat:
            kind = "folders" if _flag(args, "directory", "ad") else "files and folders"
            return f"Searching {where} for {kind} named '{_unq(pat)}'"
        return f"Looking at what is inside {where}"
    if t0 == "find":
        where = nice_path(pos[0]) if pos else "the current folder"
        pat = _param(args, "iname", "name")
        kind = {"d": "folders", "f": "files"}.get((_param(args, "type") or "").lower(), "files and folders")
        return f"Searching {where} for {kind}" + (f" named '{pat}'" if pat else "")
    if t0 in ("cat", "type", "get-content", "gc", "head", "tail"):
        return f"Reading the file {nice_path(_param(args, 'path', 'literalpath') or (pos[0] if pos else ''))}"
    if t0 in ("grep", "egrep", "rg", "findstr", "select-string", "sls"):
        return f"Searching for the text '{pos[0] if pos else '?'}'" + (f" in {nice_path(pos[1])}" if len(pos) > 1 else "")
    if t0 in ("echo", "write-output", "write-host", "print"):
        return "Printing a message on the screen"
    if t0 in ("pwd", "get-location"):
        return "Checking which folder it is in"
    if t0 in ("cd", "chdir", "set-location", "pushd"):
        return f"Moving into {first}" if first and first.startswith(("your home", "the ")) else f"Moving into the folder {first or 'home'}"
    if t0 in ("mkdir", "md") or (t0 == "new-item" and _flag(args, "itemtype") and "dir" in seg.lower()):
        return f"Creating a folder named {first or '?'}"
    if t0 in ("touch", "new-item"):
        return f"Creating an empty file {first or ''}".strip()
    if t0 in ("cp", "copy", "xcopy", "robocopy", "copy-item"):
        return f"Copying {first or '?'}" + (f" to {nice_path(pos[1])}" if len(pos) > 1 else "")
    if t0 in ("mv", "move", "move-item", "ren", "rename", "rename-item"):
        return f"Moving or renaming {first or '?'}" + (f" to {nice_path(pos[1])}" if len(pos) > 1 else "")
    if t0 in ("rm", "del", "erase", "rmdir", "rd", "remove-item"):
        return f"Deleting {first or 'something'}" + (" and everything inside it" if rec else "")
    if t0 in ("python", "python3", "py"):
        if _flag(args, "version", "v"):
            return "Checking the Python version"
        if pos and pos[0].lower() == "-m" or (args and args[0] == "-m"):
            mod = _unq(args[1]) if len(args) > 1 else "?"
            return "Installing Python packages" if mod == "pip" else f"Running the Python tool '{mod}'"
        if args and args[0] == "-c":
            return "Running a small piece of Python code"
        return f"Running the Python program {first}" if first else "Starting Python"
    if t0 == "node":
        return f"Running the JavaScript program {first}" if first else "Starting Node.js"
    if t0 in ("pip", "pip3", "uv"):
        pk = [p for p in pos[1:] if not p.startswith("-")] if sub in ("install", "add") else []
        if sub in ("install", "add"):
            return ("Installing the Python package" + ("s " if len(pk) > 1 else " ") + ", ".join(pk[:4])) if pk else "Installing Python packages"
        return "Listing installed Python packages" if sub in ("list", "freeze") else "Managing Python packages"
    if t0 in ("npm", "yarn", "pnpm", "npx"):
        if sub in ("install", "i", "add"):
            pk = pos[1:4]
            return "Installing the packages " + ", ".join(pk) if pk else "Installing the project's packages"
        run = pos[1].lower() if sub == "run" and len(pos) > 1 else sub
        return {"dev": "Starting the project in development mode", "start": "Starting the project",
                "build": "Building the project", "test": "Running the project's tests"}.get(run, f"Running the project command '{run}'")
    if t0 == "git":
        return {"status": "Checking which files changed in the project", "diff": "Looking at the code changes",
                "log": "Looking at the project's history", "add": "Preparing changes to be saved",
                "commit": "Saving a snapshot (commit) of the changes", "push": "Uploading changes to the online repository",
                "pull": "Downloading updates from the online repository", "fetch": "Checking for updates online",
                "clone": "Downloading a copy of a project", "checkout": "Switching branch or restoring files",
                "switch": "Switching branch", "branch": "Looking at or creating branches",
                "merge": "Merging branches together", "stash": "Setting changes aside for later",
                "reset": "Undoing changes in the project", "clean": "Deleting untracked files from the project"}.get(sub, f"Using git ({sub})" if sub else "Using git")
    if t0 in ("curl", "wget", "iwr", "irm", "invoke-webrequest", "invoke-restmethod"):
        host = _host(seg) or "a web address"
        if _flag(args, "o", "outfile", "output") or t0 == "wget":
            return f"Downloading a file from {host}"
        if re.search(r"-(?:X|Method)\s+(?:POST|PUT|PATCH)|\s-d\s|--data|-Body", seg, re.I):
            return f"Sending data to {host}"
        return f"Fetching data from {host}"
    if t0 == "docker":
        return {"ps": "Listing running containers", "run": "Starting a container", "build": "Building a container image",
                "compose": "Running the app's containers", "exec": "Running a command inside a container",
                "images": "Listing container images", "stop": "Stopping a container", "rm": "Deleting a container"}.get(sub, "Using Docker")
    if t0 in ("psql", "mysql", "sqlite3", "mongosh"):
        low = seg.lower()
        if re.search(r"\b(insert|update|delete|drop|alter|create|truncate)\b", low):
            return "Changing data in a database"
        return "Reading data from a database" if "select" in low else "Talking to a database"
    if t0 in ("taskkill", "kill", "stop-process", "pkill"):
        return "Stopping a running program"
    if t0 in ("tasklist", "ps", "get-process"):
        return "Listing the programs that are running"
    if t0 in ("whoami",):
        return "Checking which user it is running as"
    if t0 in ("ver", "uname", "systeminfo", "hostname", "get-computerinfo"):
        return "Checking information about this computer"
    if t0 in ("where", "which", "get-command"):
        return f"Looking up where {first or 'a program'} is installed"
    if t0 in ("env", "set", "printenv", "get-item") and t0 != "get-item":
        return "Looking at environment settings"
    if t0 == "get-item":
        return f"Checking details of {nice_path(_param(args, 'path', 'literalpath') or (pos[0] if pos else ''))}"
    if t0 in ("test-path",):
        return f"Checking whether {first or 'a path'} exists"
    if t0 == "ping":
        return f"Testing the network connection to {first or 'a server'}"
    if t0 in ("sleep", "start-sleep", "timeout"):
        return "Waiting a moment"
    if t0 in ("setx", "reg", "regedit", "schtasks", "crontab", "netsh", "sc", "shutdown", "format", "diskpart"):
        return {"shutdown": "Shutting down or restarting the computer", "format": "Formatting a disk"}.get(t0, "Changing a Windows system setting")
    if t0 in ("chmod", "chown", "icacls", "attrib"):
        return f"Changing permissions of {first or 'a file'}"
    if t0 in ("start", "explorer", "invoke-item", "open", "xdg-open"):
        return f"Opening {first or 'something'}"
    if t0 in ("code", "notepad"):
        return f"Opening {first or 'an editor'}"
    if t0 in ("pytest",):
        return "Running the project's tests"
    if t0 in ("ssh", "scp"):
        return "Connecting to another computer" if t0 == "ssh" else "Copying files to or from another computer"
    return f"Running a program called '{t0}'"


def humanize(cmd):
    """Plain-English one-liner for a shell command (no jargon, no tool-speak)."""
    cmd = (cmd or "").strip()
    if not cmd:
        return "Running an empty command"
    if re.search(r"(curl|wget|iwr|irm|invoke-webrequest|invoke-restmethod)\b.*\|\s*(bash|sh|iex|invoke-expression|python\w*)", cmd, re.I):
        return "Downloading a program from the internet and running it immediately"
    cmd = _unwrap(cmd)
    steps = []
    for stage in [s for s in re.split(r"&&|\|\||;|\r?\n", cmd) if s.strip()]:
        parts = [p for p in _PIPE.split(stage) if p.strip()]
        main = _describe(parts[0])
        if not main:
            continue
        rest = [p for p in parts[1:] if p.strip()]
        helpers = [p for p in rest if _TOK.findall(p.strip())[0].lower() in _HELPERS]
        if helpers and len(helpers) == len(rest):
            main += " and picking out the useful parts" if any("where" in h.lower() or "select" in h.lower() or "grep" in h.lower() for h in helpers) else ""
        elif rest:
            main += ", then " + _describe(rest[0])[:1].lower() + _describe(rest[0])[1:]
        tg = redirect_targets(stage)
        if tg:
            if _TOK.findall(parts[0])[0].lower() in ("echo", "write-output", "write-host", "printf"):
                main = f"Writing text into the file {nice_path(tg[0])}"
            else:
                main += f", saving the result into {nice_path(tg[0])}"
        steps.append(main)
    if not steps:
        return "Running a command"
    text = steps[0] if len(steps) == 1 else "; then ".join(s[:1].lower() + s[1:] if i else s for i, s in enumerate(steps[:4]))
    return text[:170] + ("…" if len(text) > 170 else "")


AREA_TITLE = {
    "database": "Working on the database", "frontend": "Working on the frontend", "backend": "Working on the backend",
    "downloading": "Downloading something", "installing": "Installing packages", "moving/copying files": "Moving or copying files",
    "deleting files": "Deleting files", "git": "Using git", "docker": "Using Docker", "automation (n8n)": "Using n8n",
    "writing a script": "Writing a script", "writing/editing files": "Writing a file", "reading files": "Reading a file",
    "searching files": "Searching files", "running a script": "Running a script",
    "creating files/folders": "Creating files or folders", "inspecting files/system": "Looking around the system",
    "running a command": "Running a command", "browsing the web": "Browsing the web",
    "external tool (MCP)": "Using an external tool", "CREDENTIAL VAULT access": "Using the saved-logins vault",
}


_VERB_TITLE = {
    "searching": "Searching files", "looking": "Looking around", "listing": "Looking around", "reading": "Reading a file",
    "creating": "Creating something", "installing": "Installing software", "running": "Running a program",
    "deleting": "Deleting files", "downloading": "Using the internet", "fetching": "Using the internet",
    "sending": "Using the internet", "contacting": "Using the internet", "checking": "Checking something",
    "moving": "Moving files", "copying": "Copying files", "writing": "Writing to a file", "opening": "Opening something",
    "stopping": "Stopping a program", "starting": "Starting the project", "building": "Building the project",
    "testing": "Testing the connection", "changing": "Changing a setting", "printing": "Showing a message",
    "waiting": "Waiting", "saving": "Saving changes", "uploading": "Uploading changes", "preparing": "Preparing changes",
    "switching": "Switching branch", "merging": "Merging branches", "undoing": "Undoing changes",
    "connecting": "Connecting to another computer", "shutting": "Shutting down", "formatting": "Formatting a disk",
    "talking": "Using a database", "using": "Using a tool", "downloading a program": "Using the internet",
}
_KEEP_AREA_TITLE = {"database", "frontend", "backend", "docker", "git", "automation (n8n)"}


def call_to_event(c):
    """One tool call -> one feed message (plain-language, redacted)."""
    name, args = c["name"], c["args"]
    kind = tool_kind(name)
    cmd = get_command(args)
    area, detail = classify(c)
    paths = get_paths(args)
    ev = {"key": c.get("id") or f"{c['msg_id']}:{name}:{hash(json.dumps(args, sort_keys=True, default=str))}",
          "msg_id": c["msg_id"], "ts": c["time"], "time": fmt_time(c["time"]), "tool": name,
          "title": AREA_TITLE.get(area, area[:1].upper() + area[1:]), "area": area,
          "kind": "other", "detail": "", "explain": "", "risk": "safe"}
    if area == "CREDENTIAL VAULT access":
        ev.update(kind="other", detail=name, explain="Touches saved logins or passwords. Make sure you asked for this.", risk="danger")
        ev["plain"] = "Using the saved-logins vault (passwords or logins)"
    elif cmd:
        expl, risk = explain_command(cmd)
        ev.update(kind="command", detail=redact(cmd), explain=expl, risk=risk)
        ev["plain"] = redact(humanize(cmd))
        ev["raw_label"] = "Exact command: "
        if area not in _KEEP_AREA_TITLE:
            ev["title"] = ("Running a script" if ev["plain"].startswith(("Running the Python program", "Running the JavaScript program"))
                           else _VERB_TITLE.get(ev["plain"].split(" ", 1)[0].lower(), ev["title"]))
    elif kind == "write":
        full = redact(", ".join(abspath(p, args.get("workdir") or "") for p in paths))
        ev.update(kind="file", detail=full, explain="Created or changed this file", risk="modifies")
        ev["plain"] = f"Created or changed {_base(paths)}"
        ev["raw_label"] = "Full path: "
    elif kind in ("read", "search"):
        ev.update(kind="file", detail=redact(", ".join(paths)), explain="Looked at this" if paths else "", risk="safe")
        ev["plain"] = (f"Opened {_base(paths)} to read it" if kind == "read" else "Searched through files") if paths or kind == "read" else "Searched through files"
        ev["raw_label"] = "Full path: "
    elif kind == "mcp":
        ev.update(detail=re.sub(r"^mcp__", "", name).replace("__", " / "), explain="Called a tool from a connected server")
        ev["plain"] = "Used a tool from a connected service"
        ev["raw_label"] = "Tool: "
    else:
        ev.update(detail=redact(", ".join(paths) or ", ".join(f"{k}={str(v)[:40]}" for k, v in list(args.items())[:2])))
        ev["plain"] = f"Used the '{name}' tool"
        ev["raw_label"] = "Details: "
    ev["risk_text"] = RISK_TEXT.get(ev["risk"], "")
    ev["raw"] = ev["detail"] if ev["detail"] and ev["detail"] != ev["plain"] else ""
    return ev


def _base(paths):
    names = [re.split(r"[\\/]", _unq(p).rstrip("\\/"))[-1] for p in paths if p]
    return ", ".join(n for n in names if n)[:80] or "a file"


def fn_feed(h, sid, last_id=0, first_limit=12, seen=None, ledger=None, cwd=None):
    """New feed messages since last_id. Returns (events, new_last_id).
    First call (last_id == 0) reads the WHOLE session so the file ledger is complete, but only returns the last
    `first_limit` messages for the feed."""
    seen = seen if seen is not None else set()
    mx = h.max_message_id(sid)
    first = last_id == 0
    calls = h.all_tool_calls(sid) if first else h.tool_calls(sid, limit=60, after_id=last_id)
    fresh = []
    for c in calls:
        key = c.get("id") or f"{c['msg_id']}:{c['name']}:{hash(json.dumps(c['args'], sort_keys=True, default=str))}"
        if key in seen:
            continue
        seen.add(key)
        if ledger is not None:
            ledger.add_call(c, cwd)
        fresh.append(c)
    if first:
        fresh = fresh[-first_limit:]
    return [call_to_event(c) for c in fresh], max(last_id, mx)


# ---------------------------------------------------------------------------
# File ledger: which files did the agent see / read / change / delete in this session
# ---------------------------------------------------------------------------
_READ_CMDS = {"cat", "type", "get-content", "gc", "head", "tail", "more", "less", "bat", "nl", "wc", "md5sum", "sha256sum",
              "get-filehash", "stat", "file"}
_SEEN_CMDS = {"ls", "dir", "get-childitem", "gci", "tree", "find", "fd", "du", "get-item", "gi", "test-path", "resolve-path"}
_WRITE_CMDS = {"set-content", "add-content", "out-file", "tee", "tee-object"}
_SCRIPT_EXT = (".py", ".js", ".ts", ".ps1", ".sh", ".bat", ".cmd", ".rb", ".php")


def _norm_path(p):
    p = re.sub(r"\\{2,}", r"\\", _unq(p or "").strip())
    m = re.match(r"^/([a-zA-Z])/(.*)$", p)          # Git-Bash style /c/Users/x -> C:/Users/x
    if m:
        p = f"{m.group(1).upper()}:/{m.group(2)}"
    return p


def _join(base, p):
    p = _norm_path(p)
    if not p or _ABS.match(p) or not base:
        return p
    base = _norm_path(base)
    sep = "\\" if re.match(r"^[A-Za-z]:", base) else "/"
    return base.rstrip("\\/") + sep + p.lstrip(".\\/") if p.startswith(("./", ".\\")) else base.rstrip("\\/") + sep + p


def _pkey(p):
    return re.sub(r"/+", "/", p.replace("\\", "/")).rstrip("/").lower()


def _pdisp(p):
    p = _norm_path(p)
    m = _HOME.match(p.replace("/", "\\")) if re.match(r"^[A-Za-z]:", p) else _HOME.match(p)
    if m:
        rest = p[m.end():].lstrip("\\/")
        p = "~" + (("\\" if re.match(r"^[A-Za-z]:", p) else "/") + rest if rest else "")
    if re.match(r"^([A-Za-z]:|~\\)", p):
        p = p.replace("/", "\\")
    return redact(p)


def command_file_actions(cmd, base=None):
    """[(path, action, note)] a shell command is going to do. action: seen/read/changed/created/moved/deleted."""
    out = []
    cmd = _unwrap(cmd or "")
    for stage in [s for s in re.split(r"&&|\|\||;|\r?\n", cmd) if s.strip()]:
        for tgt in redirect_targets(stage):
            out.append((_join(base, tgt), "created", "written by redirect"))
        for part in [p for p in _PIPE.split(stage) if p.strip()]:
            seg = re.sub(r"\s\d*>{1,2}&?\s*\S+", "", " " + part).strip()
            toks = _TOK.findall(seg)
            while toks and (re.match(r"^[A-Za-z_]\w*=", toks[0]) or toks[0].lower() in ("sudo", "call", "nohup", "time")):
                toks = toks[1:]
            if not toks:
                continue
            t0 = os.path.basename(_unq(toks[0]).replace("\\", "/")).lower()
            t0 = re.sub(r"\.(exe|cmd|bat|ps1)$", "", t0)
            args = toks[1:]
            pos = [_unq(a) for a in args if not (a.startswith("-") or (a.startswith("/") and len(a) <= 3))]
            pos = [p for p in pos if "://" not in p]
            pth = _param(args, "path", "literalpath", "filepath")
            add = lambda ps, act, note="": out.extend((_join(base, p), act, note) for p in ps if p)
            if t0 in _SEEN_CMDS:
                add([pth] if pth else (pos[:1] or [base or "."]), "seen")
            elif t0 in _READ_CMDS:
                add([pth] if pth else pos, "read")
            elif t0 in ("grep", "egrep", "rg", "findstr", "select-string", "sls"):
                add(pos[1:], "read")
            elif t0 in _WRITE_CMDS:
                add([pth] if pth else pos[:1], "changed")
            elif t0 in ("rm", "del", "erase", "rmdir", "rd", "remove-item"):
                add([pth] if pth else pos, "deleted")
            elif t0 in ("mkdir", "md", "touch", "new-item"):
                add([pth] if pth else pos, "created")
            elif t0 in ("cp", "copy", "xcopy", "robocopy", "copy-item") and len(pos) >= 2:
                add(pos[:-1], "read", f"copied to {_pdisp(_join(base, pos[-1]))}")
                add(pos[-1:], "created", "copy")
            elif t0 in ("mv", "move", "move-item", "ren", "rename", "rename-item") and len(pos) >= 2:
                add(pos[:-1], "moved", f"moved to {_pdisp(_join(base, pos[-1]))}")
                add(pos[-1:], "created", "moved here")
            elif t0 in ("python", "python3", "py", "node") and pos and pos[0].lower().endswith(_SCRIPT_EXT):
                add(pos[:1], "read", "ran it")
            elif t0 in ("sed",) and _flag(args, "i") and pos:
                add(pos[-1:], "changed")
    return out


def file_actions(c, cwd=None):
    name, args = c["name"], c["args"]
    base = args.get("workdir") or args.get("cwd") or cwd
    kind = tool_kind(name)
    paths = get_paths(args)
    out = []
    if kind == "write":
        out += [(_join(base, p), "changed", "") for p in paths]
    elif kind == "read":
        out += [(_join(base, p), "read", "") for p in paths]
    elif kind == "search":
        out += [(_join(base, p), "seen", "") for p in (paths or ([base] if base else []))]
    cmd = get_command(args)
    if cmd:
        out += command_file_actions(cmd, base)
    return out


def fmt_when(ts):
    try:
        t = time.localtime(float(ts))
    except Exception:
        return ""
    return time.strftime("%H:%M", t) if time.strftime("%Y%m%d", t) == time.strftime("%Y%m%d") else time.strftime("%b %d %H:%M", t)


SECTIONS = (("deleted", ("deleted",)), ("changed", ("changed", "created", "moved")), ("read", ("read",)), ("seen", ("seen",)))


class FileLedger:
    """Remembers every file the agent touched in a session and how."""

    def __init__(self):
        self.files, self.version = {}, 0

    def add_call(self, c, cwd=None):
        for path, action, note in file_actions(c, cwd):
            key = _pkey(path)
            if not key or key in (".", "*"):
                continue
            e = self.files.setdefault(key, {"path": _pdisp(path), "n": {}, "last": {}, "notes": {}})
            e["n"][action] = e["n"].get(action, 0) + 1
            e["last"][action] = c.get("time") or 0
            if note:
                e["notes"][action] = note
            self.version += 1

    def report(self, limit=40):
        out = {"totals": {}}
        for sec, acts in SECTIONS:
            rows = []
            for e in self.files.values():
                hit = [a for a in acts if a in e["n"]]
                if not hit:
                    continue
                last = max(float(e["last"].get(a) or 0) for a in hit)
                nt = e["notes"]
                if sec == "changed":
                    if "moved" in hit:
                        note = nt.get("moved", "moved away")
                    elif "created" in hit and "changed" not in hit:
                        note = {"moved here": "moved here", "copy": "copy created",
                                "written by redirect": "created (saved output)"}.get(nt.get("created"), "created")
                    else:
                        note = "changed"
                elif sec == "read":
                    note = nt.get("read", "") if nt.get("read", "").startswith(("copied", "ran")) else ""
                else:
                    note = ""
                rows.append({"path": e["path"], "count": sum(e["n"][a] for a in hit), "last_ts": last,
                             "when": fmt_when(last), "note": note})
            rows.sort(key=lambda r: r["last_ts"], reverse=True)
            out["totals"][sec] = len(rows)
            out[sec] = rows[:limit]
            out[sec + "_more"] = max(len(rows) - limit, 0)
        return out


def fn_doctor(h):
    print(f"Hermes base   : {h.base}")
    print(f"Profile       : {h.profile}")
    print(f"state.db      : {h.db_path} ({h.db_path.stat().st_size // 1024} KB)")
    sid, entry = h.active_session_id()
    print(f"Active session: {sid} (surface={entry.get('surface')}, pid={entry.get('pid')})")
    for col in ("effect_disposition", "display_kind"):
        if col in h.cols("messages"):
            vals = [tuple(r) for r in h.con.execute(f"SELECT {col}, COUNT(*) FROM messages GROUP BY 1 ORDER BY 2 DESC LIMIT 12")]
            print(f"messages.{col}: {vals}")
    s = h.session(sid)
    print("session.last_activity_description:", repr(redact(s.get("last_activity_description"))))
    print("session.tool_names (first 200 chars):", redact(str(s.get("tool_names"))[:200]))
    r = h.con.execute("SELECT tool_calls FROM messages WHERE session_id=? AND tool_calls IS NOT NULL AND tool_calls NOT IN ('','[]') "
                      "ORDER BY id DESC LIMIT 1", (sid,)).fetchone()
    if r:
        parsed = parse_tool_calls(r["tool_calls"])
        print("\nLatest tool_calls row, outer shape (values hidden):")
        try:
            raw = json.loads(r["tool_calls"])
            first = raw[0] if isinstance(raw, list) and raw else raw
            print("  keys:", list(first.keys()) if isinstance(first, dict) else type(first).__name__)
            if isinstance(first, dict) and isinstance(first.get("function"), dict):
                print("  function keys:", list(first["function"].keys()))
        except Exception as e:
            print("  could not parse as JSON:", e)
        print("  parsed OK ->", [(c["name"], sorted(c["args"].keys())) for c in parsed])
    else:
        print("\nNo tool_calls rows in the active session yet. Give Hermes a small task and re-run.")
    print("\nParser self-test on last 5 tool calls:")
    for c in h.tool_calls(sid, limit=5):
        print(f"  {fmt_time(c['time'])} {c['name']:<14} -> {classify(c)[0]}  | disposition={c['disposition']}")
    print("\nIf anything above looks wrong (empty parsed list, ? tool names), send me this output.")


# --------------------------------------------------------------------------
# Output
# --------------------------------------------------------------------------
def print_status(d):
    print("\n" + d["summary"] + "\n")
    for k in ("folder", "git_branch", "last_activity", "tool_calls_total", "hermes_own_description"):
        if d.get(k) not in (None, ""):
            print(f"  {k.replace('_', ' '):<22}{d[k]}")
    for r in d.get("recent", []):
        print(f"    {r['time']}  {r['area']:<22} ({r['tool']})")


def print_commands(rows):
    if not rows:
        print("\nNo shell commands in the current session yet.")
    for r in rows:
        print(f"\n{r['time']}  [{r['risk'].upper()}]  {r['command']}")
        print(f"          -> {r['does']}")
        if r["workdir"]:
            print(f"          in {r['workdir']}")
        if r["hermes_effect_tag"] not in (None, "", "unknown"):
            print(f"          (Hermes tag: {r['hermes_effect_tag']})")


def print_files(d):
    print("\nCAN ACCESS")
    for k, v in d["can_access"].items():
        if isinstance(v, list):
            for line in v:
                print(f"  config: {line.strip()}")
        elif v:
            print(f"  {k}: {v}")
    for title, key in (("WRITTEN/EDITED (file tools)", "written_by_file_tools"),
                       ("READ/SEARCHED (file tools)", "read_or_searched"),
                       ("TOUCHED VIA COMMANDS (approximate)", "touched_via_commands_approx")):
        print(f"\n{title}")
        for p, t in d[key].items():
            print(f"  {t}  {p}")
        if not d[key]:
            print("  (none)")
    g = d["git_changes"]
    print("\nGIT CHANGES IN WORKING FOLDER")
    if g.get("skipped"):
        print("  " + g["skipped"])
    elif g:
        print("\n".join("  " + l for l in g["changed_files"]) or "  (clean)")
        if g.get("diff_stat"):
            print(g["diff_stat"])
    else:
        print("  (folder is not a git repo, so no reliable diff. A file-watcher would cover this.)")
    print("\n" + d["note"])


def watch(h):
    sid, _ = h.active_session_id()
    seen = 0
    row = h.con.execute("SELECT MAX(id) m FROM messages WHERE session_id=?", (sid,)).fetchone()
    seen = row["m"] or 0
    print(f"Watching session {sid}. Ctrl+C to stop. (read-only)\n")
    while True:
        new_sid, _ = h.active_session_id()
        if new_sid != sid:
            sid, seen = new_sid, 0
            print(f"--- new session {sid} ---")
        for c in h.tool_calls(sid, limit=50, after_id=seen):
            seen = max(seen, c["msg_id"])
            area, detail = classify(c)
            cmd = get_command(c["args"])
            line = f"{fmt_time(c['time'])}  {area:<22}"
            if cmd:
                e, r = explain_command(cmd)
                line += f" [{r.upper()}] {redact(cmd)[:90]}\n{'':>12}-> {e}"
            elif detail:
                line += f" {redact(detail)[:90]}"
            print(line, flush=True)
        time.sleep(1)


def main():
    ap = argparse.ArgumentParser(description="Argus - read-only Hermes Agent observer")
    ap.add_argument("cmd", choices=["doctor", "status", "commands", "files", "watch"])
    ap.add_argument("-n", type=int, default=10)
    ap.add_argument("--base")
    ap.add_argument("--profile")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()
    h = Hermes(a.base, a.profile)
    if a.cmd == "doctor":
        return fn_doctor(h)
    if a.cmd == "watch":
        try:
            return watch(h)
        except KeyboardInterrupt:
            return
    data = {"status": lambda: fn_status(h), "commands": lambda: fn_commands(h, a.n), "files": lambda: fn_files(h)}[a.cmd]()
    if a.json:
        print(json.dumps(data, indent=2, default=str))
    else:
        {"status": print_status, "commands": print_commands, "files": print_files}[a.cmd](data)


if __name__ == "__main__":
    main()
